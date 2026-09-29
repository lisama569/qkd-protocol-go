package main

import (
	"bytes"
	"log"
	"regexp"
	"strings"
	"testing"
)

// exec 捕获 stdout/stderr 并返回退出码；测试期间把 log 输出重定向到缓冲。
func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	old := log.Writer()
	var out, errBuf bytes.Buffer
	log.SetOutput(&errBuf)
	defer log.SetOutput(old)
	code := runMain(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// 默认单会话：成功、密钥输出与退出码符合历史口径。
func TestCLIRunDefault(t *testing.T) {
	code, out, errLog := exec(t, "-seed", "1", "-n", "4000", "-key", "16")
	if code != 0 {
		t.Fatalf("exit=%d log=%s", code, errLog)
	}
	if !strings.Contains(out, "最终密钥(16 字节): 658f5cf8e113bf1fb4734092956c44b3") {
		t.Fatalf("unexpected key output: %q", out)
	}
	if !strings.Contains(errLog, "输入参数:") {
		t.Fatalf("missing input-params log: %q", errLog)
	}
}

// 不传 -mode 时默认就是 run，且默认值不变（n=4000、seed=1、key=16 等）。
func TestCLIRunModeDefaultsUnchanged(t *testing.T) {
	code, _, _ := exec(t)
	if code != 0 {
		t.Fatalf("default invocation must succeed with unchanged defaults")
	}
}

// 窃听：run 以非零退出码结束且不输出密钥。
func TestCLIRunEavesdropFails(t *testing.T) {
	code, out, _ := exec(t, "-seed", "1", "-n", "4000", "-eve")
	if code != 1 || strings.Contains(out, "最终密钥") {
		t.Fatalf("eavesdrop run code=%d key=%q", code, out)
	}
}

// estimate：成功时展示的阈值与参数摘要一致；非可行返回 1。
func TestCLIEstimate(t *testing.T) {
	code, out, errLog := exec(t, "-mode", "estimate", "-seed", "1", "-n", "4000", "-key", "16")
	if code != 0 {
		t.Fatalf("estimate exit=%d log=%s", code, errLog)
	}
	if !strings.Contains(out, "ESTIMATE feasible: expected 128 key bits") {
		t.Fatalf("unexpected estimate output: %q", out)
	}
	// 摘要阈值与“生效阈值”同一数值（0.1100）。
	if !strings.Contains(errLog, "生效阈值=0.1100") ||
		!strings.Contains(errLog, "参数摘要阈值 QBERThreshold=0.1100") {
		t.Fatalf("threshold lines missing/mismatch: %q", errLog)
	}

	// 非法参数：阈值仍是生效缺省值，结论 invalid_config，退出码 1。
	code, out, errLog = exec(t, "-mode", "estimate", "-n", "0", "-eff", "0.9")
	if code != 1 {
		t.Fatalf("invalid estimate code=%d", code)
	}
	if !strings.Contains(out, "ESTIMATE invalid_config") ||
		!strings.Contains(errLog, "生效阈值=0.1100") {
		t.Fatalf("invalid-config estimate output=%q log=%q", out, errLog)
	}

	// 目标过大：不缩短目标，明确 insufficient_for_target。
	code, out, _ = exec(t, "-mode", "estimate", "-n", "4000", "-key", "10000")
	if code != 1 || !strings.Contains(out, "ESTIMATE insufficient_for_target") {
		t.Fatalf("oversized target code=%d out=%q", code, out)
	}
}

// batch：多任务、命名、覆盖参数、成功失败混合、退出码与密钥落位。
func TestCLIBatch(t *testing.T) {
	code, out, errLog := exec(t, "-mode", "batch", "-workers", "2", "-seed", "1",
		"-job", "success:",
		"-job", "eve:eve=true",
		"-job", "bad:n=0,eff=0.9")
	if code != 1 {
		t.Fatalf("batch with failures must exit 1, got %d", code)
	}
	if !strings.Contains(out, "[batch 0/success] 最终密钥(16 字节): 658f5cf8e113bf1fb4734092956c44b3") {
		t.Fatalf("batch success key missing: %q", out)
	}
	if strings.Contains(out, "[batch 1/eve] 最终密钥") {
		t.Fatalf("eavesdrop job must not print a key")
	}
	for _, want := range []string{
		"[batch 0/success] audit outcome=success",
		"[batch 1/eve] audit outcome=aborted_insecure",
		"[batch 2/bad] audit outcome=invalid_config",
		"批量结束: 共=3 成功=1 失败=2",
	} {
		if !strings.Contains(errLog, want) {
			t.Fatalf("batch log missing %q in:\n%s", want, errLog)
		}
	}
}

// 改变并发度，批量各任务审计与密钥不变（CLI 层复现口径）。
func TestCLIBatchWorkersReproducible(t *testing.T) {
	args := []string{"-mode", "batch", "-seed", "1",
		"-job", "a:", "-job", "eve:eve=true"}
	code1, out1, log1 := exec(t, append(append([]string{}, args...), "-workers", "1")...)
	code2, out2, log2 := exec(t, append(append([]string{}, args...), "-workers", "8")...)
	if code1 != code2 || out1 != out2 || stripTimestamps(log1) != stripTimestamps(log2) {
		t.Fatalf("batch output differs across workers:\n%s\nvs\n%s", log1, log2)
	}
}

// 非法 -job 描述返回退出码 2（参数解析失败），不执行任何会话。
func TestCLIBatchBadJobSyntax(t *testing.T) {
	code, _, errLog := exec(t, "-mode", "batch", "-job", "n=notanumber")
	if code != 2 {
		t.Fatalf("bad job syntax code=%d want 2 (%s)", code, errLog)
	}
}

// 未知模式返回 2。
func TestCLIUnknownMode(t *testing.T) {
	if code, _, _ := exec(t, "-mode", "wat"); code != 2 {
		t.Fatalf("unknown mode code=%d want 2", code)
	}
}

// stripTimestamps 去掉 log 默认时间戳前缀，并规范化 workers 输入值，
// 便于比较“只改变并发度”时各任务结果是否逐项一致。
var workersRE = regexp.MustCompile(`workers=\d+`)

func stripTimestamps(s string) string {
	s = workersRE.ReplaceAllString(s, "workers=N")
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, " "); i >= 0 && len(line) >= 20 && line[0] == '2' {
			line = line[i+1:]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
