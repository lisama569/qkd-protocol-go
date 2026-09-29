package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLISingleModeBackwardCompatible(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-seed", "1", "-n", "4000", "-loss", "5",
		"-eff", "0.9", "-dark", "0.0001", "-key", "16"}, nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "最终密钥(16 字节): 658f5cf8e113bf1fb4734092956c44b3") {
		t.Fatalf("single-mode output changed:\n%s", out.String())
	}
	// 历史输出走 log(stderr)。
	if !strings.Contains(errBuf.String(), "误码估计") {
		t.Fatalf("legacy log lines missing:\n%s", errBuf.String())
	}
}

func TestCLISingleModeEavesdrop(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-seed", "1", "-eve"}, nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if strings.Contains(out.String(), "最终密钥") {
		t.Fatalf("aborted run must not print a key:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "会话终止/失败") {
		t.Fatalf("expected termination log:\n%s", errBuf.String())
	}
}

func TestCLIEstimateModeThreshold(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-mode", "estimate", "-seed", "1", "-key", "100000"},
		nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errBuf.String())
	}
	s := out.String()
	if !strings.Contains(s, "verdict=insufficient_for_target") ||
		!strings.Contains(s, "生效阈值=0.1100") ||
		!strings.Contains(s, "requested=800000") {
		t.Fatalf("estimate output mismatch:\n%s", s)
	}
}

func TestCLIEstimateModeInvalidStillShowsThreshold(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-mode", "estimate", "-eff", "2"}, nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("invalid config is an estimate verdict, not a process error: exit=%d", code)
	}
	if !strings.Contains(out.String(), "verdict=invalid_config") ||
		!strings.Contains(out.String(), "生效阈值=0.1100") {
		t.Fatalf("invalid config must still report effective threshold:\n%s", out.String())
	}
}

func TestCLIEstimateNegativeTargetErrors(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-mode", "estimate", "-key", "-1"}, nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("negative target exit=%d want 2", code)
	}
	if !strings.Contains(errBuf.String(), "容量预估参数非法") {
		t.Fatalf("stderr=%s", errBuf.String())
	}
}

func TestCLIBatchModeFile(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"-mode", "batch", "-jobs", "testdata/jobs.json", "-workers", "1"},
		nil, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errBuf.String())
	}
	s := out.String()
	for _, want := range []string{
		"[0] success audit outcome=success",
		"658f5cf8e113bf1fb4734092956c44b3",
		"[1] abort audit outcome=aborted_insecure",
		"[2] no-signal audit outcome=no_signal detail=\"\" stage=sift",
		"[3] sampled-out audit outcome=insufficient_material detail=\"exhausted\" stage=qber_estimate",
		"共 4 组, 成功 1, 失败 3",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("batch output missing %q:\n%s", want, s)
		}
	}
}

// 并发度变化时每组结果必须逐项一致（含密钥），只允许调度差异。
func TestCLIBatchWorkersReproducible(t *testing.T) {
	var ref bytes.Buffer
	if code := run([]string{"-mode", "batch", "-jobs", "testdata/jobs.json", "-workers", "1"},
		nil, &ref, &bytes.Buffer{}); code != 0 {
		t.Fatalf("ref exit=%d", code)
	}
	for _, w := range []string{"2", "8", "100"} {
		var got, errBuf bytes.Buffer
		if code := run([]string{"-mode", "batch", "-jobs", "testdata/jobs.json", "-workers", w},
			nil, &got, &errBuf); code != 0 {
			t.Fatalf("workers=%s exit=%d", w, code)
		}
		if got.String() != ref.String() {
			t.Fatalf("workers=%s output diverged:\nref:\n%s\ngot:\n%s", w, ref.String(), got.String())
		}
	}
}

func TestCLIBatchStdin(t *testing.T) {
	input := strings.NewReader(`[{"name":"ok","n":4000,"eff":0.9,"dark":0.0001,"key":16,"seed":1}]`)
	var out, errBuf bytes.Buffer
	code := run([]string{"-mode", "batch", "-jobs", "-", "-workers", "1"}, input, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ok audit outcome=success") ||
		!strings.Contains(out.String(), "共 1 组, 成功 1, 失败 0") {
		t.Fatalf("stdin batch output:\n%s", out.String())
	}
}

func TestCLIBatchBadArgs(t *testing.T) {
	for _, args := range [][]string{
		{"-mode", "batch"},
		{"-mode", "batch", "-jobs", "testdata/does-not-exist.json"},
		{"-mode", "unknown"},
	} {
		var out, errBuf bytes.Buffer
		if code := run(args, nil, &out, &errBuf); code != 2 {
			t.Fatalf("args=%v exit=%d want 2", args, code)
		}
	}
}
