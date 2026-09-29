// Command qkdsim 在本地运行 BB84 QKD 模拟。
//
// 单会话（默认，行为与历史完全一致）:
//
//	qkdsim -seed 42 -n 4000 -loss 10 -eff 0.9 -dark 0.001 -eve=false -key 16
//
// 容量预估（不出钥，复用同一组参数与判定路径）:
//
//	qkdsim -mode estimate -seed 42 -n 4000 -key 16
//
// 批量会话（可重复 -job 指定多个参数组，其余公共参数作为缺省）:
//
//	qkdsim -mode batch -workers 4 \
//	  -job eve=true,n=4000 \
//	  -job low-loss:n=4000,loss=5 \
//	  -job scarce:n=200,key=64
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	qkd "github.com/lisama569/qkd-protocol-go"
)

// stringList 收集可重复的字符串参数（如批量任务 -job）。
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// registerFlags 注册与单会话完全相同的一组参数到给定 FlagSet，
// 保证 run / estimate / batch 三种模式的参数、缺省值与口径一致。
func registerFlags(fs *flag.FlagSet, cfg *qkd.Config) {
	fs.IntVar(&cfg.NumPhotons, "n", 4000, "制备光子数")
	fs.Float64Var(&cfg.ChannelLossDB, "loss", 5, "信道损耗(dB)")
	fs.Float64Var(&cfg.DetectorEfficiency, "eff", 0.9, "探测器效率")
	fs.Float64Var(&cfg.DarkCountProb, "dark", 0.0001, "暗计数概率")
	fs.BoolVar(&cfg.Eavesdrop, "eve", false, "是否模拟窃听")
	fs.Float64Var(&cfg.SampleFraction, "sample", 0.5, "误码抽样比例(0=缺省)")
	fs.Float64Var(&cfg.QBERThreshold, "threshold", 0.11, "QBER 判定阈值(0=缺省)")
	fs.IntVar(&cfg.SecurityMargin, "margin", 32, "安全余量比特(0=缺省)")
	fs.IntVar(&cfg.RequestedKeyBytes, "key", 16, "请求密钥字节数(0=尽量长)")
	fs.Int64Var(&cfg.Seed, "seed", 1, "随机种子")
}

// parseJob 以公共参数为缺省，解析单个批量任务描述。
// 形如 "name:n=4000,eve=true"（名称可选），仅允许公共参数白名单内的键。
func parseJob(spec string, def qkd.Config) (string, qkd.Config, error) {
	name := ""
	body := spec
	if i := strings.IndexByte(spec, ':'); i >= 0 {
		name = strings.TrimSpace(spec[:i])
		body = spec[i+1:]
	}
	cfg := def
	fs := flag.NewFlagSet("job", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, &cfg)
	var args []string
	if strings.TrimSpace(body) != "" {
		for _, kv := range strings.Split(body, ",") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			tok := "-" + kv
			if !strings.Contains(kv, "=") {
				// 允许裸写布尔开关，如 eve 等价于 eve=true。
				tok = "-" + kv + "=true"
			}
			args = append(args, tok)
		}
	}
	if err := fs.Parse(args); err != nil {
		return name, cfg, fmt.Errorf("job %q: %w", spec, err)
	}
	return name, cfg, nil
}

func runMain(args []string, stdout, stderr io.Writer) int {
	log.SetOutput(stderr)
	fs := flag.NewFlagSet("qkdsim", flag.ContinueOnError)
	fs.SetOutput(stderr)

	mode := fs.String("mode", "run", "运行模式: run(单会话) | estimate(容量预估) | batch(批量会话)")
	workers := fs.Int("workers", 0, "批量并发度(<=0 顺序执行，超过任务数按任务数计)")
	var jobsSpec stringList
	fs.Var(&jobsSpec, "job", "批量任务(可重复)，形如 [name:]key=value,key=value；仅 batch 使用")

	var cfg qkd.Config
	registerFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch *mode {
	case "run":
		return runSingle(cfg, stdout)
	case "estimate":
		return runEstimate(cfg, stdout)
	case "batch":
		return runBatch(cfg, jobsSpec, *workers, stdout)
	default:
		fmt.Fprintf(stderr, "未知模式 %q（可选 run/estimate/batch）\n", *mode)
		return 2
	}
}

func runSingle(cfg qkd.Config, stdout io.Writer) int {
	log.Printf("输入参数: %+v", cfg)
	res, err := qkd.Run(cfg)
	log.Printf("误码估计: 抽样=%d 错误=%d QBER=%.4f 阈值=%.4f secure=%v",
		res.QBER.SampleSize, res.QBER.Errors, res.QBER.QBER, res.QBER.Threshold, res.QBER.Secure)
	log.Printf("纠正: 纠正比特=%d 泄漏=%d", res.Reconciled.ErrorsFixed, res.Reconciled.LeakedBits)
	log.Printf("密钥账目: %s", res.Ledger)
	if err != nil {
		log.Printf("会话终止/失败: %v (未输出任何密钥材料)", err)
		return 1
	}
	fmt.Fprintf(stdout, "最终密钥(%d 字节): %s\n", len(res.Key), hex.EncodeToString(res.Key))
	return 0
}

func runEstimate(cfg qkd.Config, stdout io.Writer) int {
	log.Printf("容量预估参数: %+v", cfg)
	e, err := qkd.EstimateCapacity(cfg, cfg.RequestedKeyBytes)
	if err != nil {
		log.Printf("容量预估入参非法: %v", err)
		return 2
	}
	log.Printf("参数摘要阈值 QBERThreshold=%.4f 抽样比例=%.4f 目标=%d 字节",
		e.Params.QBERThreshold, e.Params.SampleFraction, e.Params.RequestedKeyBytes)
	log.Printf("预估结论: verdict=%s stage=%s", e.Verdict, e.Stage)
	log.Printf("阈值口径: QBER=%.4f / 生效阈值=%.4f（两者阈值字段一致）",
		e.QBER, e.QBERThreshold)
	log.Printf("公开计数: %s", ledgerString(e.Counts))
	log.Printf("材料口径: available=%d byteAligned=%d requested=%d expectedKeyBits=%d",
		e.AvailableBits, e.ByteAlignedBits, e.RequestedBits, e.ExpectedKeyBits)
	log.Printf("原因: %s", e.Reason)
	if e.Verdict == qkd.CapacityFeasible {
		fmt.Fprintf(stdout, "ESTIMATE feasible: expected %d key bits (%d bytes)\n",
			e.ExpectedKeyBits, e.ExpectedKeyBits/8)
		return 0
	}
	fmt.Fprintf(stdout, "ESTIMATE %s: %s\n", e.Verdict, e.Reason)
	return 1
}

func runBatch(base qkd.Config, specs []string, workers int, stdout io.Writer) int {
	if len(specs) == 0 {
		// 未提供 -job 时，以公共参数本身作为唯一任务，便于本地直接复现。
		specs = []string{""}
	}
	jobs := make([]qkd.BatchJob, 0, len(specs))
	for i, spec := range specs {
		name, jcfg, err := parseJob(spec, base)
		if err != nil {
			log.Printf("任务解析失败: %v", err)
			return 2
		}
		if name == "" {
			name = "job-" + strconv.Itoa(i)
		}
		jobs = append(jobs, qkd.BatchJob{Name: name, Cfg: jcfg})
	}
	log.Printf("批量会话: 任务数=%d workers=%d", len(jobs), workers)
	outs := qkd.RunBatch(jobs, workers)
	failed := 0
	for _, o := range outs {
		log.Printf("[batch %d/%s] %s", o.Index, o.Name, o.Audit)
		if o.Err != nil {
			failed++
			log.Printf("[batch %d/%s] 失败类别=%s 阶段=%s 说明=%s",
				o.Index, o.Name, o.Audit.Outcome, o.Audit.Stage, o.Audit.Reason)
			continue
		}
		fmt.Fprintf(stdout, "[batch %d/%s] 最终密钥(%d 字节): %s\n",
			o.Index, o.Name, len(o.Key), hex.EncodeToString(o.Key))
	}
	log.Printf("批量结束: 共=%d 成功=%d 失败=%d", len(outs), len(outs)-failed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// ledgerString 以账目风格格式化公开计数（CLI 展示用，不含任何比特内容）。
func ledgerString(c qkd.PublicCounts) string {
	return fmt.Sprintf(
		"prepared=%d detected=%d sifted=%d sampled=%d after_sample=%d leak_ec=%d leak_est=%d margin=%d final=%d discarded=%d",
		c.Prepared, c.Detected, c.Sifted, c.Sampled, c.AfterSample,
		c.LeakedEC, c.LeakedEst, c.Margin, c.Final, c.Discarded)
}

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}
