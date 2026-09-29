// Command qkdsim 在本地运行 BB84 QKD 模拟，提供同一二进制内的三个入口：
//
// 单会话（缺省，行为/参数/默认值与历史完全一致）:
//
//	qkdsim -seed 42 -n 4000 -loss 10 -eff 0.9 -dark 0.001 -eve=false -key 16
//
// 容量预估（复用同一套会话参数，只评估不输出密钥）:
//
//	qkdsim -mode estimate -seed 42 -n 4000 -loss 10 -key 16
//
// 批量会话（每组参数独立种子，JSON 文件给出多组参数；-jobs - 从标准输入读取）:
//
//	qkdsim -mode batch -jobs jobs.json -workers 4
//
// 批量 JSON 每行（字段名与单会话参数一致；除 n/eff 必填外，缺省即 0/缺省语义）:
//
//	{"name":"a","n":4000,"loss":5,"eff":0.9,"dark":0.0001,"eve":false,
//	 "sample":0.5,"threshold":0.11,"margin":32,"key":16,"seed":1}
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	qkd "github.com/lisama569/qkd-protocol-go"
)

const (
	modeRun      = "run"
	modeEstimate = "estimate"
	modeBatch    = "batch"
)

// jobSpec 是批量入口的单行参数，字段与单会话 flag 同名同口径。
type jobSpec struct {
	Name      string  `json:"name"`
	N         int     `json:"n"`
	Loss      float64 `json:"loss"`
	Eff       float64 `json:"eff"`
	Dark      float64 `json:"dark"`
	Eve       bool    `json:"eve"`
	Sample    float64 `json:"sample"`
	Threshold float64 `json:"threshold"`
	Margin    int     `json:"margin"`
	Key       int     `json:"key"`
	Seed      int64   `json:"seed"`
}

func (s jobSpec) config() qkd.Config {
	return qkd.Config{
		NumPhotons:         s.N,
		ChannelLossDB:      s.Loss,
		DetectorEfficiency: s.Eff,
		DarkCountProb:      s.Dark,
		Eavesdrop:          s.Eve,
		SampleFraction:     s.Sample,
		QBERThreshold:      s.Threshold,
		SecurityMargin:     s.Margin,
		RequestedKeyBytes:  s.Key,
		Seed:               s.Seed,
	}
}

// sessionFlags 汇聚单会话/预估共用的参数定义，保证两种入口口径一致。
type sessionFlags struct {
	cfg qkd.Config
}

func registerSessionFlags(fs *flag.FlagSet) *sessionFlags {
	sf := &sessionFlags{}
	fs.IntVar(&sf.cfg.NumPhotons, "n", 4000, "制备光子数")
	fs.Float64Var(&sf.cfg.ChannelLossDB, "loss", 5, "信道损耗(dB)")
	fs.Float64Var(&sf.cfg.DetectorEfficiency, "eff", 0.9, "探测器效率")
	fs.Float64Var(&sf.cfg.DarkCountProb, "dark", 0.0001, "暗计数概率")
	fs.BoolVar(&sf.cfg.Eavesdrop, "eve", false, "是否模拟窃听")
	fs.Float64Var(&sf.cfg.SampleFraction, "sample", 0.5, "误码抽样比例(0=缺省)")
	fs.Float64Var(&sf.cfg.QBERThreshold, "threshold", 0.11, "QBER 判定阈值(0=缺省)")
	fs.IntVar(&sf.cfg.SecurityMargin, "margin", 32, "安全余量比特(0=缺省)")
	fs.IntVar(&sf.cfg.RequestedKeyBytes, "key", 16, "请求密钥字节数(0=尽量长)")
	fs.Int64Var(&sf.cfg.Seed, "seed", 1, "随机种子")
	return sf
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run 返回进程退出码，便于自动化测试直接驱动命令行入口。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qkdsim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", modeRun, "运行模式: run(单会话,缺省) | estimate(容量预估) | batch(批量会话)")
	jobsPath := fs.String("jobs", "", "批量模式的参数文件(JSON 数组; - 表示标准输入)")
	workers := fs.Int("workers", 4, "批量模式并发度(<=0 或超过组数时按组数)")
	sf := registerSessionFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// 统一日志走向，单会话历史输出仍走 log（保持原有观感）。
	log.SetOutput(stderr)

	switch *mode {
	case modeRun:
		return runSingle(sf.cfg, stdout, stderr)
	case modeEstimate:
		return runEstimate(sf.cfg, stdout, stderr)
	case modeBatch:
		return runBatchMode(*jobsPath, *workers, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知 -mode %q: 仅支持 run|estimate|batch\n", *mode)
		return 2
	}
}

// runSingle 与历史单会话入口行为完全一致。
func runSingle(cfg qkd.Config, stdout, stderr io.Writer) int {
	log.Printf("输入参数: %+v", cfg)
	res, err := qkd.Run(cfg)
	log.Printf("误码估计: 抽样=%d 错误=%d QBER=%.4f 阈值=%.4f secure=%v",
		res.QBER.SampleSize, res.QBER.Errors, res.QBER.QBER, res.QBER.Threshold, res.QBER.Secure)
	log.Printf("纠正: 纠正比特=%d 泄漏=%d", res.Reconciled.ErrorsFixed, res.Reconciled.LeakedBits)
	log.Printf("密钥账目: %s", res.Ledger)
	if err != nil {
		log.Printf("会话终止/失败: %v (未输出任何密钥材料)", err)
		return 0
	}
	fmt.Fprintf(stdout, "最终密钥(%d 字节): %s\n", len(res.Key), hex.EncodeToString(res.Key))
	return 0
}

// runEstimate 复用单会话参数做容量预估：输出公开口径的阈值、结论与计数。
func runEstimate(cfg qkd.Config, stdout, stderr io.Writer) int {
	e, err := qkd.EstimateCapacity(cfg, cfg.RequestedKeyBytes)
	if err != nil {
		fmt.Fprintf(stderr, "容量预估参数非法: %v\n", err)
		return 2
	}
	log.Printf("预估输入参数: %+v", e.Params)
	fmt.Fprintf(stdout,
		"容量预估 verdict=%s stage=%s qber=%.4f 生效阈值=%.4f requested=%d available=%d byteAligned=%d expectedKeyBits=%d\n",
		e.Verdict, e.Stage, e.QBER, e.QBERThreshold,
		e.RequestedBits, e.AvailableBits, e.ByteAlignedBits, e.ExpectedKeyBits)
	fmt.Fprintf(stdout, "计数: %s\n", e.Counts)
	fmt.Fprintf(stdout, "说明: %s\n", e.Reason)
	return 0
}

// runBatchMode 读取 JSON 参数组并并发执行，结果按提交顺序逐项输出。
func runBatchMode(path string, workers int, stdin io.Reader, stdout, stderr io.Writer) int {
	if path == "" {
		fmt.Fprintln(stderr, "批量模式需要 -jobs 指定 JSON 参数文件(- 表示标准输入)")
		return 2
	}
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "读取批量参数失败: %v\n", err)
		return 2
	}
	var specs []jobSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		fmt.Fprintf(stderr, "批量参数 JSON 解析失败: %v\n", err)
		return 2
	}
	if len(specs) == 0 {
		fmt.Fprintln(stderr, "批量参数为空: 至少需要一组参数")
		return 2
	}

	jobs := make([]qkd.BatchJob, len(specs))
	for i, s := range specs {
		jobs[i] = qkd.BatchJob{Name: s.Name, Cfg: s.config()}
	}
	outs := qkd.RunBatch(jobs, workers)
	failures := 0
	for _, o := range outs {
		name := o.Name
		if name == "" {
			name = fmt.Sprintf("#%d", o.Index)
		}
		fmt.Fprintf(stdout, "[%d] %s %s\n", o.Index, name, o.Audit)
		if o.Err == nil {
			fmt.Fprintf(stdout, "    key(%dB): %s\n", len(o.Key), hex.EncodeToString(o.Key))
		} else {
			failures++
			fmt.Fprintf(stdout, "    结论: %s\n", o.Audit.Reason)
		}
	}
	fmt.Fprintf(stdout, "批量完成: 共 %d 组, 成功 %d, 失败 %d\n",
		len(outs), len(outs)-failures, failures)
	return 0
}
