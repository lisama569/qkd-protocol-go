// Command qkdsim 在本地运行 BB84 QKD 模拟：单会话、批量会话与容量预估。
//
// 用法:
//
//	# 单会话（默认子命令）
//	qkdsim run   -seed 42 -n 4000 -loss 10 -eff 0.9 -dark 0.001 -key 16
//	qkdsim       -seed 42 -n 4000 ...   # 不带子命令时等价于 run
//
//	# 批量会话：用分号分隔多组参数，每组 -g 开头，可选 -c 指定并发度
//	qkdsim batch -c 4 -g "-seed 1 -n 4000 -key 16" -g "-seed 2 -eve" \
//	             -g "-seed 3 -loss 60 -dark 1e-12"
//
//	# 容量预估：不产出密钥，仅给可行性/公开消耗/缺口
//	qkdsim capacity -key 32 -n 1000 -loss 5 -eff 0.9 -dark 0.0001
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	qkd "github.com/lisama569/qkd-protocol-go"
)

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	sub := "run"
	if len(args) > 0 && args[0] != "-" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "run":
		runSingle(args)
	case "batch":
		runBatch(args)
	case "capacity":
		runCapacity(args)
	default:
		log.Fatalf("未知子命令 %q（可用：run | batch | capacity）", sub)
	}
}

// registerFlags 为一套会话参数注册 flag，返回该 Config 指针。
func registerFlags(fs *flag.FlagSet) *qkd.Config {
	cfg := &qkd.Config{}
	fs.IntVar(&cfg.NumPhotons, "n", 4000, "制备光子数")
	fs.Float64Var(&cfg.ChannelLossDB, "loss", 5, "信道损耗(dB)")
	fs.Float64Var(&cfg.DetectorEfficiency, "eff", 0.9, "探测器效率")
	fs.Float64Var(&cfg.DarkCountProb, "dark", 0.0001, "暗计数概率")
	fs.BoolVar(&cfg.Eavesdrop, "eve", false, "是否模拟窃听")
	fs.Float64Var(&cfg.SampleFraction, "sample", 0, "误码抽样比例(0=缺省)")
	fs.Float64Var(&cfg.QBERThreshold, "threshold", 0, "QBER 判定阈值(0=缺省)")
	fs.IntVar(&cfg.SecurityMargin, "margin", 0, "安全余量比特(0=缺省)")
	fs.IntVar(&cfg.RequestedKeyBytes, "key", 16, "请求密钥字节数(0=尽量长)")
	fs.Int64Var(&cfg.Seed, "seed", 1, "随机种子")
	return cfg
}

func runSingle(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg := registerFlags(fs)
	_ = fs.Parse(args)

	res, err := qkd.Run(*cfg)
	if err != nil {
		audit := qkd.AuditOf(*cfg, res, err)
		log.Printf("结局: %s @ %s — %s", audit.Category, audit.Stage, audit.Reason)
		log.Printf("公开计数: %s", audit.Counts)
		log.Printf("会话终止/失败: %v (未输出任何密钥材料)", err)
		os.Exit(1)
	}
	log.Printf("误码估计: 抽样=%d 错误=%d QBER=%.4f 阈值=%.4f secure=%v",
		res.QBER.SampleSize, res.QBER.Errors, res.QBER.QBER, res.QBER.Threshold, res.QBER.Secure)
	log.Printf("纠正: 纠正比特=%d 泄漏=%d", res.Reconciled.ErrorsFixed, res.Reconciled.LeakedBits)
	log.Printf("密钥账目: %s", res.Ledger)
	fmt.Printf("最终密钥(%d 字节): %s\n", len(res.Key), hex.EncodeToString(res.Key))
}

func runBatch(args []string) {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	concurrency := fs.Int("c", 1, "并发度（改变并发度不影响任何一组的结果）")
	groups := repeatedFlag(fs, "g", "一组会话参数（引号包裹，内部同 run 的 flag）；可重复")
	_ = fs.Parse(args)

	if len(*groups) == 0 {
		log.Fatal("batch 至少需要一组 -g 参数")
	}
	items := make([]qkd.BatchItem, 0, len(*groups))
	for i, raw := range *groups {
		gfs := flag.NewFlagSet(fmt.Sprintf("g%d", i), flag.ContinueOnError)
		gc := registerFlags(gfs)
		if err := gfs.Parse(strings.Fields(raw)); err != nil {
			log.Fatalf("第 %d 组参数解析失败: %v", i, err)
		}
		items = append(items, qkd.BatchItem{
			Name:   fmt.Sprintf("g%d", i),
			Config: *gc,
		})
	}

	results := qkd.RunBatch(items, qkd.BatchOptions{Concurrency: *concurrency})
	failures := 0
	for _, g := range results {
		status := "OK"
		if g.Err != nil {
			status = "FAIL"
			failures++
		}
		fmt.Printf("[%d %s] %s @ %s keybytes=%d | %s\n",
			g.Index, status, g.Category, g.Stage, g.Audit.KeyBytes, g.Audit.Counts)
		if g.Category == qkd.CategorySuccess {
			fmt.Printf("        密钥: %s\n", hex.EncodeToString(g.Result.Key))
		} else {
			fmt.Printf("        原因: %s\n", g.Audit.Reason)
		}
	}
	log.Printf("批量完成: 共 %d 组，成功 %d，失败 %d（并发度=%d）",
		len(results), len(results)-failures, failures, *concurrency)
}

func runCapacity(args []string) {
	fs := flag.NewFlagSet("capacity", flag.ExitOnError)
	cfg := registerFlags(fs)
	_ = fs.Parse(args)

	est := qkd.EstimateCapacity(*cfg, cfg.RequestedKeyBytes)
	log.Printf("参数摘要: %+v", est.Params)
	log.Printf("结论: %s @ %s feasible=%v keyPossible=%v",
		est.Category, est.Stage, est.Feasible, est.KeyPossible)
	log.Printf("可用比特=%d 最多可得=%d 字节 目标=%d 字节 计划输出=%d bit 缺口=%d bit",
		est.AvailableBits, est.MaxKeyBytes, est.TargetKeyBytes, est.PlannedOutBits, est.ShortfallBits)
	log.Printf("公开消耗: prepared=%d detected=%d sifted=%d sampled=%d after=%d leakEC=%d leakEst=%d margin=%d",
		est.Cost.Prepared, est.Cost.Detected, est.Cost.Sifted, est.Cost.Sampled,
		est.Cost.AfterSample, est.Cost.LeakedEC, est.Cost.LeakedEst, est.Cost.Margin)
	log.Printf("说明: %s", est.Reason)
}

// stringsFlag 实现可重复的 -g 参数。
type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, " ; ") }
func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func repeatedFlag(fs *flag.FlagSet, name, usage string) *[]string {
	var v []string
	fs.Var((*stringsFlag)(&v), name, usage)
	return &v
}
