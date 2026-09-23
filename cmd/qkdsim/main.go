// Command qkdsim 在本地运行一次完整的 BB84 QKD 模拟流程。
//
// 用法:
//
//	qkdsim -seed 42 -n 4000 -loss 10 -eff 0.9 -dark 0.001 -eve=false -key 16
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	qkd "github.com/lisama569/qkd-protocol-go"
)

func main() {
	cfg := qkd.Config{}
	flag.IntVar(&cfg.NumPhotons, "n", 4000, "制备光子数")
	flag.Float64Var(&cfg.ChannelLossDB, "loss", 5, "信道损耗(dB)")
	flag.Float64Var(&cfg.DetectorEfficiency, "eff", 0.9, "探测器效率")
	flag.Float64Var(&cfg.DarkCountProb, "dark", 0.0001, "暗计数概率")
	flag.BoolVar(&cfg.Eavesdrop, "eve", false, "是否模拟窃听")
	flag.Float64Var(&cfg.SampleFraction, "sample", 0.5, "误码抽样比例(0=缺省)")
	flag.Float64Var(&cfg.QBERThreshold, "threshold", 0.11, "QBER 判定阈值(0=缺省)")
	flag.IntVar(&cfg.SecurityMargin, "margin", 32, "安全余量比特(0=缺省)")
	flag.IntVar(&cfg.RequestedKeyBytes, "key", 16, "请求密钥字节数(0=尽量长)")
	flag.Int64Var(&cfg.Seed, "seed", 1, "随机种子")
	flag.Parse()

	log.Printf("输入参数: %+v", cfg)
	res, err := qkd.Run(cfg)
	log.Printf("误码估计: 抽样=%d 错误=%d QBER=%.4f 阈值=%.4f secure=%v",
		res.QBER.SampleSize, res.QBER.Errors, res.QBER.QBER, res.QBER.Threshold, res.QBER.Secure)
	log.Printf("纠正: 纠正比特=%d 泄漏=%d", res.Reconciled.ErrorsFixed, res.Reconciled.LeakedBits)
	log.Printf("密钥账目: %s", res.Ledger)
	if err != nil {
		log.Printf("会话终止/失败: %v (未输出任何密钥材料)", err)
		return
	}
	fmt.Printf("最终密钥(%d 字节): %s\n", len(res.Key), hex.EncodeToString(res.Key))
}
