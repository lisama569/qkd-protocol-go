package qkd

import "fmt"

// Ledger 是密钥账目：记录各阶段比特数量。
// 守恒口径：
//
//	Detected <= Prepared
//	Sifted <= Detected
//	Sifted = Sampled + AfterSample
//	AfterSample = LeakedEC + LeakedEst + Margin + Final + Discarded
type Ledger struct {
	Prepared    int // 制备光子数
	Detected    int // 探测到的事件数（含暗计数）
	Sifted      int // 筛后长度（基一致）
	Sampled     int // 误码抽样公开消耗
	AfterSample int // 抽样后剩余
	LeakedEC    int // 纠错公开泄漏
	LeakedEst   int // 对 Eve 信息的估计泄漏（由 QBER 折算）
	Margin      int // 安全余量
	Final       int // 最终密钥长度（比特）
	Discarded   int // 满足请求长度后显式丢弃的多余材料（整字节对齐余量同样计入）
}

// FinalKeyLen 按账目口径计算最终可得密钥比特数；
// 结果 <= 0 表示材料不足，调用方必须显式拒绝。
func (l Ledger) FinalKeyLen() int {
	return l.AfterSample - l.LeakedEC - l.LeakedEst - l.Margin
}

// Check 校验账目守恒与各阶段单调关系。
func (l *Ledger) Check() error {
	if l.Prepared < 0 || l.Detected < 0 || l.Sifted < 0 ||
		l.Sampled < 0 || l.AfterSample < 0 ||
		l.LeakedEC < 0 || l.LeakedEst < 0 || l.Margin < 0 ||
		l.Final < 0 || l.Discarded < 0 {
		return fmt.Errorf("account: negative count: %s", l)
	}
	if l.Detected > l.Prepared {
		return fmt.Errorf("account: detected %d > prepared %d", l.Detected, l.Prepared)
	}
	if l.Sifted > l.Detected {
		return fmt.Errorf("account: sifted %d > detected %d", l.Sifted, l.Detected)
	}
	if l.Sifted != l.Sampled+l.AfterSample {
		return fmt.Errorf("account: sifted %d != sampled %d + after_sample %d",
			l.Sifted, l.Sampled, l.AfterSample)
	}
	if l.AfterSample != l.LeakedEC+l.LeakedEst+l.Margin+l.Final+l.Discarded {
		return fmt.Errorf("account: after_sample %d != leak_ec %d + leak_est %d + margin %d + final %d + discarded %d",
			l.AfterSample, l.LeakedEC, l.LeakedEst, l.Margin, l.Final, l.Discarded)
	}
	return nil
}

func (l Ledger) String() string {
	return fmt.Sprintf("prepared=%d detected=%d sifted=%d sampled=%d after_sample=%d leak_ec=%d leak_est=%d margin=%d final=%d discarded=%d",
		l.Prepared, l.Detected, l.Sifted, l.Sampled, l.AfterSample, l.LeakedEC, l.LeakedEst, l.Margin, l.Final, l.Discarded)
}
