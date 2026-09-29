package qkd

import (
	"errors"
	"fmt"
)

// 容量预估的结论类别（与真实执行结局一一对应，可直接对照）。
const (
	CapacityFeasible              = "feasible"
	CapacityInvalidConfig         = "invalid_config"
	CapacityNoSignal              = "no_signal"
	CapacityAbortedInsecure       = "aborted_insecure"
	CapacityReconcileFailed       = "reconcile_failed"
	CapacityExhausted             = "exhausted"
	CapacityLowYield              = "low_yield"
	CapacityInsufficientForTarget = "insufficient_for_target"
)

// ErrInvalidTarget 表示容量预估的目标长度非法（负数）。
var ErrInvalidTarget = errors.New("target key length must be >= 0")

// CapacityEstimate 是“不输出最终密钥”的容量预估结果，全部字段为公开口径：
// 只含参数、阶段、公开计数与可区分结论，绝无筛后/纠正后比特或最终密钥。
type CapacityEstimate struct {
	Params          ParamSummary
	Verdict         string
	Stage           string
	Reason          string
	Counts          PublicCounts
	QBER            float64
	QBERThreshold   float64
	AvailableBits   int // 账目口径原始可用材料：AfterSample-LeakEC-LeakEst-Margin
	ByteAlignedBits int // 整字节对齐后可用比特
	RequestedBits   int // 本次预估采用的目标比特数（0=尽量长模式）
	ExpectedKeyBits int // feasible 时预计实际可得密钥比特；非 feasible 为 0
}

// EstimateCapacity 在不输出最终密钥的前提下，评估给定参数与目标长度是否值得运行。
//
// targetKeyBytes 是本次显式目标：仅作用于内部克隆配置，不修改传入 cfg，也绝不静默
// 缩短目标或降级；targetKeyBytes<0 返回 ErrInvalidTarget；为 0 表示“尽量长”评估。
//
// 评估与 Run 共用同一条 prepareSession 判定路径（同种子、同随机消耗顺序），
// 因此在相同参数下，feasible ⇔ Run 必然成功且密钥长度==ExpectedKeyBits；
// 其余结论 ⇔ Run 在对应阶段以同一类别失败，二者不会自相矛盾。
func EstimateCapacity(cfg Config, targetKeyBytes int) (CapacityEstimate, error) {
	if targetKeyBytes < 0 {
		return CapacityEstimate{}, ErrInvalidTarget
	}
	run := cfg // 不修改调用方配置
	run.RequestedKeyBytes = targetKeyBytes
	c := run.withDefaults()

	e := CapacityEstimate{
		Params:        summarizeParams(c),
		RequestedBits: targetKeyBytes * 8,
	}

	prep, err := prepareSession(run)
	e.Counts = ledgerCounts(prep.ledger)
	e.QBER = prep.est.QBER
	// 阈值始终取本次真正生效的判定阈值（已应用缺省语义，与 Params.QBERThreshold
	// 同源）：绝不跟随实测 QBER，参数非法或流程早退（prep.est 为零值）时也不变成 0。
	e.QBERThreshold = c.QBERThreshold
	avail := prep.ledger.FinalKeyLen()
	e.AvailableBits = avail
	if avail > 0 {
		e.ByteAlignedBits = (avail / 8) * 8
	}

	if err == nil {
		e.Verdict = CapacityFeasible
		e.Stage = StageAccounting
		e.ExpectedKeyBits = prep.outBits
		e.Reason = fmt.Sprintf(
			"feasible: expected %d key bits (%d bytes); available=%d byteAligned=%d; public consumption sampled=%d leakEC=%d leakEst=%d margin=%d",
			prep.outBits, prep.outBits/8,
			avail, e.ByteAlignedBits,
			prep.ledger.Sampled, prep.ledger.LeakedEC, prep.ledger.LeakedEst, prep.ledger.Margin,
		)
		return e, nil
	}

	// 失败结论：映射到与 Run 相同的可区分类别，并给出不足原因（仅公开数值）。
	outcome, stage := classifyError(err)
	e.Stage = stage
	switch outcome {
	case OutcomeInvalidConfig:
		e.Verdict = CapacityInvalidConfig
	case OutcomeNoSignal:
		e.Verdict = CapacityNoSignal
	case OutcomeAbortedInsecure:
		e.Verdict = CapacityAbortedInsecure
	case OutcomeReconcileFailed:
		e.Verdict = CapacityReconcileFailed
	case OutcomeInsufficient:
		switch insufficientDetail(c, prep.ledger) {
		case DetailExhausted:
			e.Verdict = CapacityExhausted
			e.Reason = fmt.Sprintf(
				"exhausted: available=%d (<=0) after sampled=%d leakEC=%d leakEst=%d margin=%d; no key possible",
				avail, prep.ledger.Sampled, prep.ledger.LeakedEC, prep.ledger.LeakedEst, prep.ledger.Margin)
		case DetailLowYield:
			e.Verdict = CapacityLowYield
			e.Reason = fmt.Sprintf(
				"low yield: available=%d byteAligned=%d (<8 bits); a key is theoretically possible but below one byte",
				avail, e.ByteAlignedBits)
		default:
			e.Verdict = CapacityInsufficientForTarget
			e.Reason = fmt.Sprintf(
				"insufficient for target: available=%d byteAligned=%d < requested=%d bits; a shorter key is possible, target is not auto-shortened",
				avail, e.ByteAlignedBits, e.RequestedBits)
		}
	default:
		// 理论上 prepareSession 不会产生其它错误；保守归类，不伪造可行性。
		e.Verdict = outcome
	}
	if e.Reason == "" {
		if outcome == OutcomeInternalError {
			// 与 NewAudit 同口径：内部错误不转发可能含敏感内容的原文。
			e.Reason = PublicInternalErrorReason
		} else {
			e.Reason = err.Error()
		}
	}
	return e, nil
}
