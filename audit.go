package qkd

import (
	"errors"
	"fmt"
)

// 可区分的结局类别：成功与各类失败均有稳定的机器可读代码。
const (
	OutcomeSuccess         = "success"
	OutcomeInvalidConfig   = "invalid_config"
	OutcomeNoSignal        = "no_signal"
	OutcomeAbortedInsecure = "aborted_insecure"
	OutcomeReconcileFailed = "reconcile_failed"
	OutcomeInsufficient    = "insufficient_material"
	OutcomeInternalError   = "internal_error"
)

// 材料不足的可区分子类别（只在 Outcome==OutcomeInsufficient 时有意义）。
const (
	DetailExhausted             = "exhausted"               // 账目口径可用比特 <= 0，不可能出钥
	DetailLowYield              = "low_yield"               // 有正材料但不足 1 字节，收益过低
	DetailInsufficientForTarget = "insufficient_for_target" // 能出更短的钥，但达不到显式目标；不自动缩短
)

// 会话推进到的阶段（单调、公开）。
const (
	StageValidate       = "validate"
	StageTransmit       = "transmit"
	StageSift           = "sift"
	StageQBEREstimate   = "qber_estimate"
	StageReconcile      = "reconcile"
	StageAccounting     = "accounting"
	StagePrivacyAmplify = "privacy_amplify"
)

// PublicInternalErrorReason 是遇到非预期内部错误时对外使用的唯一固定说明：
// 只保留公开类别，绝不转发可能含有筛后/纠正后比特等敏感内容的内部错误原文。
const PublicInternalErrorReason = "internal error: unexpected failure; details withheld from public audit"

// stagedError 包装一个流程错误并显式记录“实际推进到的最远阶段”。
// 错误类别仍由被包装的底层错误决定（errors.Is/As 穿透），因此
// 调用方既有的错误判断不受影响；阶段以执行现场记录为准，避免归类偏移。
type stagedError struct {
	stage string
	err   error
}

func (e *stagedError) Error() string { return e.err.Error() }
func (e *stagedError) Unwrap() error { return e.err }

// withStage 在 err 上附加实际到达阶段；nil 原样返回。
func withStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stagedError{stage: stage, err: err}
}

// ParamSummary 是参数的公开摘要：只含输入参数本身，不含任何派生密钥材料。
type ParamSummary struct {
	NumPhotons         int
	ChannelLossDB      float64
	DetectorEfficiency float64
	DarkCountProb      float64
	Eavesdrop          bool
	SampleFraction     float64
	QBERThreshold      float64
	SecurityMargin     int
	RequestedKeyBytes  int
	Seed               int64
}

// PublicCounts 是各阶段的公开计数（数量口径，绝非比特内容）。
type PublicCounts struct {
	Prepared    int
	Detected    int
	Sifted      int
	Sampled     int
	AfterSample int
	LeakedEC    int
	LeakedEst   int
	Margin      int
	Final       int
	Discarded   int
}

// Audit 是成功与所有失败路径统一口径的对外审计信息。
// 结构上不含纠正后比特、筛后比特或最终密钥等任何可推导密钥的中间量；
// 成功与失败共用同一结构，换失败路径不会混入敏感量。
type Audit struct {
	Params        ParamSummary
	Stage         string // 会话推进到的最远阶段
	Outcome       string // 粗粒度结局类别
	Detail        string // 材料不足等的细分子类别（无需区分时为空）
	Reason        string // 人类可读、仅含公开数值的说明
	Counts        PublicCounts
	QBER          float64
	QBERThreshold float64
	KeyBits       int // 仅成功时为最终密钥比特长度（公开的是长度，不是内容）
}

func summarizeParams(cfg Config) ParamSummary {
	c := cfg.withDefaults()
	return ParamSummary{
		NumPhotons:         c.NumPhotons,
		ChannelLossDB:      c.ChannelLossDB,
		DetectorEfficiency: c.DetectorEfficiency,
		DarkCountProb:      c.DarkCountProb,
		Eavesdrop:          c.Eavesdrop,
		SampleFraction:     c.SampleFraction,
		QBERThreshold:      c.QBERThreshold,
		SecurityMargin:     c.SecurityMargin,
		RequestedKeyBytes:  c.RequestedKeyBytes,
		Seed:               c.Seed,
	}
}

func ledgerCounts(l Ledger) PublicCounts {
	return PublicCounts{
		Prepared:    l.Prepared,
		Detected:    l.Detected,
		Sifted:      l.Sifted,
		Sampled:     l.Sampled,
		AfterSample: l.AfterSample,
		LeakedEC:    l.LeakedEC,
		LeakedEst:   l.LeakedEst,
		Margin:      l.Margin,
		Final:       l.Final,
		Discarded:   l.Discarded,
	}
}

// classifyError 把流程错误映射为 (粗类别, 阶段)。
// 粗类别按错误类型判定；阶段优先采用错误在执行现场携带的真实阶段
// （例如抽样阶段把剩余材料抽光的材料不足应归 qber_estimate，而非 accounting）。
// 未知错误归 internal_error，阶段缺省 accounting。
func classifyError(err error) (outcome, stage string) {
	var se *stagedError
	hasStage := errors.As(err, &se)
	switch {
	case errors.Is(err, ErrReconciliationFailed):
		outcome, stage = OutcomeReconcileFailed, StageReconcile
	case errors.Is(err, ErrInsufficientKeyMaterial):
		outcome, stage = OutcomeInsufficient, StageAccounting
	default:
		var ve *ValidationError
		switch {
		case errors.As(err, &ve):
			outcome, stage = OutcomeInvalidConfig, StageValidate
		case errors.Is(err, ErrNoSignal):
			outcome, stage = OutcomeNoSignal, StageSift
		default:
			var abort *AbortError
			if errors.As(err, &abort) {
				outcome, stage = OutcomeAbortedInsecure, StageQBEREstimate
			} else {
				outcome, stage = OutcomeInternalError, StageAccounting
			}
		}
	}
	if hasStage {
		stage = se.stage
	}
	return outcome, stage
}

// NewAudit 依据 Run 的输入参数、公开结果与错误构造统一口径审计。
// 调用方即使持有成功会话的密钥，也无法通过 Audit 泄露它：字段集中无任何比特序列。
func NewAudit(cfg Config, res Result, err error) Audit {
	c := cfg.withDefaults()
	a := Audit{
		Params:        summarizeParams(c),
		QBERThreshold: c.QBERThreshold,
		Counts:        ledgerCounts(res.Ledger),
	}
	a.QBER = res.QBER.QBER
	if err == nil {
		a.Stage = StagePrivacyAmplify
		a.Outcome = OutcomeSuccess
		a.KeyBits = res.Ledger.Final
		a.Reason = "key produced"
		return a
	}
	outcome, stage := classifyError(err)
	a.Outcome = outcome
	a.Stage = stage
	switch outcome {
	case OutcomeInternalError:
		// 非预期内部错误：只保留固定公开类别与说明，绝不转发原始错误文本
		// （其中可能含纠正后比特/筛后比特等敏感内容）。
		a.Reason = PublicInternalErrorReason
	default:
		// 已知错误的文本均为不含比特内容的固定公开口径，可安全对外。
		a.Reason = err.Error()
	}
	if outcome == OutcomeInsufficient {
		a.Detail = insufficientDetail(c, res.Ledger)
	}
	return a
}

// insufficientDetail 依据账目与请求长度区分子类别，口径与 prepareSession 的判定一致。
func insufficientDetail(cfg Config, l Ledger) string {
	bits := l.FinalKeyLen()
	switch {
	case bits <= 0:
		return DetailExhausted
	case (bits/8)*8 < 8:
		return DetailLowYield
	default:
		if cfg.RequestedKeyBytes > 0 && bits < cfg.RequestedKeyBytes*8 {
			return DetailInsufficientForTarget
		}
		// 走到错误却非目标不足：按低收益口径说明。
		return DetailLowYield
	}
}

// String 输出单行公开审计，便于日志与回归比对（不含任何密钥材料）。
func (a Audit) String() string {
	return fmt.Sprintf(
		"audit outcome=%s detail=%q stage=%s seed=%d qber=%.4f/%.4f counts={prepared=%d detected=%d sifted=%d sampled=%d after=%d leakEC=%d leakEst=%d margin=%d final=%d discarded=%d} keybits=%d",
		a.Outcome, a.Detail, a.Stage, a.Params.Seed,
		a.QBER, a.QBERThreshold,
		a.Counts.Prepared, a.Counts.Detected, a.Counts.Sifted, a.Counts.Sampled,
		a.Counts.AfterSample, a.Counts.LeakedEC, a.Counts.LeakedEst, a.Counts.Margin,
		a.Counts.Final, a.Counts.Discarded, a.KeyBits,
	)
}
