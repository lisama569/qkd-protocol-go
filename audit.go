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

// String 输出公开计数的单行形式（仅数量口径，绝无比特内容）。
func (c PublicCounts) String() string {
	return fmt.Sprintf(
		"prepared=%d detected=%d sifted=%d sampled=%d after=%d leakEC=%d leakEst=%d margin=%d final=%d discarded=%d",
		c.Prepared, c.Detected, c.Sifted, c.Sampled, c.AfterSample,
		c.LeakedEC, c.LeakedEst, c.Margin, c.Final, c.Discarded)
}

// 内部错误的固定公开说明：内部错误属于实现自身故障，其原始文本可能夹带
// 纠正后比特、筛后比特等敏感内容，因此对外只保留固定类别与固定说明，
// 绝不转发 err.Error() 原文（NewAudit 与容量预估共用此口径）。
const InternalErrorPublicReason = "internal error: unexpected implementation failure; no key material released"

// stageCarrier 由携带“错误实际发生阶段”的错误实现。
type stageCarrier interface {
	error
	errorStage() string
}

// stagedError 把错误标记到流程实际推进到的阶段上，只影响阶段归类，
// 不改变 errors.Is/errors.As 对底层错误的识别。
type stagedError struct {
	stage string
	err   error
}

func (e *stagedError) Error() string      { return e.err.Error() }
func (e *stagedError) Unwrap() error      { return e.err }
func (e *stagedError) errorStage() string { return e.stage }

// withStage 标记 err 实际发生的阶段（err 为 nil 时透传 nil）。
func withStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stagedError{stage: stage, err: err}
}

// classifyError 把流程错误映射为 (粗类别, 阶段)。未知错误归 internal_error。
// 若错误显式携带阶段标记（如抽样阶段抽光材料），阶段以标记为准，
// 保证审计阶段与真实执行到达的阶段一致；否则使用各类别的规范默认阶段。
func classifyError(err error) (outcome, stage string) {
	var marked stageCarrier
	hasMarkedStage := errors.As(err, &marked)

	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		outcome, stage = OutcomeInvalidConfig, StageValidate
	case errors.Is(err, ErrNoSignal):
		outcome, stage = OutcomeNoSignal, StageSift
	default:
		var abort *AbortError
		switch {
		case errors.As(err, &abort):
			outcome, stage = OutcomeAbortedInsecure, StageQBEREstimate
		case errors.Is(err, ErrReconciliationFailed):
			outcome, stage = OutcomeReconcileFailed, StageReconcile
		case errors.Is(err, ErrInsufficientKeyMaterial):
			outcome, stage = OutcomeInsufficient, StageAccounting
		default:
			outcome, stage = OutcomeInternalError, StageAccounting
		}
	}
	if hasMarkedStage {
		stage = marked.errorStage()
	}
	return outcome, stage
}

// publicFailureReason 返回失败的对外人类可读说明：
// 已知类别错误只含公开数值，可安全转发；内部错误可能夹带敏感比特内容，
// 一律替换为固定公开说明。
func publicFailureReason(outcome string, err error) string {
	if outcome == OutcomeInternalError {
		return InternalErrorPublicReason
	}
	return err.Error()
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
	a.Reason = publicFailureReason(outcome, err)
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
