package qkd

import (
	"errors"
	"fmt"
)

// 审计与结局分类的公开口径：
//
// 审计信息只允许包含参数摘要、阶段状态、公开计数（账目数量、误码统计）
// 与可区分的失败类别；任何路径（成功或失败）都不得包含纠正后的比特序列、
// 筛后可用比特、最终密钥等可直接推导密钥的材料。成功会话与失败会话
// 严格采用同一口径，换失败路径不会混入额外中间量。

// 结局类别：成功与各类可区分失败。
const (
	CategorySuccess              = "success"
	CategoryInvalidConfig        = "invalid_config"
	CategoryAborted              = "aborted"
	CategoryNoSignal             = "no_signal"
	CategoryInsufficientMaterial = "insufficient_material"
	CategoryLowYield             = "low_yield"
	CategoryReconcileFailed      = "reconcile_failed"
	CategoryInternal             = "internal"
)

// 流程阶段：标记会话终止/完成时所处的阶段。
const (
	StageConfig    = "config"
	StageTransmit  = "transmit"
	StageSift      = "sift"
	StageQBER      = "qber"
	StageReconcile = "reconcile"
	StageAccount   = "account"
	StagePrivacy   = "privacy"
	StageComplete  = "complete"
)

// ParamSummary 是参数摘要：只含公开参数本身，不含任何运行期比特材料。
// 缺省值按实际生效口径填充，保证审计看到的参数与执行口径一致。
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

func summaryOf(cfg Config) ParamSummary {
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

// AuditRecord 是一次会话对外的审计记录（公开口径，成功/失败同口径）。
// 注意：本结构按设计不包含 Result.Key、Reconciled.Key 等任何比特序列。
type AuditRecord struct {
	Params   ParamSummary
	Category string // 结局类别，取 Category* 常量
	Stage    string // 终止/完成阶段，取 Stage* 常量
	Success  bool
	QBER     QBEREstimate // 公开误码统计（计数与比率，无比特序列）
	Counts   Ledger       // 公开计数：各阶段比特数量，不含比特取值
	KeyBytes int          // 成功时最终密钥字节数（仅长度）；失败为 0
	Reason   string       // 固定口径的类别说明，不含任何中间量取值
}

// AuditOf 依据一次会话的输入、结果与错误构造公开审计记录。
// 调用方不得把 Result 本身对外暴露给只应看到审计口径的消费者。
func AuditOf(cfg Config, res Result, err error) AuditRecord {
	rec := AuditRecord{
		Params: summaryOf(cfg),
		QBER:   res.QBER,
		Counts: res.Ledger,
	}
	if err == nil {
		rec.Category = CategorySuccess
		rec.Stage = StageComplete
		rec.Success = true
		rec.KeyBytes = len(res.Key)
		return rec
	}

	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		// 仅参数口径（字段名 + 固定原因短语），无运行期材料。
		rec.Category = CategoryInvalidConfig
		rec.Stage = StageConfig
		rec.Reason = fmt.Sprintf("invalid config: %s %s", ve.Field, ve.Reason)
		return rec
	}

	var abort *AbortError
	switch {
	case errors.As(err, &abort):
		rec.Category = CategoryAborted
		rec.Stage = StageQBER
		rec.Reason = "estimated QBER exceeds threshold"
		return rec
	}

	switch {
	case errors.Is(err, ErrNoSignal):
		rec.Category = CategoryNoSignal
		rec.Stage = StageSift
		rec.Reason = "no usable detection after sifting"
		return rec
	case errors.Is(err, ErrReconcileFailed):
		rec.Category = CategoryReconcileFailed
		rec.Stage = StageReconcile
		rec.Reason = "reconciliation failed to converge"
		return rec
	case errors.Is(err, ErrInsufficientKeyMaterial):
		rec.Category = CategoryInsufficientMaterial
		// 抽样后无剩余发生在误码估计阶段；其余发生在账目核算阶段。
		// 判定只用公开计数，不引用任何比特序列。
		if len(res.Reconciled.Key) > 0 {
			rec.Stage = StageAccount
			rec.Reason = "insufficient key material after reconciliation"
		} else {
			rec.Stage = StageQBER
			rec.Reason = "insufficient key material after sampling"
		}
		return rec
	default:
		rec.Category = CategoryInternal
		rec.Stage = StageAccount
		// 不转发任意内部错误文本，避免意外带入中间量。
		rec.Reason = "internal error"
		return rec
	}
}
