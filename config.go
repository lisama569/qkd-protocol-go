package qkd

import (
	"fmt"
	"math"
)

// 可选字段的缺省值。零值语义：SampleFraction/QBERThreshold <= 0 或
// SecurityMargin == 0 时使用下列缺省值，语义确定且稳定。
const (
	DefaultSampleFraction = 0.5
	DefaultQBERThreshold  = 0.11
	DefaultSecurityMargin = 32
)

// 校验失败的可区分原因。
const (
	ReasonMissing       = "missing required value"
	ReasonOutOfRange    = "value out of range"
	ReasonContradiction = "values contradict each other"
)

// ValidationError 描述参数校验失败，Field 与 Reason 可用于区分原因。
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid config: field %q: %s", e.Field, e.Reason)
}

// Config 为一次 QKD 会话的全部参数。
type Config struct {
	NumPhotons         int     // 必填，> 0：制备的光子数
	ChannelLossDB      float64 // 必填，>= 0：信道损耗（dB）
	DetectorEfficiency float64 // 必填，(0,1]：探测器效率
	DarkCountProb      float64 // 必填，[0,1)：每个时隙暗计数概率
	Eavesdrop          bool    // 可选：是否模拟窃听（拦截-重发）
	SampleFraction     float64 // 可选，(0,1)：误码抽样比例，<=0 用缺省
	QBERThreshold      float64 // 可选，(0,0.5)：窃听判定阈值，<=0 用缺省
	SecurityMargin     int     // 可选，>0：安全余量比特数，0 用缺省；负数非法
	RequestedKeyBytes  int     // 可选，>=0：请求的最终密钥字节数，0 表示尽量长
	Seed               int64   // 随机种子，相同种子结果完全一致
}

// withDefaults 返回应用缺省语义后的配置（不改原对象）。
func (c Config) withDefaults() Config {
	if c.SampleFraction <= 0 {
		c.SampleFraction = DefaultSampleFraction
	}
	if c.QBERThreshold <= 0 {
		c.QBERThreshold = DefaultQBERThreshold
	}
	if c.SecurityMargin == 0 {
		c.SecurityMargin = DefaultSecurityMargin
	}
	return c
}

// Validate 校验参数：缺失必填项或相互矛盾的取值均被拒绝，原因可区分。
func (c Config) Validate() error {
	switch {
	case c.NumPhotons == 0:
		return &ValidationError{Field: "NumPhotons", Reason: ReasonMissing}
	case c.NumPhotons < 0:
		return &ValidationError{Field: "NumPhotons", Reason: ReasonOutOfRange}
	}
	switch {
	case c.ChannelLossDB < 0:
		return &ValidationError{Field: "ChannelLossDB", Reason: ReasonOutOfRange}
	}
	switch {
	case c.DetectorEfficiency <= 0:
		return &ValidationError{Field: "DetectorEfficiency", Reason: ReasonMissing}
	case c.DetectorEfficiency > 1:
		return &ValidationError{Field: "DetectorEfficiency", Reason: ReasonOutOfRange}
	}
	switch {
	case c.DarkCountProb < 0:
		return &ValidationError{Field: "DarkCountProb", Reason: ReasonOutOfRange}
	case c.DarkCountProb >= 1:
		return &ValidationError{Field: "DarkCountProb", Reason: ReasonOutOfRange}
	}
	if c.SampleFraction < 0 || c.SampleFraction >= 1 {
		return &ValidationError{Field: "SampleFraction", Reason: ReasonOutOfRange}
	}
	if c.QBERThreshold < 0 || c.QBERThreshold >= 0.5 {
		return &ValidationError{Field: "QBERThreshold", Reason: ReasonOutOfRange}
	}
	if c.SecurityMargin < 0 {
		return &ValidationError{Field: "SecurityMargin", Reason: ReasonOutOfRange}
	}
	if c.RequestedKeyBytes < 0 {
		return &ValidationError{Field: "RequestedKeyBytes", Reason: ReasonOutOfRange}
	}
	// 矛盾检测：抽样比例为 1（或显式配置导致无密钥剩余）由上面范围检查拒绝；
	// 暗计数概率不得高于/等于探测器效率与传输概率的组合——此处用明确的
	// 组合判据：暗计数主导（darkProb >= 有效信号概率）会使筛选失去信号意义。
	signalProb := transmissionProb(c.ChannelLossDB) * c.DetectorEfficiency
	if c.DarkCountProb >= signalProb && signalProb > 0 {
		return &ValidationError{
			Field:  "DarkCountProb",
			Reason: ReasonContradiction,
		}
	}
	return nil
}

// transmissionProb 把 dB 损耗换算成光子存活概率：p = 10^(-loss/10)。
func transmissionProb(lossDB float64) float64 {
	return math.Pow(10, -lossDB/10)
}
