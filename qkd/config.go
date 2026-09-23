package qkd

import (
	"errors"
	"fmt"
	"math"
)

// 可区分的校验错误类别，调用方可用 errors.Is 判定。
var (
	// ErrMissingField 表示必填字段缺失（零值）。
	ErrMissingField = errors.New("qkd: missing required field")
	// ErrInvalidValue 表示单个字段取值越界。
	ErrInvalidValue = errors.New("qkd: invalid field value")
	// ErrConflictingValues 表示字段组合相互矛盾、协议必然失败。
	ErrConflictingValues = errors.New("qkd: conflicting field values")
)

// 可选字段的缺省值，语义确定且稳定。
const (
	DefaultSeed            int64   = 1
	DefaultChannelLossDB   float64 = 0.0
	DefaultDetectorEff     float64 = 1.0
	DefaultDarkCountProb   float64 = 0.0
	DefaultQBERThreshold   float64 = 0.11
	DefaultSampleFraction  float64 = 0.2
	DefaultEavesdropper            = false
	DefaultECEfficiency    float64 = 1.16
	DefaultRequiredKeyBits         = 0 // 0 表示不强制要求，产出多少算多少
)

// Config 描述一次 QKD 会话的全部参数。
//
// 必填字段：NumQubits。
// 其余字段均为可选，零值时由 withDefaults 填入缺省值；
// 若调用方想显式使用零值（如 Seed=0），可直接设置，withDefaults
// 仅替换未设置的字段，因此可选字段以指针表达“未设置”。
type Config struct {
	// NumQubits 是 Alice 制备的光子（量子比特）数量，必填，>0。
	NumQubits int

	// Seed 是会话随机源种子；nil 表示使用 DefaultSeed。
	// 相同 Seed 与相同参数下，会话结果完全一致。
	Seed *int64

	// ChannelLossDB 是信道损耗（dB），>=0；nil 表示无损耗。
	ChannelLossDB *float64

	// DetectorEfficiency 是探测器效率，取值 (0,1]；nil 表示理想探测器。
	DetectorEfficiency *float64

	// DarkCountProb 是每时隙暗计数概率，取值 [0,1)；nil 表示无暗计数。
	DarkCountProb *float64

	// QBERThreshold 是窃听判定阈值，取值 (0,0.5)；nil 用缺省 0.11。
	// 估计误码率严格大于该值时判定信道不安全并终止会话。
	QBERThreshold *float64

	// SampleFraction 是用于误码率估计的抽样比例，取值 (0,1)；
	// nil 用缺省 0.2。被抽样的比特在估计后公开并丢弃。
	SampleFraction *float64

	// Eavesdropper 表示信道中是否存在拦截-重发式窃听者。
	Eavesdropper *bool

	// ECEfficiency 是误码纠正效率因子 f_EC，>=1；nil 用缺省 1.16。
	// 用于在纠错失败回退时估计泄漏上界。
	ECEfficiency *float64

	// RequiredKeyBits 是要求的最短最终密钥长度（比特）；
	// nil 或 0 表示不强制。若密钥材料不足，会话必须失败，
	// 不得截断、补齐或静默降级。
	RequiredKeyBits *int
}

func (c Config) seed() int64 {
	if c.Seed == nil {
		return DefaultSeed
	}
	return *c.Seed
}

func (c Config) channelLossDB() float64 {
	if c.ChannelLossDB == nil {
		return DefaultChannelLossDB
	}
	return *c.ChannelLossDB
}

func (c Config) detectorEfficiency() float64 {
	if c.DetectorEfficiency == nil {
		return DefaultDetectorEff
	}
	return *c.DetectorEfficiency
}

func (c Config) darkCountProb() float64 {
	if c.DarkCountProb == nil {
		return DefaultDarkCountProb
	}
	return *c.DarkCountProb
}

func (c Config) qberThreshold() float64 {
	if c.QBERThreshold == nil {
		return DefaultQBERThreshold
	}
	return *c.QBERThreshold
}

func (c Config) sampleFraction() float64 {
	if c.SampleFraction == nil {
		return DefaultSampleFraction
	}
	return *c.SampleFraction
}

func (c Config) eavesdropper() bool {
	if c.Eavesdropper == nil {
		return DefaultEavesdropper
	}
	return *c.Eavesdropper
}

func (c Config) ecEfficiency() float64 {
	if c.ECEfficiency == nil {
		return DefaultECEfficiency
	}
	return *c.ECEfficiency
}

func (c Config) requiredKeyBits() int {
	if c.RequiredKeyBits == nil {
		return DefaultRequiredKeyBits
	}
	return *c.RequiredKeyBits
}

// Validate 校验配置。返回的错误可用 errors.Is 与
// ErrMissingField / ErrInvalidValue / ErrConflictingValues 匹配，
// 以区分缺失、越界与矛盾三类原因。
func (c Config) Validate() error {
	if c.NumQubits <= 0 {
		return fmt.Errorf("%w: NumQubits must be > 0, got %d", ErrMissingField, c.NumQubits)
	}
	if c.ChannelLossDB != nil && (*c.ChannelLossDB < 0 || math.IsNaN(*c.ChannelLossDB)) {
		return fmt.Errorf("%w: ChannelLossDB must be >= 0, got %v", ErrInvalidValue, *c.ChannelLossDB)
	}
	if c.DetectorEfficiency != nil && (*c.DetectorEfficiency <= 0 || *c.DetectorEfficiency > 1) {
		return fmt.Errorf("%w: DetectorEfficiency must be in (0,1], got %v", ErrInvalidValue, *c.DetectorEfficiency)
	}
	if c.DarkCountProb != nil && (*c.DarkCountProb < 0 || *c.DarkCountProb >= 1) {
		return fmt.Errorf("%w: DarkCountProb must be in [0,1), got %v", ErrInvalidValue, *c.DarkCountProb)
	}
	if c.QBERThreshold != nil && (*c.QBERThreshold <= 0 || *c.QBERThreshold >= 0.5) {
		return fmt.Errorf("%w: QBERThreshold must be in (0,0.5), got %v", ErrInvalidValue, *c.QBERThreshold)
	}
	if c.SampleFraction != nil && (*c.SampleFraction <= 0 || *c.SampleFraction >= 1) {
		return fmt.Errorf("%w: SampleFraction must be in (0,1), got %v", ErrInvalidValue, *c.SampleFraction)
	}
	if c.ECEfficiency != nil && *c.ECEfficiency < 1 {
		return fmt.Errorf("%w: ECEfficiency must be >= 1, got %v", ErrInvalidValue, *c.ECEfficiency)
	}
	if c.RequiredKeyBits != nil && *c.RequiredKeyBits < 0 {
		return fmt.Errorf("%w: RequiredKeyBits must be >= 0, got %v", ErrInvalidValue, *c.RequiredKeyBits)
	}

	// 矛盾检测 1：要求的密钥长度在信息论上不可能达到——
	// 即使无损耗、无窃听，筛后密钥上界也只有 NumQubits。
	if c.requiredKeyBits() > c.NumQubits {
		return fmt.Errorf("%w: RequiredKeyBits=%d exceeds NumQubits=%d (impossible even ideally)",
			ErrConflictingValues, c.requiredKeyBits(), c.NumQubits)
	}

	// 矛盾检测 2：由暗计数决定的固有误码率下限已达到或超过判定阈值，
	// 会话必然被判定为不安全，参数组合自相矛盾。
	if floor := intrinsicQBERFloor(c.channelLossDB(), c.detectorEfficiency(), c.darkCountProb()); floor >= c.qberThreshold() {
		return fmt.Errorf("%w: intrinsic QBER floor %.4f (from dark counts/loss/efficiency) >= QBERThreshold %.4f",
			ErrConflictingValues, floor, c.qberThreshold())
	}
	return nil
}

// intrinsicQBERFloor 计算无窃听时由暗计数导致的固有误码率下限：
// 信号探测率 pSig = eta * 10^(-loss/10)，暗计数 pDark 中一半给出错误比特。
func intrinsicQBERFloor(lossDB, eta, pDark float64) float64 {
	pSig := eta * math.Pow(10, -lossDB/10)
	if pSig+pDark <= 0 {
		return 0.5
	}
	return (pDark / 2) / (pSig + pDark)
}

// withDefaults 当前为恒等实现：缺省值由上面的访问器惰性提供，
// 保证缺省语义集中、确定且稳定。
func (c Config) withDefaults() Config { return c }
