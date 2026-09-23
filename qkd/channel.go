package qkd

import "math"

// 基的编码：0 = Z 基（直线基），1 = X 基（对角基）。
const (
	BasisZ = 0
	BasisX = 1
)

// Channel 是本地模拟的光子信道，覆盖信道损耗、
// 探测器效率、暗计数，以及可选的拦截-重发式窃听者。
// 信道本身无状态，全部随机性来自调用方传入的会话级 Source，
// 因此同一 seed 下行为完全可复现。
type Channel struct {
	pTransmit float64 // 光子存活概率 10^(-loss/10)
	eta       float64 // 探测器效率
	pDark     float64 // 每时隙暗计数概率
	eve       bool    // 是否存在窃听者
}

// NewChannel 由配置构造信道。
func NewChannel(cfg Config) *Channel {
	return &Channel{
		pTransmit: math.Pow(10, -cfg.channelLossDB()/10),
		eta:       cfg.detectorEfficiency(),
		pDark:     cfg.darkCountProb(),
		eve:       cfg.eavesdropper(),
	}
}

// Transmit 模拟 Alice 发送一个光子、Bob 以 bobBasis 测量的全过程。
// 返回 detected 表示 Bob 是否探测到计数，bit 为 Bob 记录的测量比特。
//
// 物理模型：
//  1. 若存在窃听者，Eve 以随机基拦截测量并重发，引入 25% 的额外误码；
//  2. 光子以 pTransmit 概率存活，存活后以 eta 概率被探测；
//  3. 无信号计数时，以 pDark 概率产生暗计数，给出随机比特；
//  4. Bob 的测量基与承载基一致时得到承载比特，否则得到随机比特。
func (ch *Channel) Transmit(src *Source, aliceBit, aliceBasis, bobBasis int) (detected bool, bit int) {
	// 光子当前承载的比特与基。
	carriedBit, carriedBasis := aliceBit, aliceBasis

	// 窃听者：随机选基测量并重发。
	if ch.eve {
		eveBasis := src.Bit()
		eveBit := carriedBit
		if eveBasis != carriedBasis {
			eveBit = src.Bit() // 基不匹配，测量结果随机
		}
		carriedBit, carriedBasis = eveBit, eveBasis
	}

	// 信号计数：光子存活且探测器响应。
	signalClick := src.Float64() < ch.pTransmit && src.Float64() < ch.eta
	if signalClick {
		if bobBasis == carriedBasis {
			return true, carriedBit
		}
		return true, src.Bit() // 基不匹配，结果随机
	}

	// 暗计数：随机比特。
	if src.Float64() < ch.pDark {
		return true, src.Bit()
	}
	return false, 0
}
