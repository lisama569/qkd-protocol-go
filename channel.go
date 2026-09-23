package qkd

// Photon 记录一个光子在信道中的传输结果。
type Photon struct {
	Bit        int  // Alice 制备的比特
	AliceBasis int  // Alice 制备基（0/1）
	BobBasis   int  // Bob 测量基（0/1）
	Detected   bool // Bob 是否探测到
	Measured   int  // Bob 测得的比特（未探测时无意义）
}

// Channel 是本地模拟的光子信道，含损耗、探测器效率、暗计数与可选窃听。
// 所有随机性来自会话级 Source，保证同种子可复现。
type Channel struct {
	lossDB   float64
	detEff   float64
	darkProb float64
	eve      bool
	src      *Source
}

func NewChannel(lossDB, detEff, darkProb float64, eve bool, src *Source) *Channel {
	return &Channel{lossDB: lossDB, detEff: detEff, darkProb: darkProb, eve: eve, src: src}
}

// Transmit 模拟发送一个光子：
//  1. 可选窃听：Eve 拦截-重发，随机选基测量（1/2 概率选错基），
//     选错基时重发的态与 Alice 原态在 Bob 基匹配时有 1/2 概率出错，
//     合计在筛后密钥中引入 25% 误码。
//  2. 信道损耗 + 探测器效率：光子以 p = 10^(-loss/10) * detEff 概率到达并被探测。
//  3. 暗计数：未探测到信号光子的时隙以 darkProb 概率产生随机比特的虚假计数。
func (ch *Channel) Transmit(bit, aliceBasis, bobBasis int) Photon {
	eveBit, eveBasis := bit, aliceBasis
	if ch.eve {
		eveBasis = ch.src.Bit()
		eveBit = measure(bit, aliceBasis, eveBasis, ch.src)
	}
	survives := ch.src.Float64() < transmissionProb(ch.lossDB)*ch.detEff
	p := Photon{Bit: bit, AliceBasis: aliceBasis, BobBasis: bobBasis}
	if survives {
		p.Detected = true
		p.Measured = measure(eveBit, eveBasis, bobBasis, ch.src)
		return p
	}
	// 暗计数：虚假探测，比特随机
	if ch.src.Float64() < ch.darkProb {
		p.Detected = true
		p.Measured = ch.src.Bit()
	}
	return p
}

// measure 在 basis 上测量处于 (bit, prepBasis) 态的光子：
// 基匹配时结果确定，基不匹配时结果随机。
func measure(bit, prepBasis, basis int, src *Source) int {
	if prepBasis == basis {
		return bit
	}
	return src.Bit()
}
