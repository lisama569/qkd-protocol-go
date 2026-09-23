package qkd

// siftResult 保存基比对与筛选后的结果。
// 该结构含密钥材料，仅在会话内部使用，不外泄。
type siftResult struct {
	aliceKey []int // Alice 侧筛后密钥比特
	bobKey   []int // Bob 侧筛后密钥比特
	sent     int   // 发送的光子总数
	detected int   // Bob 探测到计数的事件数
}

// sift 执行 BB84 的制备-传输-筛选阶段：
//  1. Alice 随机制备比特与基；
//  2. Bob 随机选基测量（经信道模拟）；
//  3. 双方公开比对基，仅保留基一致且探测到计数的事件。
func sift(cfg Config, ch *Channel, src *Source) siftResult {
	n := cfg.NumQubits
	aliceKey := make([]int, 0, n/2)
	bobKey := make([]int, 0, n/2)
	detected := 0

	for i := 0; i < n; i++ {
		aliceBit := src.Bit()
		aliceBasis := src.Bit()
		bobBasis := src.Bit()

		det, bobBit := ch.Transmit(src, aliceBit, aliceBasis, bobBasis)
		if !det {
			continue
		}
		detected++
		if aliceBasis != bobBasis {
			continue // 基不一致，丢弃
		}
		aliceKey = append(aliceKey, aliceBit)
		bobKey = append(bobKey, bobBit)
	}
	return siftResult{aliceKey: aliceKey, bobKey: bobKey, sent: n, detected: detected}
}
