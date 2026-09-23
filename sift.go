package qkd

// Sift 进行基比对与筛选：仅保留 Bob 探测到且双方基一致的事件。
// 返回双方筛后密钥与保留位置（在原光子序列中的下标，升序）。
func Sift(photons []Photon) (alice, bob []int, kept []int) {
	for i, p := range photons {
		if !p.Detected || p.AliceBasis != p.BobBasis {
			continue
		}
		alice = append(alice, p.Bit)
		bob = append(bob, p.Measured)
		kept = append(kept, i)
	}
	return alice, bob, kept
}
