package qkd

import "sort"

// QBEREstimate 记录误码率估计与窃听判定依据。
type QBEREstimate struct {
	SampleSize int
	Errors     int
	QBER       float64
	Threshold  float64
	Secure     bool
}

// EstimateQBER 用确定性抽样估计误码率：
// 抽样下标由会话随机源的 Perm 产生，对同一会话（同种子、同输入）完全确定，
// 与抽样比例、丢弃策略的实现细节无关，不会引起结论漂移。
// 抽样比特被公开比对，必须从密钥中丢弃（返回剩余下标）。
// 判定规则：QBER > threshold 判为不安全；QBER == threshold 判为安全（含），
// 临界行为稳定可解释。
func EstimateQBER(alice, bob []int, sampleSize int, src *Source, threshold float64) (QBEREstimate, []int) {
	n := len(alice)
	if sampleSize > n {
		sampleSize = n
	}
	perm := src.Perm(n)
	sample := append([]int(nil), perm[:sampleSize]...)
	sort.Ints(sample)

	errors := 0
	inSample := make(map[int]bool, sampleSize)
	for _, idx := range sample {
		inSample[idx] = true
		if alice[idx] != bob[idx] {
			errors++
		}
	}
	remaining := make([]int, 0, n-sampleSize)
	for i := 0; i < n; i++ {
		if !inSample[i] {
			remaining = append(remaining, i)
		}
	}
	qber := 0.0
	if sampleSize > 0 {
		qber = float64(errors) / float64(sampleSize)
	}
	return QBEREstimate{
		SampleSize: sampleSize,
		Errors:     errors,
		QBER:       qber,
		Threshold:  threshold,
		Secure:     qber <= threshold,
	}, remaining
}
