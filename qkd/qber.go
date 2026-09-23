package qkd

import "sort"

// qberResult 保存误码率估计与窃听判定结果。
// 判定口径：qber 严格大于阈值才判定不安全；等于阈值视为通过。
// 抽样由会话随机源驱动，同一会话同一 seed 下口径固定，不会漂移。
type qberResult struct {
	sampleSize int     // 抽样比特数（估计后公开并丢弃）
	errors     int     // 样本中不一致的比特数
	qber       float64 // 估计误码率
	threshold  float64 // 判定阈值
	abort      bool    // 是否判定为不安全并终止
	aliceRest  []int   // 丢弃样本后 Alice 的剩余密钥
	bobRest    []int   // 丢弃样本后 Bob 的剩余密钥
}

// estimateQBER 对筛后密钥做确定性无放回抽样并估计误码率。
// 抽样下标取自 src.Perm 的前 k 项，完全由会话 seed 决定；
// 被抽样的比特公开比对后从密钥材料中丢弃。
func estimateQBER(cfg Config, src *Source, s siftResult) qberResult {
	n := len(s.aliceKey)
	threshold := cfg.qberThreshold()
	res := qberResult{threshold: threshold}

	k := int(cfg.sampleFraction()*float64(n) + 0.5) // 四舍五入，确定
	if k < 1 {
		k = 1
	}
	if k > n {
		k = n
	}
	res.sampleSize = k

	perm := src.Perm(n)
	sampleIdx := make(map[int]bool, k)
	errs := 0
	for _, idx := range perm[:k] {
		sampleIdx[idx] = true
		if s.aliceKey[idx] != s.bobKey[idx] {
			errs++
		}
	}
	res.errors = errs
	res.qber = float64(errs) / float64(k)
	res.abort = res.qber > threshold

	// 无论是否终止都先构造剩余密钥；若终止，调用方必须丢弃，
	// 不得出现在任何输出中。
	restIdx := make([]int, 0, n-k)
	for i := 0; i < n; i++ {
		if !sampleIdx[i] {
			restIdx = append(restIdx, i)
		}
	}
	sort.Ints(restIdx) // 保持原始顺序，保证确定性
	res.aliceRest = make([]int, 0, len(restIdx))
	res.bobRest = make([]int, 0, len(restIdx))
	for _, i := range restIdx {
		res.aliceRest = append(res.aliceRest, s.aliceKey[i])
		res.bobRest = append(res.bobRest, s.bobKey[i])
	}
	return res
}
