package qkd

// ReconcileResult 记录误码纠正结果与泄漏量。
type ReconcileResult struct {
	Key         []int // 纠正后的密钥（与 Alice 侧一致）
	LeakedBits  int   // 纠错过程公开的奇偶校验比特总数（泄漏量）
	ErrorsFixed int   // 实际纠正的比特数
}

const (
	reconcileInitBlock = 8 // 初始分块大小
	reconcileMaxPasses = 6 // 最大洗牌轮数
)

// Reconcile 对 Bob 侧密钥做误码纠正（简化 Cascade）：
// 每轮用会话随机源洗牌后分块，比较每块奇偶性（每比较一次泄漏 1 比特），
// 奇偶不一致时在块内二分定位并纠正一个错误；块大小逐轮翻倍。
// 全程确定性：同种子、同输入必得同结果。
func Reconcile(alice, bob []int, src *Source) ReconcileResult {
	n := len(alice)
	corrected := append([]int(nil), bob...)
	res := ReconcileResult{Key: corrected}
	if n == 0 {
		return res
	}
	blockSize := reconcileInitBlock
	if blockSize > n {
		blockSize = n
	}
	for pass := 0; pass < reconcileMaxPasses; pass++ {
		perm := src.Perm(n)
		passFixed := 0
		for start := 0; start < n; start += blockSize {
			end := start + blockSize
			if end > n {
				end = n
			}
			block := perm[start:end]
			res.LeakedBits++ // 公开一次块奇偶
			if parity(alice, block) != parity(corrected, block) {
				idx := bisectError(alice, corrected, block, &res.LeakedBits)
				corrected[idx] ^= 1
				res.ErrorsFixed++
				passFixed++
			}
		}
		if passFixed == 0 {
			break // 一整轮无错误，收敛
		}
		blockSize *= 2
		if blockSize > n {
			blockSize = n
		}
	}
	return res
}

// bisectError 在已知含奇数个错误的块内二分定位一个错误比特，
// 每次二分公开一次子块奇偶（计入泄漏）。
func bisectError(alice, corrected, block []int, leaked *int) int {
	for len(block) > 1 {
		half := len(block) / 2
		left := block[:half]
		*leaked++
		if parity(alice, left) != parity(corrected, left) {
			block = left
		} else {
			block = block[half:]
		}
	}
	return block[0]
}

func parity(key []int, idxs []int) int {
	p := 0
	for _, i := range idxs {
		p ^= key[i]
	}
	return p
}
