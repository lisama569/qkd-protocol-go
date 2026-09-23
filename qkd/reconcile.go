package qkd

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

var (
	// ErrInsufficientMaterial 表示密钥材料不足，会话必须失败，
	// 不得截断、补齐或静默降级。
	ErrInsufficientMaterial = errors.New("qkd: insufficient key material")
	// ErrKeyVerification 表示误码纠正后双方密钥校验失败。
	ErrKeyVerification = errors.New("qkd: key verification failed")
)

// verifyLeakBits 是密钥校验公开的比特数（SHA-256 截断）。
const verifyLeakBits = 32

// Ledger 记录一次会话的密钥账目，满足守恒：
//
//	Final == Sifted - Sampled - ECLeak - VerifyLeak - PALeak
type Ledger struct {
	Sent       int // 发送的光子数
	Detected   int // 探测到计数的事件数
	Sifted     int // 筛后密钥长度
	Sampled    int // 误码估计抽样并丢弃的比特数
	ECLeak     int // 误码纠正公开的校验比特数
	VerifyLeak int // 密钥校验公开的比特数
	PALeak     int // 隐私放大减去的比特数（窃听者信息上界）
	Final      int // 最终密钥长度
}

// Conserved 报告账目是否守恒。
func (l Ledger) Conserved() bool {
	return l.Final == l.Sifted-l.Sampled-l.ECLeak-l.VerifyLeak-l.PALeak
}

// binaryEntropy 是二元熵函数 h2(x)，边界处定义为 0。
func binaryEntropy(x float64) float64 {
	if x <= 0 || x >= 1 {
		return 0
	}
	return -x*math.Log2(x) - (1-x)*math.Log2(1-x)
}

// parity 返回 bits 在 idx 下标集合上的异或校验。
func parity(bits []int, idx []int) int {
	p := 0
	for _, i := range idx {
		p ^= bits[i]
	}
	return p
}

// locateAndFix 在已知校验不一致的下标块内做二分定位并纠正 Bob 的一个错误比特，
// 返回过程中公开的校验比特数。确定性，不消耗随机数。
func locateAndFix(alice, bob []int, block []int) int {
	leak := 0
	for len(block) > 1 {
		half := len(block) / 2
		leak++ // Alice 公开前半块校验
		if parity(alice, block[:half]) != parity(bob, block[:half]) {
			block = block[:half]
		} else {
			block = block[half:]
		}
	}
	bob[block[0]] ^= 1
	return leak
}

// errorCorrect 执行简化的 Cascade 式误码纠正：
// 分块比对校验，不一致的块内二分定位单个错误并翻转；
// 共两轮，第二轮先用会话随机源确定性洗牌以打散残留错误。
// 返回 Bob 纠正后的密钥与公开的校验比特总数。
func errorCorrect(cfg Config, src *Source, qber float64, alice, bob []int) ([]int, int) {
	n := len(alice)
	out := make([]int, n)
	copy(out, bob)
	if n == 0 || qber <= 0 {
		return out, 0
	}
	// 基础块大小取约每块 1 个错误，至少为 2。
	base := int(1/qber + 0.5)
	if base < 2 {
		base = 2
	}
	// Cascade 式纠错：块大小每两轮翻倍，洗牌后重分块；
	// 某一轮没有任何纠正即可提前结束，上限 10 轮。
	// 全程确定性：洗牌由会话随机源驱动，轮次与块大小只依赖 qber 与 n。
	leak := 0
	for pass := 0; pass < 10; pass++ {
		blockSize := base << (pass / 2)
		order := make([]int, n)
		for i := range order {
			order[i] = i
		}
		if pass > 0 {
			order = src.Perm(n) // 确定性洗牌
		}
		fixed := 0
		for start := 0; start < n; start += blockSize {
			end := start + blockSize
			if end > n {
				end = n
			}
			block := order[start:end]
			leak++ // Alice 公开块校验
			if parity(alice, block) != parity(out, block) {
				leak += locateAndFix(alice, out, block)
				fixed++
			}
		}
		if pass > 0 && fixed == 0 {
			break // 一整轮无纠正，收敛
		}
	}
	return out, leak
}

// packBits 将比特切片按 MSB 优先打包为字节。
func packBits(bits []int) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}

// verifyKey 比较双方密钥的截断 SHA-256 校验值，
// 公开比特数恒为 verifyLeakBits。
func verifyKey(alice, bob []int) bool {
	sumA := sha256.Sum256(packBits(alice))
	sumB := sha256.Sum256(packBits(bob))
	return binary.BigEndian.Uint32(sumA[:4]) == binary.BigEndian.Uint32(sumB[:4])
}

// privacyAmplify 用 Toeplitz 通用哈希将 key 压缩为 outLen 比特，
// 矩阵种子取自会话随机源，确定性可复现。返回打包后的字节。
func privacyAmplify(src *Source, key []int, outLen int) []byte {
	n := len(key)
	// Toeplitz 矩阵由 n+outLen-1 个随机比特确定。
	t := make([]int, n+outLen-1)
	for i := range t {
		t[i] = src.Bit()
	}
	out := make([]int, outLen)
	for i := 0; i < outLen; i++ {
		acc := 0
		for j := 0; j < n; j++ {
			acc ^= t[i+j] & key[j]
		}
		out[i] = acc
	}
	return packBits(out)
}

// reconcile 串联误码纠正、密钥校验与隐私放大，并核算账目。
// 任何一步失败都返回错误且不输出密钥材料。
func reconcile(cfg Config, src *Source, q qberResult, ledger *Ledger) ([]byte, error) {
	alice := q.aliceRest
	n := len(alice)

	corrected, ecLeak := errorCorrect(cfg, src, q.qber, alice, q.bobRest)
	ledger.ECLeak = ecLeak

	ledger.VerifyLeak = verifyLeakBits
	if !verifyKey(alice, corrected) {
		return nil, ErrKeyVerification
	}

	// 隐私放大：减去窃听者信息上界 n*h2(qber)。
	paLeak := int(math.Ceil(float64(n) * binaryEntropy(q.qber)))
	ledger.PALeak = paLeak

	finalLen := n - ecLeak - verifyLeakBits - paLeak
	ledger.Final = finalLen
	if finalLen <= 0 {
		return nil, errors.Join(ErrInsufficientMaterial,
			errors.New("no positive key length remains after reconciliation"))
	}
	if finalLen < cfg.requiredKeyBits() {
		return nil, errors.Join(ErrInsufficientMaterial,
			errors.New("final key shorter than RequiredKeyBits"))
	}

	return privacyAmplify(src, alice, finalLen), nil
}
