package qkd

import "errors"

// ErrInsufficientKeyMaterial 表示密钥材料不足，必须显式拒绝，
// 不得截断、补齐或静默降级。
var ErrInsufficientKeyMaterial = errors.New("insufficient key material")

// PrivacyAmplify 用 Toeplitz 哈希做隐私放大：
// 由会话随机源生成 inLen+outLen-1 个种子比特确定 Toeplitz 矩阵，
// 输出第 i 位为 key 与第 i 行的模二内积。全程确定性。
// outLen <= 0 或 outLen > len(key) 时返回 ErrInsufficientKeyMaterial。
func PrivacyAmplify(key []int, outLen int, src *Source) ([]int, error) {
	inLen := len(key)
	if outLen <= 0 || outLen > inLen {
		return nil, ErrInsufficientKeyMaterial
	}
	seed := make([]int, inLen+outLen-1)
	for i := range seed {
		seed[i] = src.Bit()
	}
	out := make([]int, outLen)
	for i := 0; i < outLen; i++ {
		acc := 0
		row := seed[i : i+inLen] // 第 i 行：T[i][j] = seed[i+j]
		for j := 0; j < inLen; j++ {
			acc ^= key[j] & row[j]
		}
		out[i] = acc
	}
	return out, nil
}
