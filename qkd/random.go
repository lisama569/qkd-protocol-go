package qkd

import "math/rand"

// Source 是每个会话独立的确定性随机源。
// 不同会话持有各自实例，互不共享状态，因此并发会话互不影响。
// 非并发安全：同一会话内按固定顺序串行消费，保证可复现。
type Source struct {
	rng *rand.Rand
}

// NewSource 以给定种子创建随机源。
func NewSource(seed int64) *Source {
	return &Source{rng: rand.New(rand.NewSource(seed))}
}

// Bit 返回一个均匀随机比特（0 或 1）。
func (s *Source) Bit() int {
	return s.rng.Intn(2)
}

// Float64 返回 [0,1) 上的均匀随机数。
func (s *Source) Float64() float64 {
	return s.rng.Float64()
}

// Intn 返回 [0,n) 上的均匀随机整数。
func (s *Source) Intn(n int) int {
	return s.rng.Intn(n)
}

// Perm 返回 [0,n) 的一个随机排列，用于确定性的无放回抽样。
func (s *Source) Perm(n int) []int {
	return s.rng.Perm(n)
}
