package qkd

import "math/rand"

// Source 是会话级确定性随机源，每个会话独立，互不影响。
type Source struct {
	rng *rand.Rand
}

func NewSource(seed int64) *Source {
	return &Source{rng: rand.New(rand.NewSource(seed))}
}

func (s *Source) Float64() float64 { return s.rng.Float64() }

func (s *Source) Bit() int { return s.rng.Intn(2) }

// Perm 返回 [0,n) 的确定性随机排列。
func (s *Source) Perm(n int) []int { return s.rng.Perm(n) }
