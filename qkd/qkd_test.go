package qkd

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func i64(v int64) *int64     { return &v }
func f64(v float64) *float64 { return &v }
func boolean(v bool) *bool   { return &v }
func integer(v int) *int     { return &v }

func makeConfig(mut func(*Config)) Config {
	cfg := Config{
		NumQubits:          20000,
		Seed:               i64(42),
		ChannelLossDB:      f64(0),
		DetectorEfficiency: f64(1.0),
		DarkCountProb:      f64(0),
		QBERThreshold:      f64(0.11),
		SampleFraction:     f64(0.2),
		Eavesdropper:       boolean(false),
	}
	if mut != nil {
		mut(&cfg)
	}
	return cfg
}

func logResult(t *testing.T, name string, cfg Config, res *Result, err error) {
	t.Helper()
	l := res.Ledger
	t.Logf("[%s] 输入: NumQubits=%d Seed=%d Loss=%.1fdB Eta=%.2f Dark=%.3f Threshold=%.2f SampleFrac=%.2f Eve=%v Required=%d",
		name, cfg.NumQubits, cfg.seed(), cfg.channelLossDB(), cfg.detectorEfficiency(),
		cfg.darkCountProb(), cfg.qberThreshold(), cfg.sampleFraction(), cfg.eavesdropper(), cfg.requiredKeyBits())
	t.Logf("[%s] 中间量: sent=%d detected=%d sifted=%d sampled=%d qber=%.4f threshold=%.2f",
		name, l.Sent, l.Detected, l.Sifted, l.Sampled, res.QBER, cfg.qberThreshold())
	t.Logf("[%s] 账目: ecLeak=%d verifyLeak=%d paLeak=%d final=%d conserved=%v",
		name, l.ECLeak, l.VerifyLeak, l.PALeak, l.Final, l.Conserved())
	t.Logf("[%s] 判定: aborted=%v reason=%q err=%v", name, res.Aborted, res.Reason, err)
}

// TestNoEavesdrop 覆盖无窃听场景：会话成功、账目守恒、结果可复现。
func TestNoEavesdrop(t *testing.T) {
	cfg := makeConfig(nil)
	res1, err1 := mustRun(t, cfg)
	res2, err2 := mustRun(t, cfg)
	logResult(t, "no-eve", cfg, res1, err1)

	if err1 != nil || err2 != nil {
		t.Fatalf("expected success, got %v / %v", err1, err2)
	}
	if res1.Aborted {
		t.Fatal("session should not abort without eavesdropper")
	}
	if len(res1.Key) == 0 {
		t.Fatal("expected non-empty final key")
	}
	if !res1.Ledger.Conserved() {
		t.Fatalf("ledger not conserved: %+v", res1.Ledger)
	}
	if !bytes.Equal(res1.Key, res2.Key) {
		t.Fatal("same seed must reproduce identical key")
	}
}

func mustRun(t *testing.T, cfg Config) (*Result, error) {
	t.Helper()
	sess, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	return sess.Run()
}

// TestEavesdrop 覆盖存在窃听场景：判定不安全并终止，不输出任何密钥材料。
func TestEavesdrop(t *testing.T) {
	cfg := makeConfig(func(c *Config) { c.Eavesdropper = boolean(true) })
	res, err := mustRun(t, cfg)
	logResult(t, "eve", cfg, res, err)

	if !errors.Is(err, ErrSessionAborted) {
		t.Fatalf("expected ErrSessionAborted, got %v", err)
	}
	if !res.Aborted || res.Key != nil {
		t.Fatalf("aborted session must not output key material: %+v", res)
	}
	if res.QBER <= cfg.qberThreshold() {
		t.Fatalf("abort requires qber > threshold, got %.4f <= %.2f", res.QBER, cfg.qberThreshold())
	}
}

// TestHighLoss 覆盖高损耗场景：几乎无探测事件，会话因无筛后密钥终止。
func TestHighLoss(t *testing.T) {
	cfg := makeConfig(func(c *Config) {
		c.ChannelLossDB = f64(60)
		c.DetectorEfficiency = f64(0.1)
	})
	res, err := mustRun(t, cfg)
	logResult(t, "high-loss", cfg, res, err)

	if !errors.Is(err, ErrSessionAborted) {
		t.Fatalf("expected abort on dead channel, got %v", err)
	}
	if res.Key != nil {
		t.Fatal("aborted session must not output key material")
	}
	if res.Ledger.Detected >= res.Ledger.Sent/100 {
		t.Fatalf("expected very low detection, got %d/%d", res.Ledger.Detected, res.Ledger.Sent)
	}
}

// TestNoisyChannel 覆盖有暗计数但低于阈值的场景：纠错后成功出钥。
func TestNoisyChannel(t *testing.T) {
	cfg := makeConfig(func(c *Config) {
		c.ChannelLossDB = f64(3)
		c.DetectorEfficiency = f64(0.5)
		c.DarkCountProb = f64(0.05)
	})
	res, err := mustRun(t, cfg)
	logResult(t, "noisy", cfg, res, err)

	if err != nil {
		t.Fatalf("expected success below threshold, got %v", err)
	}
	if res.QBER <= 0 {
		t.Fatal("expected positive QBER from dark counts")
	}
	if res.Ledger.ECLeak == 0 {
		t.Fatal("expected error-correction leakage on noisy channel")
	}
	if !res.Ledger.Conserved() {
		t.Fatalf("ledger not conserved: %+v", res.Ledger)
	}
}

// TestInsufficientMaterial 覆盖材料不足场景：必须明确拒绝，不得截断或补齐。
func TestInsufficientMaterial(t *testing.T) {
	cfg := makeConfig(func(c *Config) {
		c.ChannelLossDB = f64(3)
		c.DetectorEfficiency = f64(0.5)
		c.DarkCountProb = f64(0.05)
	})
	// 先跑一次拿到实际可产出长度。
	probe, err := mustRun(t, cfg)
	if err != nil {
		t.Fatalf("probe run failed: %v", err)
	}
	available := probe.Ledger.Final
	t.Logf("[insufficient] 可产出长度=%d，要求=%d", available, available+1)

	cfg.RequiredKeyBits = integer(available + 1)
	res, err := mustRun(t, cfg)
	logResult(t, "insufficient", cfg, res, err)

	if !errors.Is(err, ErrInsufficientMaterial) {
		t.Fatalf("expected ErrInsufficientMaterial, got %v", err)
	}
	if res.Key != nil {
		t.Fatal("must not output truncated or padded key")
	}
}

// TestConcurrentSessions 覆盖并发会话：各自随机状态与账目互不影响，
// 且与串行运行结果完全一致。
func TestConcurrentSessions(t *testing.T) {
	const n = 8
	cfgs := make([]Config, n)
	for i := 0; i < n; i++ {
		seed := int64(1000 + i)
		cfgs[i] = makeConfig(func(c *Config) {
			c.Seed = i64(seed)
			c.DarkCountProb = f64(0.01 * float64(i%3))
		})
	}
	// 串行基准。
	want := make([][]byte, n)
	for i, cfg := range cfgs {
		res, err := mustRun(t, cfg)
		if err != nil {
			t.Fatalf("serial session %d failed: %v", i, err)
		}
		want[i] = res.Key
	}
	// 并发运行。
	got := make([][]byte, n)
	var wg sync.WaitGroup
	for i, cfg := range cfgs {
		wg.Add(1)
		go func(i int, cfg Config) {
			defer wg.Done()
			sess, err := NewSession(cfg)
			if err != nil {
				t.Errorf("config %d rejected: %v", i, err)
				return
			}
			res, err := sess.Run()
			if err != nil {
				t.Errorf("concurrent session %d failed: %v", i, err)
				return
			}
			t.Logf("[concurrent-%d] seed=%d sifted=%d final=%d", i, cfg.seed(), res.Ledger.Sifted, res.Ledger.Final)
			got[i] = res.Key
		}(i, cfg)
	}
	wg.Wait()
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Errorf("session %d: concurrent result differs from serial", i)
		}
	}
}

// TestConfigValidation 覆盖缺失、越界与矛盾三类可区分的拒绝原因。
func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{"missing NumQubits", makeConfig(func(c *Config) { c.NumQubits = 0 }), ErrMissingField},
		{"negative loss", makeConfig(func(c *Config) { c.ChannelLossDB = f64(-1) }), ErrInvalidValue},
		{"eta above 1", makeConfig(func(c *Config) { c.DetectorEfficiency = f64(1.5) }), ErrInvalidValue},
		{"dark count >= 1", makeConfig(func(c *Config) { c.DarkCountProb = f64(1) }), ErrInvalidValue},
		{"threshold out of range", makeConfig(func(c *Config) { c.QBERThreshold = f64(0.5) }), ErrInvalidValue},
		{"sample fraction out of range", makeConfig(func(c *Config) { c.SampleFraction = f64(1) }), ErrInvalidValue},
		{"required exceeds qubits", makeConfig(func(c *Config) { c.RequiredKeyBits = integer(20001) }), ErrConflictingValues},
		{"dark-count floor above threshold", makeConfig(func(c *Config) {
			c.ChannelLossDB = f64(20)
			c.DetectorEfficiency = f64(0.1)
			c.DarkCountProb = f64(0.01)
		}), ErrConflictingValues},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			t.Logf("[validate-%s] err=%v", tc.name, err)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestQBERBoundary 覆盖临界误码率：qber == threshold 通过，qber > threshold 终止。
func TestQBERBoundary(t *testing.T) {
	const (
		n         = 1000
		frac      = 0.1  // 样本量 k=100
		threshold = 0.11 // 11 个错误恰为临界
	)
	seed := int64(7)
	// 用同 seed 的随机源预先算出抽样下标，把错误精确放在样本内。
	perm := NewSource(seed).Perm(n)
	sampleIdx := perm[:100]

	build := func(numErr int) siftResult {
		alice := make([]int, n)
		bob := make([]int, n)
		for i := 0; i < numErr; i++ {
			bob[sampleIdx[i]] = 1 // 与 alice 不一致
		}
		return siftResult{aliceKey: alice, bobKey: bob, sent: n, detected: n}
	}
	cfg := makeConfig(func(c *Config) {
		c.NumQubits = n
		c.SampleFraction = f64(frac)
		c.QBERThreshold = f64(threshold)
	})

	at := estimateQBER(cfg, NewSource(seed), build(11))
	above := estimateQBER(cfg, NewSource(seed), build(12))
	t.Logf("[boundary] at-threshold qber=%.4f abort=%v; above qber=%.4f abort=%v",
		at.qber, at.abort, above.qber, above.abort)

	if at.qber != threshold {
		t.Fatalf("expected qber exactly %.2f, got %.4f", threshold, at.qber)
	}
	if at.abort {
		t.Fatal("qber == threshold must pass (abort only when strictly greater)")
	}
	if !above.abort {
		t.Fatal("qber > threshold must abort")
	}
	// 抽样确定性：同 seed 重复估计结果一致。
	again := estimateQBER(cfg, NewSource(seed), build(12))
	if again.qber != above.qber || again.sampleSize != above.sampleSize {
		t.Fatal("sampling must be deterministic for the same seed")
	}
}

// TestErrorCorrectsActualErrors 直接验证误码纠正确实修复了 Bob 侧错误。
func TestErrorCorrectsActualErrors(t *testing.T) {
	const n = 5000
	src := NewSource(99)
	alice := make([]int, n)
	for i := range alice {
		alice[i] = src.Bit()
	}
	bob := make([]int, n)
	copy(bob, alice)
	// 注入约 3% 的错误。
	errSrc := NewSource(7)
	injected := 0
	for i := range bob {
		if errSrc.Float64() < 0.03 {
			bob[i] ^= 1
			injected++
		}
	}
	corrected, leak := errorCorrect(makeConfig(nil), NewSource(5), 0.03, alice, bob)
	match := verifyKey(alice, corrected)
	t.Logf("[ec] n=%d injected=%d leak=%d verified=%v", n, injected, leak, match)
	if !match {
		t.Fatal("error correction failed to align keys")
	}
	if leak == 0 {
		t.Fatal("expected positive leakage")
	}
}

// TestDeterminismAcrossRuns 固定 seed 重复运行，结果（含密钥与账目）完全一致。
func TestDeterminismAcrossRuns(t *testing.T) {
	cfg := makeConfig(func(c *Config) {
		c.ChannelLossDB = f64(3)
		c.DetectorEfficiency = f64(0.5)
		c.DarkCountProb = f64(0.05)
	})
	first, err := mustRun(t, cfg)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	for i := 0; i < 5; i++ {
		res, err := mustRun(t, cfg)
		if err != nil {
			t.Fatalf("run %d failed: %v", i+2, err)
		}
		if !bytes.Equal(first.Key, res.Key) || first.Ledger != res.Ledger {
			t.Fatalf("run %d diverged: %+v vs %+v", i+2, res.Ledger, first.Ledger)
		}
	}
	t.Logf("[determinism] 6 次运行结果完全一致，key[:8]=%x", first.Key[:8])
}

// Example 演示一次完整会话。
func Example() {
	cfg := Config{NumQubits: 20000}
	sess, err := NewSession(cfg)
	if err != nil {
		panic(err)
	}
	res, err := sess.Run()
	if err != nil {
		panic(err)
	}
	fmt.Printf("final key bits: %d, conserved: %v\n", res.Ledger.Final, res.Ledger.Conserved())
	// Output:
	// final key bits: 7889, conserved: true
}
