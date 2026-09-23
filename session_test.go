package qkd

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func baseConfig() Config {
	return Config{
		NumPhotons:         4000,
		ChannelLossDB:      5,
		DetectorEfficiency: 0.9,
		DarkCountProb:      0.0001,
		SampleFraction:     0.5,
		QBERThreshold:      0.11,
		SecurityMargin:     32,
		RequestedKeyBytes:  16,
		Seed:               1,
	}
}

func logResult(t *testing.T, name string, cfg Config, res Result, err error) {
	t.Helper()
	t.Logf("[%s] 输入参数=%+v", name, cfg)
	t.Logf("[%s] 账目: %s", name, res.Ledger)
	t.Logf("[%s] 误码估计: 抽样=%d 错误=%d QBER=%.4f 阈值=%.4f secure=%v",
		name, res.QBER.SampleSize, res.QBER.Errors, res.QBER.QBER, res.QBER.Threshold, res.QBER.Secure)
	t.Logf("[%s] 纠错: 固定=%d 泄漏=%d; 判定依据: err=%v",
		name, res.Reconciled.ErrorsFixed, res.Reconciled.LeakedBits, err)
}

// 场景 1：无窃听 → 成功输出密钥，账目守恒。
func TestRunNoEavesdrop(t *testing.T) {
	cfg := baseConfig()
	res, err := Run(cfg)
	logResult(t, "no-eve", cfg, res, err)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(res.Key) != 16 {
		t.Fatalf("expected 16-byte key, got %d", len(res.Key))
	}
	if res.QBER.QBER > 0.02 {
		t.Fatalf("expected near-zero QBER without eavesdrop, got %.4f", res.QBER.QBER)
	}
	if err := res.Ledger.Check(); err != nil {
		t.Fatalf("ledger conservation: %v", err)
	}
}

// 场景 2：窃听 → QBER 显著升高，会话终止，无密钥输出。
func TestRunEavesdropAbort(t *testing.T) {
	cfg := baseConfig()
	cfg.Eavesdrop = true
	res, err := Run(cfg)
	logResult(t, "eve", cfg, res, err)
	var abort *AbortError
	if !errors.As(err, &abort) {
		t.Fatalf("expected *AbortError, got %v", err)
	}
	if res.QBER.QBER <= cfg.QBERThreshold {
		t.Fatalf("expected QBER above threshold, got %.4f", res.QBER.QBER)
	}
	if res.Key != nil {
		t.Fatalf("aborted session must not leak key material")
	}
}

// 场景 3：高损耗 → 探测极少，要么材料不足要么无信号，均不得产生密钥。
func TestRunHighLoss(t *testing.T) {
	cfg := baseConfig()
	cfg.ChannelLossDB = 25
	cfg.DarkCountProb = 1e-9 // 避免与暗计数矛盾判据冲突
	res, err := Run(cfg)
	logResult(t, "high-loss", cfg, res, err)
	if err == nil {
		t.Fatalf("expected failure under 25dB loss, got key of %d bytes", len(res.Key))
	}
	if res.Key != nil {
		t.Fatalf("failed session must not output key")
	}
}

// 场景 4：材料不足 → 请求超过可用量，显式拒绝且账目清楚。
func TestRunInsufficientMaterial(t *testing.T) {
	cfg := baseConfig()
	cfg.NumPhotons = 200
	cfg.RequestedKeyBytes = 64
	res, err := Run(cfg)
	logResult(t, "insufficient", cfg, res, err)
	if !errors.Is(err, ErrInsufficientKeyMaterial) {
		t.Fatalf("expected ErrInsufficientKeyMaterial, got %v", err)
	}
	if res.Key != nil {
		t.Fatalf("must not truncate/pad: no key expected")
	}
	if got := res.Ledger.FinalKeyLen(); got > 0 {
		t.Fatalf("expected non-positive available bits, got %d", got)
	}
}

// 场景 5：固定种子重复运行完全一致（密钥、QBER、账目全部相同）。
func TestDeterministicSameSeed(t *testing.T) {
	for _, seed := range []int64{1, 2, 99} {
		cfg := baseConfig()
		cfg.Seed = seed
		r1, err1 := Run(cfg)
		r2, err2 := Run(cfg)
		logResult(t, fmt.Sprintf("seed=%d", seed), cfg, r1, err1)
		if (err1 == nil) != (err2 == nil) || fmt.Sprint(err1) != fmt.Sprint(err2) {
			t.Fatalf("seed %d: error mismatch %v vs %v", seed, err1, err2)
		}
		if err1 != nil {
			continue
		}
		if fmt.Sprintf("%x", r1.Key) != fmt.Sprintf("%x", r2.Key) {
			t.Fatalf("seed %d: key differs across runs", seed)
		}
		if r1.Ledger != r2.Ledger || r1.QBER != r2.QBER {
			t.Fatalf("seed %d: ledger/qber differs across runs", seed)
		}
	}
}

// 场景 6：多会话并行 —— 同种子结果一致，不同种子互不干扰。
func TestConcurrentSessions(t *testing.T) {
	const workers = 16
	var wg sync.WaitGroup
	results := make([]Result, workers)
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			cfg := baseConfig()
			cfg.Seed = int64(w%2 + 1) // 只使用种子 1、2
			results[w], errs[w] = Run(cfg)
		}(w)
	}
	wg.Wait()
	ref := make(map[int64]Result)
	for w := 0; w < workers; w++ {
		if errs[w] != nil {
			t.Fatalf("worker %d: %v", w, errs[w])
		}
		seed := int64(w%2 + 1)
		if want, ok := ref[seed]; ok {
			if fmt.Sprintf("%x", want.Key) != fmt.Sprintf("%x", results[w].Key) {
				t.Fatalf("worker %d: same seed %d diverged under concurrency", w, seed)
			}
		} else {
			ref[seed] = results[w]
		}
	}
	if len(ref) != 2 {
		t.Fatalf("expected 2 distinct seed results, got %d", len(ref))
	}
}

// 临界 QBER 行为：QBER == 阈值判为安全（含），超过即终止。
func TestThresholdBoundary(t *testing.T) {
	alice := []int{0, 1, 0, 1, 0, 1, 0, 1}
	bob := []int{0, 1, 0, 1, 0, 1, 0, 1}
	est, rem := EstimateQBER(alice, bob, len(alice), NewSource(1), 0.11)
	if !est.Secure || len(rem) != 0 {
		t.Fatalf("QBER=0 must be secure, got %+v", est)
	}
	bob2 := []int{0, 1, 0, 1, 0, 1, 0, 0} // 1/8 = 0.125 > 0.11
	est2, _ := EstimateQBER(alice, bob2, len(alice), NewSource(1), 0.11)
	t.Logf("临界判定: %d/%d = %.4f vs 0.11, secure=%v", est2.Errors, est2.SampleSize, est2.QBER, est2.Secure)
	if est2.Secure {
		t.Fatalf("QBER 0.125 must be insecure")
	}
}
