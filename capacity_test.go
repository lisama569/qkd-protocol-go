package qkd

import (
	"errors"
	"reflect"
	"testing"
)

// 预估结论 → 对应 Run 的审计粗类别（feasible 对应 success）。
func verdictOutcome(verdict string) string {
	switch verdict {
	case CapacityFeasible:
		return OutcomeSuccess
	case CapacityInvalidConfig:
		return OutcomeInvalidConfig
	case CapacityNoSignal:
		return OutcomeNoSignal
	case CapacityAbortedInsecure:
		return OutcomeAbortedInsecure
	case CapacityReconcileFailed:
		return OutcomeReconcileFailed
	case CapacityExhausted, CapacityLowYield, CapacityInsufficientForTarget:
		return OutcomeInsufficient
	default:
		return "unknown"
	}
}

// 预估成功 ⇒ Run 成功且密钥长度==ExpectedKeyBits；预估失败 ⇒ Run 以对应类别失败。
func assertEstimateMatchesRun(t *testing.T, cfg Config, target int) {
	t.Helper()
	e, err := EstimateCapacity(cfg, target)
	if err != nil {
		t.Fatalf("EstimateCapacity target=%d: %v", target, err)
	}
	run := cfg
	run.RequestedKeyBytes = target
	res, rerr := Run(run)
	audit := NewAudit(run, res, rerr)

	if got := verdictOutcome(e.Verdict); got != audit.Outcome {
		t.Fatalf("verdict=%s but run outcome=%s (target=%d cfg=%+v)",
			e.Verdict, audit.Outcome, target, cfg)
	}
	if e.Verdict == CapacityFeasible {
		if rerr != nil {
			t.Fatalf("feasible estimate but run failed: %v", rerr)
		}
		if len(res.Key)*8 != e.ExpectedKeyBits {
			t.Fatalf("expected %d bits, run produced %d", e.ExpectedKeyBits, len(res.Key)*8)
		}
		if e.ExpectedKeyBits < target*8 && target > 0 {
			t.Fatalf("target %d bytes silently shortened to %d bits", target, e.ExpectedKeyBits)
		}
	} else {
		if rerr == nil {
			t.Fatalf("verdict=%s but run produced a key", e.Verdict)
		}
		if e.ExpectedKeyBits != 0 {
			t.Fatalf("non-feasible verdict must not promise key bits, got %d", e.ExpectedKeyBits)
		}
		// 材料类结论细分必须与真实审计 Detail 完全一致。
		if audit.Outcome == OutcomeInsufficient {
			wantDetail := map[string]string{
				CapacityExhausted:             DetailExhausted,
				CapacityLowYield:              DetailLowYield,
				CapacityInsufficientForTarget: DetailInsufficientForTarget,
			}[e.Verdict]
			if audit.Detail != wantDetail {
				t.Fatalf("verdict=%s detail mismatch: run detail=%s want %s",
					e.Verdict, audit.Detail, wantDetail)
			}
		}
	}
}

// 结构性保证：CapacityEstimate 不承载任何比特序列/密钥切片。
func TestCapacityEstimateHasNoSensitiveSlices(t *testing.T) {
	typ := reflect.TypeOf(CapacityEstimate{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.IsExported() && f.Type.Kind() == reflect.Slice {
			t.Fatalf("CapacityEstimate.%s is a slice; estimate must not carry bit/key material", f.Name)
		}
	}
}

// 固定夹具的各结论显式断言与公开消耗字段。
func TestEstimateCapacityFixedScenarios(t *testing.T) {
	c := baseConfig()

	// 成功：目标 16 字节。
	e, err := EstimateCapacity(c, 16)
	if err != nil || e.Verdict != CapacityFeasible || e.ExpectedKeyBits != 128 {
		t.Fatalf("feasible case: verdict=%s expected=%d err=%v", e.Verdict, e.ExpectedKeyBits, err)
	}
	t.Logf("feasible: %s", e.Reason)
	if e.Counts.Sampled <= 0 || e.Counts.LeakedEC <= 0 || e.Counts.Margin != c.SecurityMargin {
		t.Fatalf("public consumption missing: %+v", e.Counts)
	}

	// 达不到目标：能出更短钥，但不自动缩短。
	e2, _ := EstimateCapacity(c, 64)
	if e2.Verdict != CapacityInsufficientForTarget || e2.AvailableBits <= 0 {
		t.Fatalf("expected insufficient_for_target, got %s avail=%d", e2.Verdict, e2.AvailableBits)
	}
	t.Logf("short-of-target: %s", e2.Reason)

	// 同一参数在目标 0（尽量长）下应可行，证明“有材料但达不到目标”不是参数矛盾。
	e3, _ := EstimateCapacity(c, 0)
	if e3.Verdict != CapacityFeasible || e3.ExpectedKeyBits < 8 {
		t.Fatalf("max-length mode should be feasible, got %s expected=%d", e3.Verdict, e3.ExpectedKeyBits)
	}

	// 低收益：有正材料但不足 1 字节，不与“耗尽/矛盾”混淆。
	low := c
	low.NumPhotons = 640
	low.RequestedKeyBytes = 0
	e4, _ := EstimateCapacity(low, 0)
	if e4.Verdict != CapacityLowYield || e4.AvailableBits <= 0 || e4.ByteAlignedBits != 0 {
		t.Fatalf("expected low_yield with positive material, got %s avail=%d aligned=%d",
			e4.Verdict, e4.AvailableBits, e4.ByteAlignedBits)
	}
	t.Logf("low-yield: %s", e4.Reason)

	// 耗尽：可用比特 <=0，明确不可能出钥。
	exh := c
	exh.NumPhotons = 40
	exh.RequestedKeyBytes = 0
	e5, _ := EstimateCapacity(exh, 0)
	if e5.Verdict != CapacityExhausted || e5.AvailableBits > 0 {
		t.Fatalf("expected exhausted, got %s avail=%d", e5.Verdict, e5.AvailableBits)
	}

	// 窃听终止。
	eve := c
	eve.Eavesdrop = true
	e6, _ := EstimateCapacity(eve, 16)
	if e6.Verdict != CapacityAbortedInsecure {
		t.Fatalf("expected aborted_insecure, got %s", e6.Verdict)
	}

	// 无信号。
	ns := c
	ns.NumPhotons = 100
	ns.ChannelLossDB = 40
	ns.DarkCountProb = 1e-12
	e7, _ := EstimateCapacity(ns, 0)
	if e7.Verdict != CapacityNoSignal {
		t.Fatalf("expected no_signal, got %s", e7.Verdict)
	}

	// 参数不可行（非法配置）。
	bad := Config{NumPhotons: 0, DetectorEfficiency: 0.9}
	if e8, err := EstimateCapacity(bad, 16); err != nil || e8.Verdict != CapacityInvalidConfig {
		t.Fatalf("expected invalid_config, got verdict=%s err=%v", e8.Verdict, err)
	}

	// 负目标显式报错，不静默当 0 处理。
	if _, err := EstimateCapacity(c, -1); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("expected ErrInvalidTarget, got %v", err)
	}
}

// 预估不得修改调用方配置（目标只作用于内部克隆）。
func TestEstimateCapacityDoesNotMutateConfig(t *testing.T) {
	cfg := baseConfig()
	before := cfg
	_, _ = EstimateCapacity(cfg, 64)
	if !reflect.DeepEqual(cfg, before) {
		t.Fatalf("EstimateCapacity mutated caller config: %+v -> %+v", before, cfg)
	}
}

// 穷举式一致性：跨多种光子数/损耗/窃听/目标，预估与真实执行边界不得自相矛盾。
func TestEstimateMatchesRunSweep(t *testing.T) {
	photons := []int{40, 120, 300, 640, 900, 2000, 4000}
	losses := []float64{5, 15, 25, 35}
	targets := []int{0, 8, 16, 64}
	checked := 0
	for _, n := range photons {
		for _, loss := range losses {
			for _, eve := range []bool{false, true} {
				for _, target := range targets {
					cfg := baseConfig()
					cfg.NumPhotons = n
					cfg.ChannelLossDB = loss
					cfg.Eavesdrop = eve
					cfg.RequestedKeyBytes = target
					// 高损耗下放宽暗计数到合法且不触发矛盾判据。
					if loss >= 25 {
						cfg.DarkCountProb = 1e-9
					}
					assertEstimateMatchesRun(t, cfg, target)
					checked++
				}
			}
		}
	}
	t.Logf("sweep verified %d (cfg,target) combinations", checked)
}

// 同种子下预估的公开计数与真实执行成功账目的公开计数一致。
func TestEstimateCountsMatchSuccessfulRun(t *testing.T) {
	cfg := baseConfig()
	e, _ := EstimateCapacity(cfg, 16)
	res, err := Run(cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// 预估不做隐私放大，故 Final/Discarded 为 0；其余出钥前公开计数必须逐项一致。
	pre := func(c PublicCounts) PublicCounts { c.Final, c.Discarded = 0, 0; return c }
	if pre(e.Counts) != pre(ledgerCounts(res.Ledger)) {
		t.Fatalf("pre-output counts diverge: estimate=%+v run=%+v", e.Counts, ledgerCounts(res.Ledger))
	}
	if res.Ledger.Final != e.ExpectedKeyBits {
		t.Fatalf("run Final=%d != estimate ExpectedKeyBits=%d", res.Ledger.Final, e.ExpectedKeyBits)
	}
	if e.QBER != res.QBER.QBER {
		t.Fatalf("qber diverge: estimate=%.4f run=%.4f", e.QBER, res.QBER.QBER)
	}
}
