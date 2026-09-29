package qkd

import (
	"testing"
)

// 预估值 QBERThreshold 必须始终等于“本次真正生效的判定阈值”，
// 即 Params 摘要中的同一值：成功、窃听终止、无信号等任何结局都一致，
// 绝不跟着实测 QBER 变；参数非法或流程很早结束时也不得变成 0。
func TestEstimateThresholdAlwaysEffective(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		target int
	}{
		{"feasible", baseConfig(), 16},
		{"target-zero-max-length", withMut(baseConfig(), func(c *Config) { c.RequestedKeyBytes = 0 }), 0},
		{"target-too-large", withMut(baseConfig(), func(c *Config) { c.RequestedKeyBytes = 100000 }), 100000},
		{"short-of-target", baseConfig(), 64},
		{"aborted-insecure", withMut(baseConfig(), func(c *Config) { c.Eavesdrop = true }), 16},
		{"no-signal-early-end", withMut(baseConfig(), func(c *Config) {
			c.NumPhotons = 100
			c.ChannelLossDB = 40
			c.DarkCountProb = 1e-12
			c.RequestedKeyBytes = 0
		}), 0},
		{"invalid-config", Config{NumPhotons: 0, DetectorEfficiency: 0.9, Seed: 1}, 16},
		{"exhausted-accounting", withMut(baseConfig(), func(c *Config) {
			c.NumPhotons = 40
			c.RequestedKeyBytes = 0
		}), 0},
		{"sampled-out-at-qber-stage", withMut(baseConfig(), func(c *Config) {
			c.NumPhotons = 200
			c.SampleFraction = 0.999
			c.RequestedKeyBytes = 0
		}), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := EstimateCapacity(tc.cfg, tc.target)
			if err != nil {
				t.Fatalf("EstimateCapacity: %v", err)
			}
			want := tc.cfg.withDefaults().QBERThreshold // 本次真正生效（含缺省补全）的阈值
			if e.Params.QBERThreshold != want {
				t.Fatalf("param summary threshold=%.4f want effective %.4f", e.Params.QBERThreshold, want)
			}
			if e.QBERThreshold != want {
				t.Fatalf("estimate threshold=%.4f want effective %.4f (qber=%.4f verdict=%s)",
					e.QBERThreshold, want, e.QBER, e.Verdict)
			}
			if e.QBERThreshold == 0 {
				t.Fatalf("threshold must never be reported as 0, even on %s", e.Verdict)
			}
			t.Logf("%s: verdict=%s stage=%s qber=%.4f threshold=%.4f",
				tc.name, e.Verdict, e.Stage, e.QBER, e.QBERThreshold)
		})
	}
}

// 显式配置非缺省阈值时，预估展示的阈值同样必须采用该生效阈值（而非缺省值）。
func TestEstimateThresholdHonorsCustomValue(t *testing.T) {
	for _, threshold := range []float64{0.05, 0.2, 0.3} {
		c := baseConfig()
		c.QBERThreshold = threshold
		for _, eve := range []bool{false, true} {
			c2 := c
			c2.Eavesdrop = eve
			e, err := EstimateCapacity(c2, 16)
			if err != nil {
				t.Fatalf("threshold=%.2f eve=%v: %v", threshold, eve, err)
			}
			if e.QBERThreshold != threshold || e.Params.QBERThreshold != threshold {
				t.Fatalf("threshold=%.2f eve=%v: reported %.4f/%.4f",
					threshold, eve, e.QBERThreshold, e.Params.QBERThreshold)
			}
		}
	}
}

// 边界：目标为 0 表示尽量长，RequestedBits 必须为 0；目标过大时不得被静默缩短，
// RequestedBits 始终等于请求值（*8），且不可行结论不得承诺密钥比特。
func TestEstimateRequestedBitsBoundaries(t *testing.T) {
	e0, err := EstimateCapacity(baseConfig(), 0)
	if err != nil || e0.RequestedBits != 0 {
		t.Fatalf("target 0: requested=%d err=%v", e0.RequestedBits, err)
	}

	big := 1 << 20
	eb, err := EstimateCapacity(baseConfig(), big)
	if err != nil {
		t.Fatalf("large target: %v", err)
	}
	if eb.RequestedBits != big*8 {
		t.Fatalf("requested bits shortened: got %d want %d", eb.RequestedBits, big*8)
	}
	if eb.Verdict == CapacityFeasible {
		t.Fatalf("target far beyond available material must not be feasible")
	}
	if eb.ExpectedKeyBits != 0 {
		t.Fatalf("non-feasible estimate promised %d key bits", eb.ExpectedKeyBits)
	}
	if eb.AvailableBits > 0 && eb.ByteAlignedBits > 0 {
		// 有更短钥可得时必须明确是“达不到目标”，而不是耗尽。
		if eb.Verdict != CapacityInsufficientForTarget {
			t.Fatalf("want insufficient_for_target, got %s", eb.Verdict)
		}
	}
}

func withMut(c Config, fn func(*Config)) Config {
	fn(&c)
	return c
}
