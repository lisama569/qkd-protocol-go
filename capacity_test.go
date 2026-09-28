package qkd

import (
	"errors"
	"reflect"
	"testing"
)

// 边界一致性：对多组参数与多个目标，预估可行 ⇔ 真实执行成功，
// 且计划输出长度等于真实密钥长度；预估失败类别与执行审计类别一致。
func TestCapacityMatchesExecution(t *testing.T) {
	configs := []Config{
		baseConfig(),
		func() Config {
			c := baseConfig()
			c.NumPhotons = 120 // 材料紧张
			return c
		}(),
		func() Config {
			c := baseConfig()
			c.Eavesdrop = true
			return c
		}(),
		func() Config {
			c := baseConfig()
			c.ChannelLossDB = 60
			c.DarkCountProb = 1e-12
			return c
		}(),
	}
	targets := []int{0, 1, 8, 16, 32, 64, 256}

	for ci, base := range configs {
		for _, target := range targets {
			est := EstimateCapacity(base, target)

			runCfg := base
			runCfg.RequestedKeyBytes = target
			res, err := Run(runCfg)
			audit := AuditOf(runCfg, res, err)

			if est.Feasible != (err == nil) {
				t.Fatalf("cfg%d target=%d: Feasible=%v but Run err=%v (cat=%s)",
					ci, target, est.Feasible, err, est.Category)
			}
			if err == nil {
				if est.PlannedOutBits != len(res.Key)*8 {
					t.Fatalf("cfg%d target=%d: planned %d != actual key bits %d",
						ci, target, est.PlannedOutBits, len(res.Key)*8)
				}
				if est.MaxKeyBytes < len(res.Key) {
					t.Fatalf("cfg%d target=%d: max %d < actual %d",
						ci, target, est.MaxKeyBytes, len(res.Key))
				}
			} else {
				// 失败类别必须与执行审计口径一致（low_yield 是预估对
				// insufficient_material 的细化：仍可出少量钥但不够目标）。
				if est.Category == CategoryLowYield {
					if audit.Category != CategoryInsufficientMaterial {
						t.Fatalf("cfg%d target=%d: low_yield must correspond to run insufficient, got %s",
							ci, target, audit.Category)
					}
				} else if est.Category != audit.Category {
					t.Fatalf("cfg%d target=%d: est cat %s != run cat %s",
						ci, target, est.Category, audit.Category)
				}
			}
		}
	}
}

// 低收益：目标达不到但确实能出 >=1 字节密钥，必须单独成类，
// 既不能笼统归为参数矛盾，也不能自动缩短目标。
func TestCapacityLowYieldIsDistinct(t *testing.T) {
	// 选一个材料够出一点、但远不够 32 字节目标的配置。
	cfg := baseConfig()
	cfg.NumPhotons = 1000
	cfg.RequestedKeyBytes = 0
	res, err := Run(cfg)
	if err != nil {
		t.Fatalf("need a config that can emit some key, got %v", err)
	}
	if len(res.Key) < 1 {
		t.Fatalf("fixture should yield >=1 byte")
	}
	target := len(res.Key) + 16 // 高于实际可得

	est := EstimateCapacity(cfg, target)
	t.Logf("low-yield: avail=%d max=%d target=%d shortfall=%d cat=%s",
		est.AvailableBits, est.MaxKeyBytes, target, est.ShortfallBits, est.Category)

	if est.Feasible {
		t.Fatalf("target beyond material must not be feasible")
	}
	if !est.KeyPossible || est.MaxKeyBytes < 1 {
		t.Fatalf("expected key still possible, got possible=%v max=%d",
			est.KeyPossible, est.MaxKeyBytes)
	}
	if est.Category != CategoryLowYield {
		t.Fatalf("expected category low_yield, got %s", est.Category)
	}
	if est.TargetKeyBytes != target {
		t.Fatalf("target must be preserved verbatim, got %d", est.TargetKeyBytes)
	}
	if est.ShortfallBits <= 0 {
		t.Fatalf("expected positive shortfall, got %d", est.ShortfallBits)
	}

	// 同参数真实执行目标长度必须显式失败（不静默降级、不缩短）。
	runCfg := cfg
	runCfg.RequestedKeyBytes = target
	if _, rerr := Run(runCfg); !errors.Is(rerr, ErrInsufficientKeyMaterial) {
		t.Fatalf("real run must fail insufficient, got %v", rerr)
	}
	// 但不指定目标时真实执行确实能出钥，证明它不是参数矛盾。
	if _, rerr := Run(cfg); rerr != nil {
		t.Fatalf("real run without target should succeed, got %v", rerr)
	}
}

// 预估结构在类型层面不得包含任何比特序列字段。
func TestCapacityNoBitMaterial(t *testing.T) {
	sensitive := map[string]bool{"Key": true, "Measured": true, "Bit": true}
	var bad []string
	walkFields(reflect.TypeOf(CapacityEstimate{}), nil, &bad, sensitive)
	if len(bad) != 0 {
		t.Fatalf("CapacityEstimate leaks sensitive fields: %v", bad)
	}
}

// 非法目标长度必须按参数不可行处理，且不改变目标值。
func TestCapacityNegativeTarget(t *testing.T) {
	est := EstimateCapacity(baseConfig(), -1)
	if est.Category != CategoryInvalidConfig || est.Feasible {
		t.Fatalf("negative target must be invalid_config, got %+v", est)
	}
	if est.TargetKeyBytes != -1 {
		t.Fatalf("target must not be rewritten")
	}
}

// 主要公开消耗必须被如实报告（成功场景计数非零且自洽）。
func TestCapacityReportsPublicCost(t *testing.T) {
	est := EstimateCapacity(baseConfig(), 16)
	c := est.Cost
	t.Logf("cost: %+v avail=%d", c, est.AvailableBits)
	if c.Prepared == 0 || c.Sifted == 0 || c.AfterSample == 0 {
		t.Fatalf("expected non-trivial public cost, got %+v", c)
	}
	if c.Sifted != c.Sampled+c.AfterSample {
		t.Fatalf("sifted conservation broken: %d != %d+%d",
			c.Sifted, c.Sampled, c.AfterSample)
	}
	if c.LeakedEC < 0 || c.LeakedEst < 0 || c.Margin <= 0 {
		t.Fatalf("unexpected cost values: %+v", c)
	}
}
