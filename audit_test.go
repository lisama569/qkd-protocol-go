package qkd

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// 审计结构允许出现的全部 JSON 字段（白名单）。
// 该测试是结构性保证：任何新增字段若不在白名单（尤其比特序列/密钥类字段），
// 必须显式评审后才能加入，防止敏感中间量借失败路径混入审计。
var allowedAuditFields = map[string]bool{
	// Audit
	"Params": true, "Stage": true, "Outcome": true, "Detail": true, "Reason": true,
	"Counts": true, "QBER": true, "QBERThreshold": true, "KeyBits": true,
	// ParamSummary
	"NumPhotons": true, "ChannelLossDB": true, "DetectorEfficiency": true,
	"DarkCountProb": true, "Eavesdrop": true, "SampleFraction": true,
	"QBERThreshold ": true, "SecurityMargin": true, "RequestedKeyBytes": true, "Seed": true,
	// PublicCounts
	"Prepared": true, "Detected": true, "Sifted": true, "Sampled": true,
	"AfterSample": true, "LeakedEC": true, "LeakedEst": true, "Margin": true,
	"Final": true, "Discarded": true,
}

func TestAuditStructExposesOnlyPublicFields(t *testing.T) {
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			seen[f.Name] = true
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type)
			}
			// 禁止任何 []byte / []int 等可承载比特序列的字段出现在审计结构中。
			if f.Type.Kind() == reflect.Slice {
				t.Fatalf("audit field %s.%s is a slice; audits must not carry bit/key sequences",
					typ.Name(), f.Name)
			}
		}
	}
	walk(reflect.TypeOf(Audit{}))
	for name := range seen {
		if name == "QBERThreshold" {
			continue // 同时出现在 Audit 与 ParamSummary，合法
		}
		if !allowedAuditFields[name] {
			t.Fatalf("audit struct contains non-whitelisted field %q", name)
		}
	}
}

// 把审计序列化，断言成功密钥的十六进制/二进制内容不出现在任何对外文本中。
func assertNoKeyLeak(t *testing.T, a Audit, key []byte) {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	text := string(raw) + a.String()
	if len(key) > 0 {
		hx := hex.EncodeToString(key)
		if strings.Contains(text, hx) {
			t.Fatalf("audit leaks final key: %s", hx)
		}
		if strings.Contains(text, strings.TrimLeft(hx, "0")) && len(key) >= 4 {
			t.Fatalf("audit text contains key fragment")
		}
	}
	for _, banned := range []string{"reconciled", "sifted bits", "corrected"} {
		if strings.Contains(strings.ToLower(text), banned) {
			t.Fatalf("audit text mentions sensitive material %q", banned)
		}
	}
}

// 覆盖成功与各失败路径：类别/阶段正确，失败无密钥，全部审计文本不含密钥材料。
func TestAuditOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		outcome string
		detail  string
		stage   string
	}{
		{"success", nil, OutcomeSuccess, "", StagePrivacyAmplify},
		{"abort", func(c *Config) { c.Eavesdrop = true }, OutcomeAbortedInsecure, "", StageQBEREstimate},
		{"no-signal", func(c *Config) {
			c.NumPhotons = 100
			c.ChannelLossDB = 40
			c.DarkCountProb = 1e-12
			c.RequestedKeyBytes = 0
		}, OutcomeNoSignal, "", StageSift},
		{"exhausted", func(c *Config) { c.NumPhotons = 40; c.RequestedKeyBytes = 0 },
			OutcomeInsufficient, DetailExhausted, StageAccounting},
		{"low-yield", func(c *Config) { c.NumPhotons = 640; c.RequestedKeyBytes = 0 },
			OutcomeInsufficient, DetailLowYield, StageAccounting},
		{"short-of-target", func(c *Config) { c.RequestedKeyBytes = 64 },
			OutcomeInsufficient, DetailInsufficientForTarget, StageAccounting},
		{"invalid", func(c *Config) { *c = Config{Seed: 1} },
			OutcomeInvalidConfig, "", StageValidate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := preset(1, tc.mutate)
			res, err := Run(cfg)
			a := NewAudit(cfg, res, err)
			t.Logf("audit: %s", a)
			if a.Outcome != tc.outcome || a.Detail != tc.detail || a.Stage != tc.stage {
				t.Fatalf("got outcome=%s detail=%q stage=%s; want %s/%q/%s",
					a.Outcome, a.Detail, a.Stage, tc.outcome, tc.detail, tc.stage)
			}
			if tc.outcome == OutcomeSuccess {
				if a.KeyBits != len(res.Key)*8 || a.KeyBits == 0 {
					t.Fatalf("success audit KeyBits=%d key=%dB", a.KeyBits, len(res.Key))
				}
				if a.Counts.Final != a.KeyBits {
					t.Fatalf("final count %d != KeyBits %d", a.Counts.Final, a.KeyBits)
				}
			} else if a.KeyBits != 0 {
				t.Fatalf("failed audit must report KeyBits=0, got %d", a.KeyBits)
			}
			// 成功与失败共用同一结构、同一公开口径：两者文本都不能含密钥内容。
			assertNoKeyLeak(t, a, res.Key)
			// 参数摘要与公开计数必须始终存在（失败路径同样可得）。
			if a.Params.NumPhotons != cfg.withDefaults().NumPhotons {
				t.Fatalf("param summary missing on %s path", tc.name)
			}
		})
	}
}

// 无信号路径也必须保留公开的制备/参数信息（用于审计），且不含密钥。
func TestAuditNoSignalKeepsPreparedCount(t *testing.T) {
	cfg := preset(1, func(c *Config) {
		c.NumPhotons = 100
		c.ChannelLossDB = 40
		c.DarkCountProb = 1e-12
		c.RequestedKeyBytes = 0
	})
	res, err := Run(cfg)
	a := NewAudit(cfg, res, err)
	if a.Outcome != OutcomeNoSignal || a.Counts.Prepared != 100 {
		t.Fatalf("expected no_signal with prepared=100, got %s counts=%+v", a.Outcome, a.Counts)
	}
	assertNoKeyLeak(t, a, res.Key)
}
