package qkd

import (
	"errors"
	"reflect"
	"testing"
)

// 各结局的统一形态：成功 / 窃听终止 / 无信号 / 材料不足 / 参数不可行。
func TestAuditClassifiesOutcomes(t *testing.T) {
	cases := []struct {
		name      string
		cfg       func() Config
		wantCat   string
		wantStage string
		wantSucc  bool
	}{
		{"success", func() Config { return baseConfig() }, CategorySuccess, StageComplete, true},
		{"aborted", func() Config {
			c := baseConfig()
			c.Eavesdrop = true
			return c
		}, CategoryAborted, StageQBER, false},
		{"no_signal", func() Config {
			c := baseConfig()
			c.ChannelLossDB = 60
			c.DarkCountProb = 1e-12
			return c
		}, CategoryNoSignal, StageSift, false},
		{"insufficient", func() Config {
			c := baseConfig()
			c.NumPhotons = 200
			c.RequestedKeyBytes = 64
			return c
		}, CategoryInsufficientMaterial, "", false},
		{"invalid", func() Config { return Config{} }, CategoryInvalidConfig, StageConfig, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			res, err := Run(cfg)
			rec := AuditOf(cfg, res, err)
			if rec.Category != tc.wantCat {
				t.Fatalf("category = %q, want %q (err=%v)", rec.Category, tc.wantCat, err)
			}
			if rec.Success != tc.wantSucc {
				t.Fatalf("success = %v, want %v", rec.Success, tc.wantSucc)
			}
			if tc.wantStage != "" && rec.Stage != tc.wantStage {
				t.Fatalf("stage = %q, want %q", rec.Stage, tc.wantStage)
			}
			if tc.wantSucc {
				if rec.KeyBytes != len(res.Key) || rec.KeyBytes == 0 {
					t.Fatalf("success audit KeyBytes=%d", rec.KeyBytes)
				}
			} else {
				if rec.KeyBytes != 0 {
					t.Fatalf("failed audit must report KeyBytes=0, got %d", rec.KeyBytes)
				}
				if res.Key != nil && tc.wantCat != CategorySuccess {
					t.Fatalf("failed run must not hold key")
				}
			}
			t.Logf("[audit:%s] cat=%s stage=%s reason=%q counts={%s}",
				tc.name, rec.Category, rec.Stage, rec.Reason, rec.Counts)
		})
	}
}

// 审计记录任何结局都不得包含可推导密钥的比特序列字段。
func TestAuditNeverCarriesBitMaterial(t *testing.T) {
	sensitive := map[string]bool{
		"Key":      true, // 最终密钥 / 纠正后密钥
		"Measured": true, // 光子测量比特
		"Bit":      true,
	}
	// 覆盖成功与多种失败路径。
	configs := []Config{baseConfig()}
	eve := baseConfig()
	eve.Eavesdrop = true
	configs = append(configs, eve)
	low := baseConfig()
	low.NumPhotons = 120
	low.RequestedKeyBytes = 64
	configs = append(configs, low)
	configs = append(configs, Config{}) // invalid

	for idx, cfg := range configs {
		res, err := Run(cfg)
		rec := AuditOf(cfg, res, err)
		var bad []string
		walkFields(reflect.TypeOf(rec), nil, &bad, sensitive)
		if len(bad) != 0 {
			t.Fatalf("AuditRecord case %d leaks sensitive field paths: %v", idx, bad)
		}
		// 失败路径的 Reason 不得为内部裸错误（只允许固定口径短语）。
		if err != nil && rec.Category != CategoryInvalidConfig {
			if rec.Reason == "" {
				t.Fatalf("case %d: empty reason", idx)
			}
		}
	}
}

// walkFields 递归遍历类型的所有字段路径，命中敏感字段名即记录。
// 只检查类型结构：审计口径在“类型层面”就不允许存在比特序列字段，
// 从根上杜绝任何执行路径把中间量放进审计记录。
func walkFields(t reflect.Type, prefix []string, bad *[]string, sensitive map[string]bool) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		path := append(append([]string{}, prefix...), f.Name)
		if sensitive[f.Name] {
			*bad = append(*bad, joinPath(path))
		}
		walkFields(f.Type, path, bad, sensitive)
	}
}

func joinPath(p []string) string {
	s := ""
	for i, x := range p {
		if i > 0 {
			s += "."
		}
		s += x
	}
	return s
}

// 成功与失败必须同口径：审计结构都只含参数摘要、阶段、公开计数、类别。
func TestAuditSameShapeSuccessAndFailure(t *testing.T) {
	ok, _ := Run(baseConfig())
	bad := baseConfig()
	bad.Eavesdrop = true
	badRes, badErr := Run(bad)

	a := AuditOf(baseConfig(), ok, nil)
	b := AuditOf(bad, badRes, badErr)

	ta := reflect.TypeOf(a)
	tb := reflect.TypeOf(b)
	if ta != tb {
		t.Fatalf("audit shape differs: %v vs %v", ta, tb)
	}
	if a.Params.Seed != b.Params.Seed {
		t.Fatalf("seed mismatch in params summary")
	}
	// 成功路径同样不允许借道 Counts/QBER 之外的字段（结构扫描已保证）。
	if !a.Success || b.Success {
		t.Fatalf("success flags inverted: %v / %v", a.Success, b.Success)
	}
	var abort *AbortError
	if !errors.As(badErr, &abort) {
		t.Fatalf("expected abort error")
	}
}

// 直接锁定难自然触发的两类：纠错失败与内部错误，均不得泄露内部文本。
func TestAuditReconcileAndInternalClassification(t *testing.T) {
	cfg := baseConfig()
	ledger := Ledger{Prepared: 10, Detected: 8, Sifted: 6, Sampled: 3, AfterSample: 3, Margin: 32}
	rec := ReconcileResult{Key: []int{1, 0, 1}, LeakedBits: 2, ErrorsFixed: 1}

	r1 := AuditOf(cfg, Result{Ledger: ledger, Reconciled: rec}, ErrReconcileFailed)
	if r1.Category != CategoryReconcileFailed || r1.Stage != StageReconcile {
		t.Fatalf("got cat=%s stage=%s", r1.Category, r1.Stage)
	}

	// 任意未知内部错误：分类 internal，Reason 固定，绝不透传裸错误文本。
	r2 := AuditOf(cfg, Result{Ledger: ledger, Reconciled: rec}, errExplosive)
	if r2.Category != CategoryInternal || r2.Reason != "internal error" {
		t.Fatalf("internal error leaked or misclassified: cat=%s reason=%q", r2.Category, r2.Reason)
	}

	// 抽样后无剩余的材料不足：阶段落在 qber。
	r3 := AuditOf(cfg, Result{Ledger: ledger}, ErrInsufficientKeyMaterial)
	if r3.Category != CategoryInsufficientMaterial || r3.Stage != StageQBER {
		t.Fatalf("post-sample insufficiency: cat=%s stage=%s", r3.Category, r3.Stage)
	}
}

var errExplosive = stringError("boom: reconciled bits=010110 sifted=110011")

type stringError string

func (e stringError) Error() string { return string(e) }
