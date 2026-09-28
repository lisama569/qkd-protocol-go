package qkd

import (
	"fmt"
	"testing"
)

func batchFixture() []BatchItem {
	mk := func(name string, mutate func(*Config)) BatchItem {
		c := baseConfig()
		mutate(&c)
		return BatchItem{Name: name, Config: c}
	}
	return []BatchItem{
		mk("ok", func(c *Config) { c.Seed = 1 }),
		mk("eve", func(c *Config) { c.Seed = 2; c.Eavesdrop = true }),
		mk("high-loss", func(c *Config) {
			c.Seed = 3
			c.ChannelLossDB = 60
			c.DarkCountProb = 1e-12
		}),
		mk("insufficient", func(c *Config) {
			c.Seed = 4
			c.NumPhotons = 150
			c.RequestedKeyBytes = 64
		}),
		mk("invalid", func(c *Config) { *c = Config{} }),
		mk("ok2", func(c *Config) { c.Seed = 5 }),
	}
}

// 不同并发度（含顺序）下，每个固定下标的组结果必须逐项一致。
func TestRunBatchConcurrencyInvariant(t *testing.T) {
	items := batchFixture()
	levels := []int{1, 2, 4, 8, 100}

	baseline := RunBatch(items, BatchOptions{Concurrency: levels[0]})
	if len(baseline) != len(items) {
		t.Fatalf("result length %d != items %d", len(baseline), len(items))
	}

	for _, conc := range levels[1:] {
		got := RunBatch(items, BatchOptions{Concurrency: conc})
		for i := range items {
			assertGroupEqual(t, fmt.Sprintf("conc=%d idx=%d", conc, i), baseline[i], got[i])
		}
	}
}

// 调整分组顺序后，按组标识（Name/参数）匹配，结果仍逐项一致，
// 且返回结果严格按下标对齐输入顺序。
func TestRunBatchOrderInvariant(t *testing.T) {
	items := batchFixture()
	original := RunBatch(items, BatchOptions{Concurrency: 4})

	reordered := []BatchItem{items[4], items[1], items[5], items[0], items[3], items[2]}
	got := RunBatch(reordered, BatchOptions{Concurrency: 3})

	// 下标对齐：第 k 个结果必须对应第 k 个输入。
	for k, item := range reordered {
		if got[k].Name != item.Name {
			t.Fatalf("alignment broken at %d: got %s want %s", k, got[k].Name, item.Name)
		}
	}

	// 按 Name 匹配原始结果，逐项比较。
	byName := map[string]GroupResult{}
	for _, g := range original {
		byName[g.Name] = g
	}
	for _, g := range got {
		want, ok := byName[g.Name]
		if !ok {
			t.Fatalf("missing baseline for %s", g.Name)
		}
		assertGroupEqual(t, "reorder:"+g.Name, want, g)
	}
}

// 同种子两组并存于同一批次时结果必须与独立 Run 一致，证明无跨组串扰。
func TestRunBatchIsolation(t *testing.T) {
	items := []BatchItem{
		{Name: "a", Config: seededCfg(7)},
		{Name: "b", Config: seededCfg(8)},
		{Name: "a2", Config: seededCfg(7)}, // 与 a 同种子、不同位置
	}
	groups := RunBatch(items, BatchOptions{Concurrency: 3})

	solo7, err7 := Run(seededCfg(7))
	if err7 != nil {
		t.Fatalf("solo seed7 err %v", err7)
	}
	solo8, err8 := Run(seededCfg(8))
	if err8 != nil {
		t.Fatalf("solo seed8 err %v", err8)
	}
	assertResultEqual(t, "a", solo7, groups[0].Result)
	assertResultEqual(t, "b", solo8, groups[1].Result)
	assertResultEqual(t, "a2", solo7, groups[2].Result)
	if groups[0].Name != "a" || groups[2].Name != "a2" {
		t.Fatalf("unexpected names %s/%s", groups[0].Name, groups[2].Name)
	}
}

func seededCfg(seed int64) Config {
	c := baseConfig()
	c.Seed = seed
	return c
}

func assertGroupEqual(t *testing.T, ctx string, want, got GroupResult) {
	t.Helper()
	if want.Name != got.Name || want.Category != got.Category || want.Stage != got.Stage {
		t.Fatalf("%s: header %+v != %+v", ctx, want, got)
	}
	if want.Audit != got.Audit {
		t.Fatalf("%s: audit differs:\nwant=%+v\ngot =%+v", ctx, want.Audit, got.Audit)
	}
	assertResultEqual(t, ctx, want.Result, got.Result)
}

func assertResultEqual(t *testing.T, ctx string, want, got Result) {
	t.Helper()
	if fmt.Sprintf("%x", want.Key) != fmt.Sprintf("%x", got.Key) {
		t.Fatalf("%s: key differs %x vs %x", ctx, want.Key, got.Key)
	}
	if want.Ledger != got.Ledger {
		t.Fatalf("%s: ledger differs %+v vs %+v", ctx, want.Ledger, got.Ledger)
	}
	if want.QBER != got.QBER {
		t.Fatalf("%s: qber differs %+v vs %+v", ctx, want.QBER, got.QBER)
	}
	if want.Reconciled.LeakedBits != got.Reconciled.LeakedBits ||
		want.Reconciled.ErrorsFixed != got.Reconciled.ErrorsFixed {
		t.Fatalf("%s: reconcile stats differs", ctx)
	}
	if fmt.Sprintf("%v", want.Reconciled.Key) != fmt.Sprintf("%v", got.Reconciled.Key) {
		t.Fatalf("%s: reconcile key differs", ctx)
	}
}
