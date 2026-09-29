package qkd

import (
	"fmt"
	"testing"
)

// preset 构造一组可复现、结局明确的参数（除显式覆盖外与 baseConfig 同源）。
func preset(seed int64, mutate func(*Config)) Config {
	c := baseConfig()
	c.Seed = seed
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func batchJobs() []BatchJob {
	return []BatchJob{
		{Name: "success", Cfg: preset(1, nil)},
		{Name: "abort", Cfg: preset(1, func(c *Config) { c.Eavesdrop = true })},
		{Name: "no-signal", Cfg: preset(1, func(c *Config) {
			c.NumPhotons = 100
			c.ChannelLossDB = 40
			c.DarkCountProb = 1e-12
			c.RequestedKeyBytes = 0
		})},
		{Name: "exhausted", Cfg: preset(1, func(c *Config) {
			c.NumPhotons = 40
			c.RequestedKeyBytes = 0
		})},
		{Name: "low-yield", Cfg: preset(1, func(c *Config) {
			c.NumPhotons = 640
			c.RequestedKeyBytes = 0
		})},
		{Name: "short-of-target", Cfg: preset(1, func(c *Config) {
			c.NumPhotons = 4000
			c.RequestedKeyBytes = 64 // 能出更短的钥（约 25 字节）但达不到 64 字节
		})},
		{Name: "invalid", Cfg: Config{NumPhotons: 0, DetectorEfficiency: 0.9, Seed: 1}},
	}
}

func expectedOutcomes() map[string]string {
	return map[string]string{
		"success":         OutcomeSuccess,
		"abort":           OutcomeAbortedInsecure,
		"no-signal":       OutcomeNoSignal,
		"exhausted":       OutcomeInsufficient,
		"low-yield":       OutcomeInsufficient,
		"short-of-target": OutcomeInsufficient,
		"invalid":         OutcomeInvalidConfig,
	}
}

func expectedDetails() map[string]string {
	return map[string]string{
		"exhausted":       DetailExhausted,
		"low-yield":       DetailLowYield,
		"short-of-target": DetailInsufficientForTarget,
	}
}

func verifyOutcomes(t *testing.T, outs []BatchOutcome) {
	t.Helper()
	wantOutcome := expectedOutcomes()
	wantDetail := expectedDetails()
	if len(outs) != len(batchJobs()) {
		t.Fatalf("expected %d outcomes, got %d", len(batchJobs()), len(outs))
	}
	for i, o := range outs {
		if o.Index != i {
			t.Fatalf("outcome %d not placed at its submission index (got Index=%d)", i, o.Index)
		}
		want := wantOutcome[o.Name]
		if o.Audit.Outcome != want {
			t.Fatalf("job %q: outcome=%s want %s (err=%v)", o.Name, o.Audit.Outcome, want, o.Err)
		}
		if d, ok := wantDetail[o.Name]; ok && o.Audit.Detail != d {
			t.Fatalf("job %q: detail=%q want %q", o.Name, o.Audit.Detail, d)
		}
		// 失败不得携带密钥；成功必须携带且与审计长度一致。
		if want == OutcomeSuccess {
			if o.Key == nil || len(o.Key)*8 != o.Audit.KeyBits {
				t.Fatalf("job %q: success must carry key matching KeyBits=%d", o.Name, o.Audit.KeyBits)
			}
		} else if o.Key != nil {
			t.Fatalf("job %q: non-success outcome must not carry key", o.Name)
		}
		t.Logf("[batch] %s -> %s/%s stage=%s %s", o.Name, o.Audit.Outcome, o.Audit.Detail, o.Audit.Stage, o.Audit)
	}
}

// 同一批任务在不同并发度（顺序/1/2/4/超大）下逐项一致：结论、计数、密钥全相同。
func TestBatchConcurrencyReproducible(t *testing.T) {
	jobs := batchJobs()
	degrees := []int{0, 1, 2, 4, 100}
	ref := RunBatch(jobs, degrees[0])
	verifyOutcomes(t, ref)
	for _, w := range degrees[1:] {
		got := RunBatch(jobs, w)
		for i := range ref {
			if !outcomesEqual(ref[i], got[i]) {
				t.Fatalf("workers=%d job %d (%s) diverged:\n ref=%s\n got=%s",
					w, i, ref[i].Name, ref[i].Audit, got[i].Audit)
			}
		}
	}
}

// 打乱分组顺序：每个参数组的结果仍与顺序执行时逐字段一致（按 Name 对照）。
func TestBatchOrderIndependence(t *testing.T) {
	jobs := batchJobs()
	ref := RunBatch(jobs, 1)
	byName := map[string]BatchOutcome{}
	for _, o := range ref {
		byName[o.Name] = o
	}

	shuffled := []BatchJob{
		jobs[6], jobs[1], jobs[4], jobs[0], jobs[5], jobs[2], jobs[3],
	}
	got := RunBatch(shuffled, 3)
	for pos, o := range got {
		if o.Index != pos || o.Name != shuffled[pos].Name {
			t.Fatalf("outcome not placed at submission index after shuffle")
		}
		r := byName[o.Name]
		if !outcomesEqual(r, o) {
			t.Fatalf("job %q differs when group order changes:\n ref=%s\n got=%s",
				o.Name, r.Audit, o.Audit)
		}
	}
}

// 并发隔离：重复参数组在批内并发执行，互不串状态，且与单独 Run 的结果一致。
func TestBatchConcurrentIsolation(t *testing.T) {
	const copies = 24
	jobs := make([]BatchJob, copies)
	for i := range jobs {
		jobs[i] = BatchJob{Name: fmt.Sprintf("dup-%d", i), Cfg: preset(int64(i%3)+1, nil)}
	}
	outs := RunBatch(jobs, 8)

	solo := map[int64][]byte{}
	for _, o := range outs {
		seed := int64(o.Index%3) + 1
		want, ok := solo[seed]
		if !ok {
			res, err := Run(preset(seed, nil))
			if err != nil {
				t.Fatalf("solo run seed %d: %v", seed, err)
			}
			want = res.Key
			solo[seed] = want
		}
		if o.Audit.Outcome != OutcomeSuccess {
			t.Fatalf("%s: expected success, got %s", o.Name, o.Audit.Outcome)
		}
		if fmt.Sprintf("%x", o.Key) != fmt.Sprintf("%x", want) {
			t.Fatalf("%s: key diverged from solo run", o.Name)
		}
	}
}

func outcomesEqual(a, b BatchOutcome) bool {
	if a.Name != b.Name || a.Audit != b.Audit {
		return false
	}
	return fmt.Sprintf("%x", a.Key) == fmt.Sprintf("%x", b.Key)
}

// 改变分组顺序与并发度：逐位置/逐 Name 比对，审计全字段（含阶段、阈值、
// QBER、公开计数、KeyBits）与密钥必须完全一致。
func TestBatchPerItemConsistencyAcrossOrderAndWorkers(t *testing.T) {
	jobs := batchJobs()
	ref := RunBatch(jobs, 1)

	// 1) 仅改变并发度：同一下标位置逐项一致。
	for _, w := range []int{0, 2, 4, 8, 100} {
		got := RunBatch(jobs, w)
		if len(got) != len(ref) {
			t.Fatalf("workers=%d length=%d want %d", w, len(got), len(ref))
		}
		for i := range ref {
			if got[i].Index != i || !outcomesEqual(ref[i], got[i]) {
				t.Fatalf("workers=%d item %d diverged:\n ref=%s\n got=%s",
					w, i, ref[i].Audit, got[i].Audit)
			}
		}
	}

	// 2) 改变分组顺序：按 Name 对照，每个参数组结果逐项一致。
	shuffled := []BatchJob{jobs[3], jobs[6], jobs[0], jobs[5], jobs[2], jobs[4], jobs[1]}
	got := RunBatch(shuffled, 3)
	byName := map[string]BatchOutcome{}
	for _, o := range ref {
		byName[o.Name] = o
	}
	for pos, o := range got {
		if o.Index != pos || o.Name != shuffled[pos].Name {
			t.Fatalf("item not placed at submission index after reorder")
		}
		want := byName[o.Name]
		if !outcomesEqual(want, o) {
			t.Fatalf("group %q diverges across order:\n ref=%s\n got=%s",
				o.Name, want.Audit, o.Audit)
		}
	}
}
