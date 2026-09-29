package qkd

import (
	"fmt"
	"testing"
)

// 分组顺序 × 并发度的笛卡尔组合：同一参数组的审计、密钥必须逐项一致。
func TestBatchOrderAndWorkersMatrix(t *testing.T) {
	base := batchJobs()

	orders := [][]int{
		{0, 1, 2, 3, 4, 5, 6}, // 原顺序
		{6, 5, 4, 3, 2, 1, 0}, // 逆序
		{3, 0, 6, 2, 5, 1, 4},
		{6, 1, 4, 0, 5, 2, 3}, // 与既有 shuffle 不同的新排列
		{0, 0, 6, 6, 3, 3, 2}, // 含重复参数组
	}
	degrees := []int{1, 2, 3, 4, 7, 16}

	// 基线：每组单独 Run，按 Name 建立参照。
	type ref struct {
		audit Audit
		key   string
	}
	refs := map[string]ref{}
	for _, j := range base {
		res, err := Run(j.Cfg)
		refs[j.Name] = ref{audit: NewAudit(j.Cfg, res, err), key: fmt.Sprintf("%x", res.Key)}
	}

	for oi, order := range orders {
		jobs := make([]BatchJob, len(order))
		for k, idx := range order {
			jobs[k] = base[idx]
		}
		// 重复组重名时给唯一名，避免对照歧义；参数本身不变。
		seen := map[string]int{}
		for k := range jobs {
			seen[jobs[k].Name]++
			if seen[jobs[k].Name] > 1 {
				jobs[k].Name = fmt.Sprintf("%s#%d", jobs[k].Name, seen[jobs[k].Name]-1)
			}
		}
		for _, w := range degrees {
			outs := RunBatch(jobs, w)
			if len(outs) != len(jobs) {
				t.Fatalf("order=%d workers=%d: len=%d want %d", oi, w, len(outs), len(jobs))
			}
			for pos, o := range outs {
				if o.Index != pos {
					t.Fatalf("order=%d workers=%d: outcome at %d carries Index=%d", oi, w, pos, o.Index)
				}
				baseName := jobs[pos].Name
				if i := indexByte(baseName, '#'); i >= 0 {
					baseName = baseName[:i]
				}
				r := refs[baseName]
				if o.Audit != r.audit {
					t.Fatalf("order=%d workers=%d pos=%d job=%s audit diverged:\n got=%s\nwant=%s",
						oi, w, pos, jobs[pos].Name, o.Audit, r.audit)
				}
				if fmt.Sprintf("%x", o.Key) != r.key {
					t.Fatalf("order=%d workers=%d job=%s key diverged", oi, w, jobs[pos].Name)
				}
			}
		}
	}
}

// 批量结果中的阈值口径必须与该参数组生效阈值一致（含非法参数组）。
func TestBatchAuditThresholdsEffective(t *testing.T) {
	outs := RunBatch(batchJobs(), 4)
	for i, o := range outs {
		want := jobsEffectiveThreshold(batchJobs()[i].Cfg)
		if o.Audit.QBERThreshold != want || o.Audit.Params.QBERThreshold != want {
			t.Fatalf("job %s: threshold audit=%.4f params=%.4f want %.4f",
				o.Name, o.Audit.QBERThreshold, o.Audit.Params.QBERThreshold, want)
		}
	}
}

func jobsEffectiveThreshold(cfg Config) float64 {
	return cfg.withDefaults().QBERThreshold
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
