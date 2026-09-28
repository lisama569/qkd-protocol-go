package qkd

import "sync"

// BatchJob 是批量会话中的一个参数组。
type BatchJob struct {
	Name string // 可选，便于在结果中定位
	Cfg  Config
}

// BatchOutcome 是单个参数组的统一结果形态。
//
// 每组会话独立：随机状态来自该组自身 cfg.Seed 新建的 Source，账目、结论与密钥
// 均不跨组共享。结果按提交下标落位，因此改变分组顺序只改变下标位置，
// 改变 workers 只改变调度，同一参数组的结果逐项一致。
type BatchOutcome struct {
	Index int
	Name  string
	Audit Audit  // 统一公开口径（成功/失败一致），结构上不含密钥材料
	Key   []byte // 敏感：仅成功时非空；刻意与 Audit 分离，审计不含其内容
	Err   error
}

// RunBatch 并发运行多组独立会话，返回按提交顺序排列的结果（与并发度无关）。
// workers <= 0 或 workers > len(jobs) 时按顺序/至多 len(jobs) 个 worker 执行。
// 每组使用自身 cfg.Seed；返回切片与 jobs 等长且一一对应。
func RunBatch(jobs []BatchJob, workers int) []BatchOutcome {
	n := len(jobs)
	outcomes := make([]BatchOutcome, n)
	if workers <= 0 || workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			job := jobs[i]
			res, err := Run(job.Cfg)
			// 用应用缺省语义后的配置生成摘要：即使参数校验失败，参数摘要也完整。
			outcomes[i] = BatchOutcome{
				Index: i,
				Name:  job.Name,
				Audit: NewAudit(job.Cfg.withDefaults(), res, err),
				Key:   res.Key,
				Err:   err,
			}
		}(i)
	}
	wg.Wait()
	return outcomes
}
