package qkd

import "sync"

// BatchItem 是批量会话中的一组参数：每组独立跑完整流程。
// 随机性只来自其 Config.Seed，与组顺序、并发度及其他组无关。
type BatchItem struct {
	Name   string // 可选，便于调参与回归时标识参数组
	Config Config
}

// BatchOptions 控制批量执行方式。改变并发度不得改变任何一组的结果。
type BatchOptions struct {
	Concurrency int // <=0 视为 1（顺序执行）
}

// GroupResult 是单个参数组的结局，形态对所有结局统一：
// 成功、安全终止、无可用信号、材料不足、参数不可行等均通过
// Category/Stage/Audit 说明；成功时 Result.Key 非空。
// Audit 采用统一公开口径，任何结局都不含比特中间量。
type GroupResult struct {
	Index    int
	Name     string
	Category string
	Stage    string
	Audit    AuditRecord
	Result   Result
	Err      error
}

// RunBatch 按提交顺序执行多组会话，返回与 items 等长、按下标对齐的结果。
//
// 隔离性：每组调用独立的 Run，其随机源在 Run 内部按各自 Seed 新建，
// 账目为局部值，因此随机状态、账目与结论不会跨组串扰；同一组无论
// 排在前还是后、并发度是多少，结果逐项一致。
//
// 并发：Concurrency 仅限制同时运行的 goroutine 数（worker 池），
// 输出始终写回该组的固定下标，故返回顺序与内容与顺序执行完全相同。
func RunBatch(items []BatchItem, opts BatchOptions) []GroupResult {
	results := make([]GroupResult, len(items))

	workers := opts.Concurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}

	if workers <= 1 {
		for i, item := range items {
			results[i] = runGroup(i, item)
		}
		return results
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				// 每个 worker 直接写回固定下标；不同下标互不共享内存，
				// 无需额外加锁。
				results[i] = runGroup(i, items[i])
			}
		}()
	}
	for i := range items {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// runGroup 执行单个参数组并装配统一形态的结局（含公开审计）。
func runGroup(index int, item BatchItem) GroupResult {
	res, err := Run(item.Config)
	audit := AuditOf(item.Config, res, err)
	return GroupResult{
		Index:    index,
		Name:     item.Name,
		Category: audit.Category,
		Stage:    audit.Stage,
		Audit:    audit,
		Result:   res,
		Err:      err,
	}
}
