package qkd

// 容量预估：在不输出最终密钥（也不走到隐私放大）的前提下，
// 判断给定目标长度与候选参数是否值得运行，并给出预计可用材料、
// 重要公开消耗与缺口原因。预估与真实执行共用 preparePipeline 与
// decideKeyLength，相同参数下结论不会自相矛盾。

// PublicCost 汇总密钥材料的主要公开消耗（均为计数口径，无比特序列）。
type PublicCost struct {
	Prepared    int // 制备光子数
	Detected    int // 探测事件数
	Sifted      int // 筛后可用比特
	Sampled     int // 误码抽样公开消耗
	AfterSample int // 抽样后剩余
	LeakedEC    int // 纠错公开泄漏
	LeakedEst   int // Eve 信息估计泄漏
	Margin      int // 安全余量
}

// CapacityEstimate 是一次容量预估结论。
// 本结构按设计不含任何比特序列字段：预估过程不输出最终密钥。
type CapacityEstimate struct {
	Params         ParamSummary
	TargetKeyBytes int // 用户目标，原样保留，绝不会被自动缩短
	Category       string
	Stage          string
	Feasible       bool // 目标能否严格满足（与真实 Run(RequestedKeyBytes=target) 成功边界一致）
	KeyPossible    bool // 不限目标时是否仍可产出 >=1 字节密钥（材料偏紧但非矛盾）
	AvailableBits  int  // 账目口径预计可用比特（可能为负、零或不足一字节）
	MaxKeyBytes    int  // 不限目标时整字节对齐最多可得字节数
	PlannedOutBits int  // Feasible 时计划输出的比特数；否则 0
	ShortfallBits  int  // Feasible 时为 0；否则为 need-avail（>0 缺口，说明差多少）
	Cost           PublicCost
	Reason         string // 类别 + 阶段口径的说明，不含中间量比特取值
}

// EstimateCapacity 执行与 Run 完全相同的制备→…→纠错阶段
// （preparePipeline），但不做隐私放大、不产出密钥；随后用同一个
// decideKeyLength 对目标做判定。因此：
//
//   - Feasible==true  ⇒ 以 RequestedKeyBytes=target 真实 Run 必成功；
//   - Feasible==false 且 KeyPossible==true ⇒ 材料偏紧/低收益，仍可出少量钥，
//     不得笼统归为参数矛盾，也不得自动缩短目标或静默降级；
//   - 其余 false 对应参数不可行/安全终止/无信号/材料不足等可区分类别。
func EstimateCapacity(cfg Config, targetKeyBytes int) CapacityEstimate {
	est := CapacityEstimate{
		Params:         summaryOf(cfg),
		TargetKeyBytes: targetKeyBytes,
	}
	if targetKeyBytes < 0 {
		est.Category = CategoryInvalidConfig
		est.Stage = StageConfig
		est.Reason = "invalid config: TargetKeyBytes " + ReasonOutOfRange
		return est
	}

	p, err := preparePipeline(cfg)
	fillCost(&est, p.ledger)
	if err != nil {
		// 复用审计口径，保证预估失败分类与执行/审计路径语义一致。
		rec := AuditOf(p.cfg, p.partialResult(), err)
		est.Category = rec.Category
		est.Stage = rec.Stage
		est.Reason = rec.Reason
		return est
	}

	avail := p.ledger.FinalKeyLen()
	est.AvailableBits = avail
	est.MaxKeyBytes = floorBytes(avail)
	est.KeyPossible = est.MaxKeyBytes >= 1

	// 对目标做与真实执行完全相同的出钥判定。
	out, derr := decideKeyLength(avail, targetKeyBytes)
	if derr == nil {
		est.Category = CategorySuccess
		est.Stage = StageComplete
		est.Feasible = true
		est.PlannedOutBits = out
		est.Reason = "target length is feasible"
		return est
	}

	// 目标不可行。缺口按目标整倍数口径计算（target=0 时为 8，即一字节门槛）。
	need := targetKeyBytes * 8
	if need == 0 {
		need = 8
	}
	est.ShortfallBits = need - avail

	// 仍能出少量钥 ⇒ 单独类别，区别于“无材料/参数矛盾”。
	if est.KeyPossible {
		est.Category = CategoryLowYield
		est.Stage = StageAccount
		est.Reason = "target not met but some key is possible"
		return est
	}
	est.Category = CategoryInsufficientMaterial
	est.Stage = StageAccount
	est.Reason = "insufficient key material for at least one byte"
	return est
}

func fillCost(est *CapacityEstimate, l Ledger) {
	est.Cost = PublicCost{
		Prepared:    l.Prepared,
		Detected:    l.Detected,
		Sifted:      l.Sifted,
		Sampled:     l.Sampled,
		AfterSample: l.AfterSample,
		LeakedEC:    l.LeakedEC,
		LeakedEst:   l.LeakedEst,
		Margin:      l.Margin,
	}
}

// floorBytes 返回 availBits 整字节向下对齐可得字节数（<8 为 0，负数为 0）。
func floorBytes(availBits int) int {
	if availBits < 8 {
		return 0
	}
	return availBits / 8
}
