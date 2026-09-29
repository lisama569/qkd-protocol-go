package qkd

import (
	"errors"
	"fmt"
	"math"
)

// AbortError 表示会话被判定不安全而终止，不输出任何密钥材料。
type AbortError struct {
	Reason string
	QBER   float64
}

func (e *AbortError) Error() string {
	return fmt.Sprintf("session aborted: %s (qber=%.4f)", e.Reason, e.QBER)
}

// ErrNoSignal 表示筛选后没有任何可用事件（如损耗过高）。
var ErrNoSignal = errors.New("no usable detection after sifting")

// ErrReconciliationFailed 表示误码纠正后仍与 Alice 侧不一致（未收敛）。
var ErrReconciliationFailed = errors.New("reconciliation failed to converge")

// Result 是一次会话的输出；会话终止或材料不足时 Key 为 nil。
type Result struct {
	Key        []byte
	Ledger     Ledger
	QBER       QBEREstimate
	Reconciled ReconcileResult
}

// preparedRun 是隐私放大之前的内部状态：真实执行与容量预估共用这一条判定路径，
// 保证“预估结论”和“实际执行结局”在相同参数下不会自相矛盾。
// 其中 rec.Key 为敏感中间量，仅 Run 在进程内用于隐私放大，绝不进入对外审计。
type preparedRun struct {
	cfg     Config  // 已应用缺省值
	src     *Source // 会话随机源（已消耗到纠错之后，隐私放大继续使用，保证密钥流不变）
	ledger  Ledger
	est     QBEREstimate
	rec     ReconcileResult
	stage   string // 已推进到的最远阶段
	outBits int    // 计划输出的密钥比特数（<8 或材料不足时不产生密钥）
}

// resultView 按当前状态构造对外 Result（仅填入公开/既有字段，不含最终密钥）。
func (p preparedRun) resultView() Result {
	return Result{Ledger: p.ledger, QBER: p.est, Reconciled: p.rec}
}

// Run 执行完整 BB84 流程：
//
//	制备→传输（损耗/效率/暗计数/可选窃听）→基比对筛选→
//	确定性抽样误码估计（不安全即终止）→误码纠正→
//	隐私放大→密钥账目核算→输出。
//
// 随机性全部来自 Seed 决定的会话级 Source，相同种子重复运行结果完全一致。
func Run(cfg Config) (Result, error) {
	prep, err := prepareSession(cfg)
	if err != nil {
		return prep.resultView(), err
	}

	// 8. 隐私放大（仅真实执行；容量预估不会走到这里）。
	finalBits, paErr := PrivacyAmplify(prep.rec.Key, prep.outBits, prep.src)
	if paErr != nil {
		return prep.resultView(), paErr
	}
	ledger := prep.ledger
	ledger.Final = prep.outBits
	ledger.Discarded = ledger.FinalKeyLen() - prep.outBits
	if err := ledger.Check(); err != nil {
		return Result{}, err
	}
	res := prep.resultView()
	res.Ledger = ledger
	res.Key = bitsToBytes(finalBits)
	return res, nil
}

// prepareSession 运行到账目判定为止（不出最终密钥），返回最远阶段与公开状态。
// 随机数消耗顺序与原实现严格一致：
//
//	Alice 比特 → Alice 基 → Bob 基 →（信道内部随机）→ 抽样 Perm → 纠错洗牌 → PA 种子。
func prepareSession(cfg Config) (preparedRun, error) {
	cfg = cfg.withDefaults()
	p := preparedRun{cfg: cfg, stage: StageValidate}
	if err := cfg.Validate(); err != nil {
		return p, err
	}
	src := NewSource(cfg.Seed)
	p.src = src
	ch := NewChannel(cfg.ChannelLossDB, cfg.DetectorEfficiency, cfg.DarkCountProb, cfg.Eavesdrop, src)

	// 1. 制备与传输。
	p.stage = StageTransmit
	p.ledger.Prepared = cfg.NumPhotons // 公开计数：即便后续无信号也保留制备量
	photons := make([]Photon, cfg.NumPhotons)
	detected := 0
	for i := range photons {
		bit := src.Bit()
		aliceBasis := src.Bit()
		bobBasis := src.Bit()
		photons[i] = ch.Transmit(bit, aliceBasis, bobBasis)
		if photons[i].Detected {
			detected++
		}
	}

	// 2. 基比对筛选。
	p.stage = StageSift
	aliceSift, bobSift, _ := Sift(photons)
	n := len(aliceSift)
	if n == 0 {
		return p, ErrNoSignal
	}

	// 3. 确定性抽样误码估计（四舍五入，至少抽 1 个）。
	p.stage = StageQBEREstimate
	sampleSize := int(math.Round(float64(n) * cfg.SampleFraction))
	if sampleSize < 1 {
		sampleSize = 1
	}
	if sampleSize > n {
		sampleSize = n
	}
	est, remaining := EstimateQBER(aliceSift, bobSift, sampleSize, src, cfg.QBERThreshold)
	p.est = est
	p.ledger = Ledger{
		Prepared:    cfg.NumPhotons,
		Detected:    detected,
		Sifted:      n,
		Sampled:     est.SampleSize,
		AfterSample: len(remaining),
	}

	// 4. 窃听判定：不安全立即终止，不返回任何密钥材料。
	if !est.Secure {
		return p, &AbortError{
			Reason: fmt.Sprintf("estimated QBER %.4f exceeds threshold %.4f", est.QBER, est.Threshold),
			QBER:   est.QBER,
		}
	}
	if len(remaining) == 0 {
		// 抽样把全部筛后材料公开消耗：实际只推进到误码估计阶段，
		// 显式标注阶段，避免审计把该失败错归到账目阶段。
		return p, withStage(StageQBEREstimate, ErrInsufficientKeyMaterial)
	}

	// 5. 取出抽样剩余部分做误码纠正。
	p.stage = StageReconcile
	aliceKey := make([]int, len(remaining))
	bobKey := make([]int, len(remaining))
	for i, idx := range remaining {
		aliceKey[i] = aliceSift[idx]
		bobKey[i] = bobSift[idx]
	}
	rec := Reconcile(aliceKey, bobKey, src)
	for i := range aliceKey {
		if rec.Key[i] != aliceKey[i] {
			// 与历史口径一致：不收敛时账目不计入 LeakedEC（公开纠正统计仍在 rec 中）。
			p.rec = rec
			return p, ErrReconciliationFailed
		}
	}
	p.rec = rec
	p.ledger.LeakedEC = rec.LeakedBits

	// 6. Eve 信息估计泄漏：n_after * h2(QBER)，向上取整（香农界口径）。
	p.ledger.LeakedEst = int(math.Ceil(float64(p.ledger.AfterSample) * binaryEntropy(est.QBER)))
	p.ledger.Margin = cfg.SecurityMargin

	// 7. 账目口径判定最终长度（整字节对齐），材料不足显式拒绝。
	p.stage = StageAccounting
	bits := p.ledger.FinalKeyLen()
	if bits <= 0 {
		return p, ErrInsufficientKeyMaterial
	}
	outBits := (bits / 8) * 8
	if cfg.RequestedKeyBytes > 0 {
		need := cfg.RequestedKeyBytes * 8
		if bits < need {
			return p, ErrInsufficientKeyMaterial
		}
		outBits = need
	}
	if outBits < 8 {
		return p, ErrInsufficientKeyMaterial
	}
	p.outBits = outBits
	return p, nil
}

// binaryEntropy 返回二元熵 H2(p) = -p log2 p - (1-p) log2(1-p)，端点为 0。
func binaryEntropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// bitsToBytes 按高位优先打包；len(bits) 为 8 的倍数。
func bitsToBytes(bits []int) []byte {
	out := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b == 1 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}
