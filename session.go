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

// ErrReconcileFailed 表示误码纠正后两侧仍不一致，显式终止且不输出密钥。
var ErrReconcileFailed = errors.New("reconciliation failed to converge")

// Result 是一次会话的输出；会话终止或材料不足时 Key 为 nil。
type Result struct {
	Key        []byte
	Ledger     Ledger
	QBER       QBEREstimate
	Reconciled ReconcileResult
}

// Run 执行完整 BB84 流程：
//
//	制备→传输（损耗/效率/暗计数/可选窃听）→基比对筛选→
//	确定性抽样误码估计（不安全即终止）→误码纠正→
//	隐私放大→密钥账目核算→输出。
//
// 随机性全部来自 Seed 决定的会话级 Source，相同种子重复运行结果完全一致。
func Run(cfg Config) (Result, error) {
	p, err := preparePipeline(cfg)
	if err != nil {
		return p.partialResult(), err
	}

	// 7. 账目口径计算最终长度（整字节对齐），材料不足显式拒绝。
	outBits, err := decideKeyLength(p.ledger.FinalKeyLen(), cfg.RequestedKeyBytes)
	if err != nil {
		return p.partialResult(), err
	}

	// 8. 隐私放大。
	finalBits, paErr := PrivacyAmplify(p.rec.Key, outBits, p.src)
	if paErr != nil {
		return p.partialResult(), paErr
	}
	p.ledger.Final = outBits
	p.ledger.Discarded = p.ledger.FinalKeyLen() - outBits
	if err := p.ledger.Check(); err != nil {
		return Result{}, err
	}

	return Result{
		Key:        bitsToBytes(finalBits),
		Ledger:     p.ledger,
		QBER:       p.est,
		Reconciled: p.rec,
	}, nil
}

// pipeline 承载制备→…→纠错阶段后的会话内部状态。
// 其中 rec.Key 等比特材料仅存在于进程内存，供隐私放大使用，
// 绝不进入审计口径。
type pipeline struct {
	cfg    Config
	src    *Source
	ledger Ledger
	est    QBEREstimate
	rec    ReconcileResult
}

// partialResult 返回当前阶段可公开的结果形态（账目/误码/纠错计数）。
func (p pipeline) partialResult() Result {
	return Result{Ledger: p.ledger, QBER: p.est, Reconciled: p.rec}
}

// preparePipeline 执行隐私放大之前的全部阶段（制备、传输、筛选、
// 误码估计与窃听判定、纠错、公开消耗入账）。Run 与容量预估共用本函数，
// 因此相同参数下两者对“能否继续、消耗多少”的判断不可能分叉。
func preparePipeline(cfg0 Config) (pipeline, error) {
	cfg := cfg0.withDefaults()
	if err := cfg.Validate(); err != nil {
		return pipeline{cfg: cfg}, err
	}
	p := pipeline{cfg: cfg}
	p.src = NewSource(cfg.Seed)
	ch := NewChannel(cfg.ChannelLossDB, cfg.DetectorEfficiency, cfg.DarkCountProb, cfg.Eavesdrop, p.src)

	// 1. 制备与传输。每光子随机数消耗顺序固定：
	//    Alice 比特 → Alice 基 → Bob 基 →（信道内部随机）。
	photons := make([]Photon, cfg.NumPhotons)
	detected := 0
	for i := range photons {
		bit := p.src.Bit()
		aliceBasis := p.src.Bit()
		bobBasis := p.src.Bit()
		photons[i] = ch.Transmit(bit, aliceBasis, bobBasis)
		if photons[i].Detected {
			detected++
		}
	}

	// 2. 基比对筛选。
	aliceSift, bobSift, _ := Sift(photons)
	n := len(aliceSift)
	if n == 0 {
		return p, ErrNoSignal
	}

	// 3. 确定性抽样误码估计（四舍五入，至少抽 1 个）。
	sampleSize := int(math.Round(float64(n) * cfg.SampleFraction))
	if sampleSize < 1 {
		sampleSize = 1
	}
	if sampleSize > n {
		sampleSize = n
	}
	est, remaining := EstimateQBER(aliceSift, bobSift, sampleSize, p.src, cfg.QBERThreshold)
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
		return p, ErrInsufficientKeyMaterial
	}

	// 5. 取出抽样剩余部分做误码纠正。
	aliceKey := make([]int, len(remaining))
	bobKey := make([]int, len(remaining))
	for i, idx := range remaining {
		aliceKey[i] = aliceSift[idx]
		bobKey[i] = bobSift[idx]
	}
	rec := Reconcile(aliceKey, bobKey, p.src)
	for i := range aliceKey {
		if rec.Key[i] != aliceKey[i] {
			p.rec = rec
			return p, ErrReconcileFailed
		}
	}
	p.rec = rec
	p.ledger.LeakedEC = rec.LeakedBits

	// 6. Eve 信息估计泄漏：n_after * h2(QBER)，向上取整（二元熵，香农界口径）。
	p.ledger.LeakedEst = int(math.Ceil(float64(p.ledger.AfterSample) * binaryEntropy(est.QBER)))
	p.ledger.Margin = cfg.SecurityMargin
	return p, nil
}

// decideKeyLength 按账目口径判定计划输出比特数（纯函数）：
//   - availBits <= 0：材料不足；
//   - requestedBytes > 0：必须严格满足 requestedBytes*8，否则不足（不截断）；
//   - requestedBytes == 0：尽量长，整字节向下对齐，不足 1 字节判不足。
//
// Run 与容量预估共用，保证“预估可行 ⇔ 真实执行能出钥”。
func decideKeyLength(availBits, requestedBytes int) (int, error) {
	if availBits <= 0 {
		return 0, ErrInsufficientKeyMaterial
	}
	if requestedBytes > 0 {
		need := requestedBytes * 8
		if availBits < need {
			return 0, ErrInsufficientKeyMaterial
		}
		return need, nil
	}
	outBits := (availBits / 8) * 8
	if outBits < 8 {
		return 0, ErrInsufficientKeyMaterial
	}
	return outBits, nil
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
