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
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	src := NewSource(cfg.Seed)
	ch := NewChannel(cfg.ChannelLossDB, cfg.DetectorEfficiency, cfg.DarkCountProb, cfg.Eavesdrop, src)

	// 1. 制备与传输。每光子随机数消耗顺序固定：
	//    Alice 比特 → Alice 基 → Bob 基 →（信道内部随机）。
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
	aliceSift, bobSift, _ := Sift(photons)
	n := len(aliceSift)
	if n == 0 {
		return Result{}, ErrNoSignal
	}

	// 3. 确定性抽样误码估计（四舍五入，至少抽 1 个）。
	sampleSize := int(math.Round(float64(n) * cfg.SampleFraction))
	if sampleSize < 1 {
		sampleSize = 1
	}
	if sampleSize > n {
		sampleSize = n
	}
	est, remaining := EstimateQBER(aliceSift, bobSift, sampleSize, src, cfg.QBERThreshold)

	ledger := Ledger{
		Prepared:    cfg.NumPhotons,
		Detected:    detected,
		Sifted:      n,
		Sampled:     est.SampleSize,
		AfterSample: len(remaining),
	}

	// 4. 窃听判定：不安全立即终止，不返回任何密钥材料。
	if !est.Secure {
		return Result{Ledger: ledger, QBER: est}, &AbortError{
			Reason: fmt.Sprintf("estimated QBER %.4f exceeds threshold %.4f", est.QBER, est.Threshold),
			QBER:   est.QBER,
		}
	}
	if len(remaining) == 0 {
		return Result{Ledger: ledger, QBER: est}, ErrInsufficientKeyMaterial
	}

	// 5. 取出抽样剩余部分做误码纠正。
	aliceKey := make([]int, len(remaining))
	bobKey := make([]int, len(remaining))
	for i, idx := range remaining {
		aliceKey[i] = aliceSift[idx]
		bobKey[i] = bobSift[idx]
	}
	rec := Reconcile(aliceKey, bobKey, src)
	for i := range aliceKey {
		if rec.Key[i] != aliceKey[i] {
			return Result{Ledger: ledger, QBER: est, Reconciled: rec},
				errors.New("reconciliation failed to converge")
		}
	}
	ledger.LeakedEC = rec.LeakedBits

	// 6. Eve 信息估计泄漏：n_after * h2(QBER)，向上取整（二元熵，香农界口径）。
	ledger.LeakedEst = int(math.Ceil(float64(ledger.AfterSample) * binaryEntropy(est.QBER)))
	ledger.Margin = cfg.SecurityMargin

	// 7. 账目口径计算最终长度（整字节对齐），材料不足显式拒绝。
	bits := ledger.FinalKeyLen()
	if bits <= 0 {
		return Result{Ledger: ledger, QBER: est, Reconciled: rec}, ErrInsufficientKeyMaterial
	}
	outBits := (bits / 8) * 8
	if cfg.RequestedKeyBytes > 0 {
		need := cfg.RequestedKeyBytes * 8
		if bits < need {
			return Result{Ledger: ledger, QBER: est, Reconciled: rec}, ErrInsufficientKeyMaterial
		}
		outBits = need
	}
	if outBits < 8 {
		return Result{Ledger: ledger, QBER: est, Reconciled: rec}, ErrInsufficientKeyMaterial
	}

	// 8. 隐私放大。
	finalBits, err := PrivacyAmplify(rec.Key, outBits, src)
	if err != nil {
		return Result{Ledger: ledger, QBER: est, Reconciled: rec}, err
	}
	ledger.Final = outBits
	ledger.Discarded = ledger.FinalKeyLen() - outBits
	if err := ledger.Check(); err != nil {
		return Result{}, err
	}

	return Result{
		Key:        bitsToBytes(finalBits),
		Ledger:     ledger,
		QBER:       est,
		Reconciled: rec,
	}, nil
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
