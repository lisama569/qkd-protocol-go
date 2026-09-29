package qkd

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 任意内部错误（即便原始文本含纠正后比特/筛后比特/最终密钥）都不得出现在审计输出中：
// Reason 与 String() 只保留固定公开类别与固定说明。
func TestAuditInternalErrorNeverForwardsRawText(t *testing.T) {
	sensitiveTexts := []string{
		"panic: corrected key bits=[1 0 1 1 0 0 1 0] leaked from cascade pass 2",
		"siftedbitssecret 0110100110010110 unexpectedly copied into audit payload",
		"fatal: finalkeyhex 3a7bdc1e9f2048b6 appended to error text before release",
		"[]int{1,1,0,0,1,0,1,0} index out of range in reconciledslice",
	}
	// 只可能来自错误原文的敏感片段（注意：sifted 等词是审计公开格式的合法字段名，
	// 不在此列；这里检查的是比特内容与仅内部实现才会出现的标记）。
	banned := []string{"10110010", "0110100110010110", "3a7bdc1e9f2048b6", "[]int", "panic", "fatal", "reconciledslice", "siftedbitssecret"}
	for i, raw := range sensitiveTexts {
		err := fmt.Errorf("%s", raw) // 非库内已知错误类型 → 归类 internal_error
		a := NewAudit(preset(int64(i+1), nil), Result{}, err)
		if a.Outcome != OutcomeInternalError {
			t.Fatalf("case %d: outcome=%s want internal_error", i, a.Outcome)
		}
		if a.Reason != InternalErrorPublicReason {
			t.Fatalf("case %d: raw internal text forwarded: %q", i, a.Reason)
		}
		text := a.Reason + " " + a.String()
		if strings.Contains(text, raw) {
			t.Fatalf("case %d: full raw internal text leaked into audit: %s", i, text)
		}
		low := strings.ToLower(text)
		for _, b := range banned {
			if strings.Contains(low, strings.ToLower(b)) {
				t.Fatalf("case %d: audit output contains sensitive fragment %q: %s", i, b, text)
			}
		}
		assertNoKeyLeak(t, a, nil)
		t.Logf("case %d sanitized: %s", i, a)
	}
}

// 即便内部错误被标记到其它阶段，也必须按内部错误脱敏（阶段可定位，原文不转发）。
func TestAuditMarkedInternalErrorStillSanitized(t *testing.T) {
	raw := errors.New("pa buffer overrun holding reconciled bits 10110010")
	err := withStage(StagePrivacyAmplify, raw)
	a := NewAudit(baseConfig(), Result{}, err)
	if a.Outcome != OutcomeInternalError || a.Stage != StagePrivacyAmplify {
		t.Fatalf("got %s/%s", a.Outcome, a.Stage)
	}
	if a.Reason != InternalErrorPublicReason || strings.Contains(a.String(), "10110010") {
		t.Fatalf("marked internal error leaked: reason=%q audit=%s", a.Reason, a)
	}
}

// publicFailureReason：已知类别错误可安全透传公开文本；内部错误统一替换为固定说明。
func TestPublicFailureReason(t *testing.T) {
	if got := publicFailureReason(OutcomeInternalError, errors.New("secret bits 0011")); got != InternalErrorPublicReason {
		t.Fatalf("internal error not sanitized: %q", got)
	}
	ve := &ValidationError{Field: "NumPhotons", Reason: ReasonMissing}
	if got := publicFailureReason(OutcomeInvalidConfig, ve); got != ve.Error() {
		t.Fatalf("known error text should pass through, got %q", got)
	}
	abort := &AbortError{Reason: "qber high", QBER: 0.3}
	if got := publicFailureReason(OutcomeAbortedInsecure, abort); got != abort.Error() {
		t.Fatalf("abort text should pass through, got %q", got)
	}
}

// 抽样阶段把剩余材料抽光而失败：必须归到 qber_estimate 阶段，
// 不得再被记到 accounting 阶段；结论仍为材料不足（耗尽子类别）。
func TestAuditSampledOutClassifiedAtQBERStage(t *testing.T) {
	cfg := preset(1, func(c *Config) {
		c.NumPhotons = 200
		c.SampleFraction = 0.999
		c.RequestedKeyBytes = 0
	})
	res, err := Run(cfg)
	if !errors.Is(err, ErrInsufficientKeyMaterial) {
		t.Fatalf("want ErrInsufficientKeyMaterial, got %v", err)
	}
	if res.Ledger.Sifted == 0 || res.Ledger.AfterSample != 0 || res.Ledger.Sampled != res.Ledger.Sifted {
		t.Fatalf("expected all sifted material sampled out: %s", res.Ledger)
	}
	a := NewAudit(cfg, res, err)
	t.Logf("sampled-out audit: %s", a)
	if a.Outcome != OutcomeInsufficient {
		t.Fatalf("outcome=%s want insufficient_material", a.Outcome)
	}
	if a.Stage != StageQBEREstimate {
		t.Fatalf("stage=%s want %s (must match the stage where sampling exhausted material)",
			a.Stage, StageQBEREstimate)
	}
	if a.Detail != DetailExhausted {
		t.Fatalf("detail=%s want exhausted", a.Detail)
	}
	assertNoKeyLeak(t, a, res.Key)

	// 容量预估同参必须报告同一阶段（真实执行口径一致）。
	e, eerr := EstimateCapacity(cfg, 0)
	if eerr != nil {
		t.Fatalf("estimate: %v", eerr)
	}
	if e.Stage != StageQBEREstimate || e.Verdict != CapacityExhausted {
		t.Fatalf("estimate got stage=%s verdict=%s", e.Stage, e.Verdict)
	}
}
