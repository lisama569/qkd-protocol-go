package qkd

import "errors"

// ErrSessionAborted 表示会话因判定不安全而终止。
var ErrSessionAborted = errors.New("qkd: session aborted")

// Session 表示一次完整的 QKD 会话。
// 会话持有独立的随机源，多个会话可安全并发，互不影响。
type Session struct {
	cfg Config
	src *Source
}

// Result 是会话的最终输出。
// 当 Aborted 为 true 或 err 非 nil 时，Key 必为 nil，
// 且不包含任何可用于推导密钥的中间材料（仅含计数与比率）。
type Result struct {
	Key     []byte // 最终密钥；失败或终止时为 nil
	Ledger  Ledger // 密钥账目
	QBER    float64
	Aborted bool   // 是否因窃听判定而终止
	Reason  string // 终止或失败原因（成功时为空）
}

// NewSession 校验配置并创建会话。
func NewSession(cfg Config) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Session{cfg: cfg.withDefaults(), src: NewSource(cfg.seed())}, nil
}

// Run 执行完整协议流程：制备与筛选 → 误码估计与窃听判定 →
// 误码纠正 → 密钥校验 → 隐私放大与账目核算。
// 判定不安全时返回的 Result.Aborted 为 true 且 Key 为 nil。
func (s *Session) Run() (*Result, error) {
	cfg := s.cfg
	ch := NewChannel(cfg)

	// 阶段 1：光子制备、传输与基比对筛选。
	sf := sift(cfg, ch, s.src)
	ledger := Ledger{Sent: sf.sent, Detected: sf.detected, Sifted: len(sf.aliceKey)}
	res := &Result{}

	if ledger.Sifted == 0 {
		res.Aborted = true
		res.Reason = "no sifted key bits (channel too lossy)"
		res.Ledger = ledger
		return res, ErrSessionAborted
	}

	// 阶段 2：误码率估计与窃听判定。
	q := estimateQBER(cfg, s.src, sf)
	ledger.Sampled = q.sampleSize
	res.QBER = q.qber
	if q.abort {
		// 终止：丢弃全部密钥材料，仅保留计数与比率。
		res.Aborted = true
		res.Reason = "estimated QBER above threshold; possible eavesdropping"
		res.Ledger = ledger
		return res, ErrSessionAborted
	}

	// 阶段 3：误码纠正、校验、隐私放大与账目核算。
	key, err := reconcile(cfg, s.src, q, &ledger)
	res.Ledger = ledger
	if err != nil {
		res.Reason = err.Error()
		return res, err
	}
	res.Key = key
	return res, nil
}
