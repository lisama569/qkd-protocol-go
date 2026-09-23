# qkd-protocol-go

在本地以模拟光子信道与确定性随机源贯通 BB84 量子密钥分发完整链路：
光子制备 → 基比对筛选 → 误码率估计与窃听判定 → 误码纠正 → 密钥校验 →
隐私放大 → 密钥账目核算。相同参数与随机种子下结果完全可复现。

## 运行

```bash
# 无窃听、理想信道
go run ./cmd/qkd -n 20000 -seed 1

# 有损耗、探测器效率与暗计数
go run ./cmd/qkd -loss 3 -eta 0.5 -dark 0.05

# 注入拦截-重发式窃听者（会话将被判定不安全并终止）
go run ./cmd/qkd -eve

# 要求最短密钥长度（不足时明确失败，不截断不补齐）
go run ./cmd/qkd -loss 3 -eta 0.5 -dark 0.05 -require 500
```

## 测试与复现验证

```bash
go test ./...          # 全部单测
go test -race ./...    # 并发竞态检测
go test -v -run TestNoisyChannel ./qkd/   # 查看输入参数/中间量/判定依据日志
```

`TestDeterminismAcrossRuns` 与 `TestConcurrentSessions` 验证固定种子下
重复运行、并发运行的结果与串行基准逐比特一致。

## 协议参数

| 参数 | 必填 | 缺省 | 含义 |
|---|---|---|---|
| `NumQubits` | 是 | — | Alice 制备的光子数，>0 |
| `Seed` | 否 | 1 | 会话随机源种子；同种子同参数结果完全一致 |
| `ChannelLossDB` | 否 | 0 | 信道损耗（dB），≥0；光子存活率 10^(-loss/10) |
| `DetectorEfficiency` | 否 | 1.0 | 探测器效率，(0,1] |
| `DarkCountProb` | 否 | 0 | 每时隙暗计数概率，[0,1)，产生随机比特 |
| `QBERThreshold` | 否 | 0.11 | 窃听判定阈值，(0,0.5) |
| `SampleFraction` | 否 | 0.2 | 误码估计抽样比例，(0,1)，样本公开后丢弃 |
| `Eavesdropper` | 否 | false | 是否存在拦截-重发式窃听者 |
| `ECEfficiency` | 否 | 1.16 | 纠错效率因子（保留用于泄漏建模） |
| `RequiredKeyBits` | 否 | 0 | 要求的最短最终密钥；0 表示不强制 |

可选字段以指针表达“未设置”，缺省值集中于 `config.go` 的常量，语义确定且稳定。

### 配置拒绝（可区分原因）

- `ErrMissingField`：必填项缺失（`NumQubits <= 0`）。
- `ErrInvalidValue`：单项越界（如效率 >1、阈值不在 (0,0.5)）。
- `ErrConflictingValues`：组合矛盾，包括
  1. `RequiredKeyBits > NumQubits`（信息论上不可能）；
  2. 暗计数决定的固有误码率下限 `(pDark/2)/(η·10^(-L/10)+pDark)` ≥ 阈值，
     会话必然被判定不安全。

均可用 `errors.Is` 区分。

## 终止规则

1. **无筛后密钥**（信道过损）：终止，`ErrSessionAborted`。
2. **窃听判定**：抽样误码率 `qber > QBERThreshold`（严格大于；等于阈值视为通过，
   临界行为稳定）时终止，`ErrSessionAborted`。
3. **密钥校验失败**（纠错后双方校验值不一致）：失败，`ErrKeyVerification`。
4. **材料不足**（纠错、校验、隐私放大后剩余长度 ≤0 或 < `RequiredKeyBits`）：
   失败，`ErrInsufficientMaterial`，不截断、不补齐、不静默降级。

任何终止或失败路径下 `Result.Key` 均为 nil，输出仅含计数与比率，
不含任何可用于推导密钥的中间材料。

### 抽样口径的稳定性

误码估计的抽样下标取自会话随机源的 `Perm` 前 k 项（k 由抽样比例四舍五入确定），
完全由种子决定；同一会话内口径固定，重复运行不会漂移。

## 密钥账目口径

`Ledger` 满足守恒恒等式（`Ledger.Conserved()` 校验）：

```
Final == Sifted - Sampled - ECLeak - VerifyLeak - PALeak
```

- `Sifted`：基一致且探测到计数的筛后比特数；
- `Sampled`：误码估计公开并丢弃的比特数；
- `ECLeak`：纠错过程公开的校验比特数（逐比特计数）；
- `VerifyLeak`：密钥校验公开的比特数（恒 32，SHA-256 截断）；
- `PALeak`：隐私放大减去的窃听者信息上界 `⌈n·h2(qber)⌉`。

最终密钥由 Toeplitz 通用哈希（种子取自会话随机源）压缩产出。

## 并发与随机状态

每个 `Session` 持有独立的 `Source`（`math/rand` 实例），会话间不共享
随机状态与账目，可安全并发；同种子会话并发与串行结果一致。

## 代码结构

```
qkd/config.go     参数、缺省值与可区分校验
qkd/random.go     会话级确定性随机源
qkd/channel.go    光子信道模拟（损耗/效率/暗计数/窃听）
qkd/sift.go       光子制备、基比对与筛选
qkd/qber.go       误码率估计与窃听判定
qkd/reconcile.go  误码纠正、密钥校验、隐私放大与账目
qkd/session.go    会话编排与终止规则
cmd/qkd/main.go   本地可运行入口
```
