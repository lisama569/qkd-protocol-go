# qkd-protocol-go

本地可运行的 BB84 量子密钥分发模拟实现（Go，无第三方依赖）。用本地模拟的光子信道
与确定性随机源，贯通 **光子制备 → 传输（损耗/暗计数/窃听）→ 基比对筛选 →
误码率估计与窃听判定 → 误码纠正 → 隐私放大 → 密钥账目核算 → 最终密钥输出**
完整链路。

## 快速开始

```bash
# 构建/测试
go build ./...
go test -v ./...

# 运行一次会话（默认无窃听、种子 1）
go run ./cmd/qkdsim -seed 1 -n 4000 -loss 5 -eff 0.9 -dark 0.0001 -key 16

# 模拟窃听（拦截-重发），会话将被终止且不输出密钥
go run ./cmd/qkdsim -seed 1 -n 4000 -eve
```

CLI 会打印输入参数、误码估计、纠正统计与密钥账目，成功时输出十六进制密钥。

## 协议参数含义

| 参数 | 字段 | 必填 | 合法范围 / 缺省语义 |
|---|---|---|---|
| 制备光子数 | `NumPhotons` | 是 | `> 0`；0 视为缺失 |
| 信道损耗 (dB) | `ChannelLossDB` | 是 | `>= 0`，光子存活概率 `p = 10^(-loss/10)` |
| 探测器效率 | `DetectorEfficiency` | 是 | `(0,1]`；0 视为缺失 |
| 暗计数概率 | `DarkCountProb` | 是 | `[0,1)`，每个空时隙产生随机比特虚假计数的概率 |
| 窃听开关 | `Eavesdrop` | 否 | `true` 时 Eve 以拦截-重发介入 |
| 误码抽样比例 | `SampleFraction` | 否 | `(0,1)`；`<=0` 缺省为 `0.5` |
| QBER 判定阈值 | `QBERThreshold` | 否 | `(0,0.5)`；`<=0` 缺省为 `0.11` |
| 安全余量 (bit) | `SecurityMargin` | 否 | `>=0`；`0` 缺省为 `32`，负数非法 |
| 请求密钥字节数 | `RequestedKeyBytes` | 否 | `>=0`，`0` 表示“按可用材料尽量长”（整字节对齐） |
| 随机种子 | `Seed` | 否 | 相同种子 + 相同参数 ⇒ 结果逐比特一致 |

参数校验失败返回 `*qkd.ValidationError`，含 `Field` 与 `Reason`：

- `missing required value`：必填项缺失（如 `NumPhotons=0`、`DetectorEfficiency=0`）；
- `value out of range`：越界（如 `DarkCountProb>=1`、`SampleFraction>=1`）；
- `values contradict each other`：取值互相矛盾（如 `DarkCountProb >= 10^(-loss/10)*eff`，
  即暗计数概率不低于有效信号概率，筛选出的“事件”将不具信号意义）。

## 信道与窃听模型

1. 每个时隙 Alice 随机生成比特与制备基，Bob 随机选基；
2. 若启用窃听：Eve 随机选基测量后重发。选错基概率 1/2，选错时 Bob 在基匹配处
   再以 1/2 概率得到错误比特 ⇒ 筛后密钥中 **约 25% QBER**；
3. 信号光子以 `10^(-loss/10) * DetectorEfficiency` 的概率被探测；
4. 未探到信号光子的时隙以 `DarkCountProb` 产生暗计数，测得比特随机。
   暗计数落在基匹配位置时表现为筛后误码。

## 终止规则（安全条件）

1. 筛选后无任何事件 → `ErrNoSignal`；
2. **抽样误码率 `QBER > QBERThreshold` 判定为不安全**，立即返回 `*AbortError`，
   终止于误码估计之后、纠错之前，**不返回任何可推导密钥的中间材料**；
   规则为严格大于：`QBER == 阈值` 判安全（含），临界行为稳定；
3. 抽样后无剩余、纠错不收敛 → 显式错误终止；
4. 按账目口径可用密钥 `<= 0`，或不足 `RequestedKeyBytes`，或不足 1 字节
   → `ErrInsufficientKeyMaterial`。**绝不截断、补齐或静默降级**。

## 抽样口径（结论不漂移）

抽样下标完全由会话级随机源的 `Perm(sifted_len)` 前 `round(sifted_len*SampleFraction)`
个元素决定（升序取出），抽样比特公开比对后从密钥中丢弃。
抽样结果只依赖 `(种子, 筛后序列)`，与切片方式、遍历顺序等实现细节无关，
因此同一会话重复运行结论完全一致；丢弃策略固定为“抽样即消耗”。

## 误码纠正与隐私放大

- **纠错**：简化 Cascade——每轮洗牌分块，公开每块奇偶（1 次奇偶 = 1 bit 泄漏），
  不一致时二分定位并纠正；块大小逐轮翻倍，整轮无错误即收敛。
  公开的奇偶总数计入 `LeakedBits`；收敛失败显式报错。
- **信息泄漏估计**：`LeakedEst = ceil(after_sample * H2(QBER))`，
  `H2` 为二元熵（香农界口径，向上取整偏保守）。
- **隐私放大**：由会话随机源生成 Toeplitz 矩阵做通用哈希，输出长度由账目决定。

## 密钥账目口径（守恒）

```
Detected    <= Prepared
Sifted      <= Detected
Sifted      = Sampled + AfterSample
AfterSample = LeakedEC + LeakedEst + Margin + Final + Discarded
```

- `LeakedEC`：纠错实际公开的奇偶比特数；
- `LeakedEst`：基于抽样 QBER 的 Eve 信息估计；
- `Margin`：安全余量；
- `Final`：实际输出比特数；
- `Discarded`：满足请求长度/整字节对齐后**显式丢弃**的多余材料（不是静默浪费）。

最终可用长度 `FinalKeyLen = AfterSample - LeakedEC - LeakedEst - Margin`。
每次成功会话结束前都调用 `Ledger.Check()` 强制守恒校验，不守恒即内部错误，
不会输出密钥。

## 并发隔离

`Run` 的全部随机状态来自函数内部新建的 `*Source`（`math/rand` 每会话独立），
无任何包级可变状态；多个 goroutine 并行运行同种子会话得到相同结果、
不同种子互不影响（`go test -race` 覆盖）。

## 本地复现验证

```bash
# 1) 固定种子重复运行，密钥十六进制必须完全一致
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1

# 2) 确定性与并发隔离由单测保证
go test -race -v ./...
```

测试覆盖场景：无窃听（成功+守恒）、存在窃听（终止无密钥）、高损耗（无信号/
材料不足）、材料不足（显式拒绝）、固定种子重复一致、临界阈值、多会话并行；
单测日志打印每个场景的输入参数、账目、误码中间量与判定依据。

## 代码结构

| 文件 | 职责 |
|---|---|
| `config.go` | 参数定义、缺省语义与校验 |
| `random.go` | 会话级确定性随机源 |
| `channel.go` | 光子传输：损耗、效率、暗计数、拦截-重发 |
| `sift.go` | 基比对与筛选 |
| `qber.go` | 确定性抽样误码估计与窃听判定 |
| `reconcile.go` | 简化 Cascade 误码纠正与泄漏计数 |
| `privacy.go` | Toeplitz 隐私放大 |
| `account.go` | 密钥账目与守恒校验 |
| `session.go` | 全流程编排 |
| `cmd/qkdsim` | 本地可运行入口 |
