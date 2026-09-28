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

## 批量会话（调参与回归）

`RunBatch(jobs, workers)` 在同一工程内提供面向调参/回归的批量能力，**不是独立工具**，
沿用既有 `Config`、构建方式与随机口径。

- 入参：`[]BatchJob{Name, Cfg}` 与并发度 `workers`（`<=0` 顺序执行；超过任务数按任务数计）。
- 隔离：每组调用独立 `Run`，随机源由该组自身 `cfg.Seed` 新建，账目、结论、密钥不跨组共享。
- 可复现：结果**按提交下标落位**，改变分组顺序只改变下标位置，改变 `workers` 只改变调度；
  同一参数组的结局、公开计数、审计与密钥逐项一致。
- 统一结果形态 `BatchOutcome{Index, Name, Audit, Key, Err}`：成功与各类失败同构。
  `Key` 是唯一敏感字段（仅成功非空），刻意与 `Audit` 分离，审计里只有密钥**长度**。

结局类别（`Audit.Outcome`）稳定可机读：

| 类别 | 含义 | 最远阶段 |
|---|---|---|
| `success` | 成功出钥 | `privacy_amplify` |
| `invalid_config` | 参数不可行（缺失/越界/矛盾） | `validate` |
| `no_signal` | 筛选后无可用事件（无可用信号） | `sift` |
| `aborted_insecure` | QBER 超阈值，安全判定终止 | `qber_estimate` |
| `reconcile_failed` | 纠错未收敛 | `reconcile` |
| `insufficient_material` | 材料不足，细分见 `Detail` | `accounting` |

材料不足细分 `Audit.Detail`：`exhausted`（账目可用比特 `<=0`，不可能出钥）、
`low_yield`（有正材料但不足 1 字节，收益过低）、
`insufficient_for_target`（**能出更短的钥但达不到显式目标**，不自动缩短、不静默降级）。

```go
outs := qkd.RunBatch([]qkd.BatchJob{
    {Name: "low-loss", Cfg: cfgA},
    {Name: "eavesdrop", Cfg: cfgB},
}, 4)
for _, o := range outs {
    fmt.Println(o.Index, o.Name, o.Audit.Outcome, o.Audit.Detail, o.Audit)
}
```

## 安全失败审计

`NewAudit(cfg, result, err)` 对**成功与所有失败路径**产出统一公开口径的 `Audit`：

- 只含：参数摘要 `ParamSummary`、最远阶段 `Stage`、结局类别 `Outcome/Detail`、
  公开计数 `PublicCounts`（制备/探测/筛后/抽样/抽样后/纠错泄漏/估计泄漏/余量/最终/丢弃）、
  QBER 与阈值、以及最终密钥**长度** `KeyBits`；
- **结构上不含**纠正后比特、筛后可用比特、最终密钥等任何可推导密钥的材料
  （单测以反射白名单保证审计结构无任何 `[]byte/[]int` 切片，并断言序列化文本不出现密钥）；
- 换失败路径不会混入敏感中间量：无信号时也保留 `Prepared` 等公开计数，成功失败同一结构。

## 目标容量预估（不出钥）

`EstimateCapacity(cfg, targetKeyBytes)` 在**不输出最终密钥**的情况下判断参数是否值得运行。

- 不修改传入 `cfg`：显式目标 `targetKeyBytes` 只作用于内部克隆；`<0` 返回
  `ErrInvalidTarget`，`0` 表示“尽量长”评估。**不会自动缩短目标或静默降级**。
- 与 `Run` 共用同一条 `prepareSession` 判定路径（同种子、同随机消耗顺序，但不做隐私放大），
  因此边界一致：`feasible` ⇔ `Run` 必成功且密钥长度 `== ExpectedKeyBits`；
  其余结论 ⇔ `Run` 在同一阶段以同一类别失败。
- 给出预计可用材料 `AvailableBits`、整字节对齐量 `ByteAlignedBits`、
  主要公开消耗（抽样 `Sampled`、纠错泄漏 `LeakedEC`、估计泄漏 `LeakedEst`、余量 `Margin`）
  与可区分的不足原因 `Reason`。
- 结论 `Verdict`：`feasible` / `invalid_config` / `no_signal` / `aborted_insecure` /
  `reconcile_failed` / `exhausted` / `low_yield` / `insufficient_for_target`。
  其中 **“还有可能出更短钥”的 `low_yield`、`insufficient_for_target` 与
  “参数矛盾”的 `invalid_config`、“不可能出钥”的 `exhausted` 严格区分**，不会笼统归并。
- `CapacityEstimate` 全部字段为公开口径，结构上无任何比特序列（单测反射保证）。

## 本地复现验证

```bash
# 1) 固定种子重复运行，密钥十六进制必须完全一致
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1

# 2) 确定性、并发隔离、批量可复现、审计口径、容量一致性由单测保证
go test -race -v ./...
```

测试覆盖除原有场景（无窃听成功+守恒、窃听终止无密钥、高损耗、材料不足、
固定种子重复一致、临界阈值、多会话并行）外，新增：

- **批量并发隔离**：批内重复参数组并发执行，结果与单独 `Run` 逐字节一致、互不串状态；
- **分组顺序可复现**：打乱提交顺序、切换并发度（顺序/1/2/4/超大），同参数组结果逐项一致；
- **安全失败审计**：成功与各失败路径审计口径一致，反射白名单 + 文本断言保证不泄露
  纠正后比特/筛后比特/最终密钥，且无信号路径仍保留公开计数；
- **容量预估一致性**：跨光子数/损耗/窃听/目标的穷举扫描，预估结论与真实执行结局
  一一对应，`feasible` 时预计长度等于实际出钥长度，材料不足三种子类与真实 `Detail` 一致；
  并校验预估不修改入参、不静默缩短目标。

单测日志打印每个场景的输入参数、公开审计行、账目与判定依据；审计行中不含任何密钥材料。

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
| `session.go` | 全流程编排；抽出 `prepareSession` 共享内核供真实执行与容量预估复用 |
| `audit.go` | 统一公开审计：参数摘要、阶段、结局类别、公开计数（结构上不含密钥材料） |
| `capacity.go` | 目标容量预估：不出钥判定可行性/材料/公开消耗与不足原因 |
| `batch.go` | 批量会话：固定 worker 池、按提交下标落位、每组隔离可复现 |
| `cmd/qkdsim` | 本地可运行入口（单会话，行为不变） |

## 兼容性说明

- 单会话入口 `Run`、`Result`、`Config`、错误（`*AbortError`、`ErrNoSignal`、
  `ErrInsufficientKeyMaterial`）及同种子出钥结果**保持不变**；批量、审计、容量预估均为
  在现有工程上的增量 API，既有调用方与 CLI 无需改动。
- 新增 `ErrReconciliationFailed` 用于把“纠错未收敛”标为可区分失败类别（错误文案与历史一致）。
