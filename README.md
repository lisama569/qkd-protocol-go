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

# 运行一次会话（默认无窃听、种子 1；-mode 缺省为 run，旧用法完全不变）
go run ./cmd/qkdsim -seed 1 -n 4000 -loss 5 -eff 0.9 -dark 0.0001 -key 16

# 模拟窃听（拦截-重发），会话将被终止且不输出密钥
go run ./cmd/qkdsim -seed 1 -n 4000 -eve

# 容量预估：复用同一套会话参数，只评估不输出密钥
go run ./cmd/qkdsim -mode estimate -seed 1 -n 4000 -key 16

# 批量会话：JSON 文件给出多组参数（-jobs - 从标准输入读取）
go run ./cmd/qkdsim -mode batch -jobs cmd/qkdsim/testdata/jobs.json -workers 4
```

CLI 在**同一个 `qkdsim` 二进制**内通过 `-mode` 选择入口，不拆分为独立工具：

| `-mode` | 入口 | 说明 |
|---|---|---|
| `run`（缺省） | 单会话 | 参数、默认值、输出与历史版本逐字一致 |
| `estimate` | 容量预估 | 复用单会话全部参数（`-n/-loss/-eff/-dark/-eve/-sample/-threshold/-margin/-key/-seed`），输出公开口径结论，不产出密钥 |
| `batch` | 批量会话 | 另用 `-jobs`（JSON 数组文件，`-` 表示 stdin）与 `-workers`（默认 4），逐组输出审计，成功组另打印密钥 |

批量 JSON 为一个数组，元素字段名与单会话 flag 同名（除 `n/eff` 必填外缺省即 0/缺省语义）：

```json
[
  {"name":"success","n":4000,"loss":5,"eff":0.9,"dark":0.0001,
   "sample":0.5,"threshold":0.11,"margin":32,"key":16,"seed":1},
  {"name":"abort","n":4000,"loss":5,"eff":0.9,"dark":0.0001,
   "eve":true,"key":16,"seed":1}
]
```

CLI 会打印输入参数、误码估计、纠正统计与密钥账目，成功时输出十六进制密钥。
**单会话（`run`）的行为、参数名、默认值不因新增模式而改变。**

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
3. **抽样阶段就把筛后材料全部抽光**（抽样后无剩余）→ 停在 `qber_estimate`
   阶段并显式报 `ErrInsufficientKeyMaterial`；纠错不收敛 → 停在 `reconcile` 阶段；
   二者都不会被误记到账目阶段；
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

结局类别（`Audit.Outcome`）稳定可机读。**阶段（`Audit.Stage`）一律按错误实际发生、
会话真实到达的阶段归类**（错误在内部携带阶段标记），而不是按错误类型套用固定阶段：

| 类别 | 含义 | 典型最远阶段 |
|---|---|---|
| `success` | 成功出钥 | `privacy_amplify` |
| `invalid_config` | 参数不可行（缺失/越界/矛盾） | `validate` |
| `no_signal` | 筛选后无可用事件（无可用信号） | `sift` |
| `aborted_insecure` | QBER 超阈值，安全判定终止 | `qber_estimate` |
| `reconcile_failed` | 纠错未收敛 | `reconcile` |
| `insufficient_material` | 材料不足，细分见 `Detail` | 抽样阶段抽光时为 `qber_estimate`；账目口径不足时为 `accounting` |
| `internal_error` | 实现内部非预期故障 | 错误实际发生阶段（缺省 `accounting`） |

例如抽样比例把筛后比特全部抽光时，流程停在 `qber_estimate`，审计即为
`outcome=insufficient_material detail=exhausted stage=qber_estimate`，
不会错记成账目阶段；容量预估同参报告同一阶段。

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

- 只含：参数摘要 `ParamSummary`、实际到达阶段 `Stage`、结局类别 `Outcome/Detail`、
  公开计数 `PublicCounts`（制备/探测/筛后/抽样/抽样后/纠错泄漏/估计泄漏/余量/最终/丢弃）、
  QBER 与阈值、以及最终密钥**长度** `KeyBits`；
- **结构上不含**纠正后比特、筛后可用比特、最终密钥等任何可推导密钥的材料
  （单测以反射白名单保证审计结构无任何 `[]byte/[]int` 切片，并断言序列化文本不出现密钥）；
- 换失败路径不会混入敏感中间量：无信号时也保留 `Prepared` 等公开计数，成功失败同一结构。
- **内部错误脱敏（修订口径）**：对所有非已知类别（`internal_error`）的非预期内部错误，
  审计**绝不转发 `err.Error()` 原文**——内部实现的错误文本可能夹带纠正后比特、筛后比特或
  最终密钥。对外只保留固定机器类别 `internal_error` 与固定公开说明
  `InternalErrorPublicReason`（"internal error: unexpected implementation failure;
  no key material released"），阶段仍可用于定位。已知类别错误（参数校验、无信号、窃听终止、
  纠错失败、材料不足）的文案只含公开数值，按原文透传。容量预估的失败说明共用同一脱敏函数。

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
- **判定阈值语义（修订口径）**：`CapacityEstimate.QBERThreshold` **始终等于本次真正生效的
  判定阈值**（配置显式给出的值，或经缺省补全后的 `DefaultQBERThreshold`），并且与
  `Params.QBERThreshold` 逐位相同。它：
  - **不随实测误码率 `QBER` 漂移**（预估展示的阈值就是本次窃听判定实际采用的阈值）；
  - **参数非法（`invalid_config`）或流程很早结束（`no_signal` 等）时也不会变成 0**；
  - 无论预估成功还是各类失败，阈值字段都一致、可得。
- 结论 `Verdict`：`feasible` / `invalid_config` / `no_signal` / `aborted_insecure` /
  `reconcile_failed` / `exhausted` / `low_yield` / `insufficient_for_target` /
  `internal_error`（内部错误同样使用固定公开说明，不转发可能含敏感比特的原文）。
  其中 **“还有可能出更短钥”的 `low_yield`、`insufficient_for_target` 与
  “参数矛盾”的 `invalid_config`、“不可能出钥”的 `exhausted` 严格区分**，不会笼统归并。
- `CapacityEstimate` 全部字段为公开口径，结构上无任何比特序列（单测反射保证）。

## 本地复现验证

```bash
# 1) 固定种子重复运行，密钥十六进制必须完全一致（run 为缺省模式）
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1

# 2) 容量预估：观察“生效阈值”在成功/各类失败下恒等于参数阈值，不随实测 QBER 变
go run ./cmd/qkdsim -mode estimate -seed 1 -n 4000 -key 16
go run ./cmd/qkdsim -mode estimate -seed 1 -n 4000 -key 100000   # 目标过大：不缩短
go run ./cmd/qkdsim -mode estimate -seed 1 -eff 2                # 参数非法：阈值仍为 0.1100

# 3) 批量：改 -workers 只改变调度，每组结论/计数/密钥逐项一致
go run ./cmd/qkdsim -mode batch -jobs cmd/qkdsim/testdata/jobs.json -workers 1
go run ./cmd/qkdsim -mode batch -jobs cmd/qkdsim/testdata/jobs.json -workers 8

# 4) 全部自动化测试（含竞态检测与命令行入口测试）
go test -race -count=1 ./...
```

测试覆盖除原有场景（无窃听成功+守恒、窃听终止无密钥、高损耗、材料不足、
固定种子重复一致、临界阈值、多会话并行）外，新增/修订：

- **预估阈值一致性**：成功、目标为 0、目标过大、窃听终止、无信号、参数非法、账目耗尽、
  抽样阶段抽光等结局下，`QBERThreshold` 都等于本次生效阈值且与 `Params` 摘要一致，
  绝不跟实测 QBER 变、绝不变成 0；并校验自定义阈值被如实采用、入参不被修改、
  `RequestedBits` 不被静默缩短；
- **内部错误脱敏**：向审计注入文本中含纠正后比特/筛后比特/最终密钥的任意内部错误，
  断言原文与敏感片段不出现在 `Reason`/`String()` 中，只有固定类别与固定公开说明；
  携带阶段标记的内部错误同样脱敏但阶段保留；
- **抽样抽光阶段归类**：`n=200, sample=0.999` 等夹具下筛后材料被全部抽光，
  审计为 `insufficient_material/exhausted` 且 `stage=qber_estimate`，容量预估同阶段；
- **批量分组顺序 × 并发度矩阵**：多种分组排列（含重复参数组）× 多种 worker 数，
  同一参数组的审计逐字段一致、密钥逐字节一致，且结果始终按提交下标落位；
  并校验批量每组审计阈值为该组生效阈值；
- **命令行入口**：`run`（含窃听失败）、`estimate`（含非法参数/负目标退出码）、
  `batch`（文件/stdin、坏参数、并发度可复现）均有进程级测试直接驱动，本地可直接复现。

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
| `session.go` | 全流程编排；抽出 `prepareSession` 共享内核供真实执行与容量预估复用；失败携带实际阶段标记 |
| `audit.go` | 统一公开审计：参数摘要、阶段、结局类别、公开计数；内部错误固定说明脱敏（结构上不含密钥材料） |
| `capacity.go` | 目标容量预估：不出钥判定可行性/材料/公开消耗/生效阈值与不足原因 |
| `batch.go` | 批量会话：固定 worker 池、按提交下标落位、每组隔离可复现 |
| `cmd/qkdsim` | 本地入口（同一二进制内 `-mode run|estimate|batch`；`run` 行为不变） |
| `cmd/qkdsim/testdata/jobs.json` | 批量模式示例参数组（成功/窃听/无信号/抽样抽光） |

## 兼容性说明

- **单会话完全兼容**：`Run`、`Result`、`Config`、错误（`*AbortError`、`ErrNoSignal`、
  `ErrInsufficientKeyMaterial`、`ErrReconciliationFailed`）及同种子出钥结果**保持不变**；
  CLI 不带 `-mode` 即等价于旧的单会话调用，参数名、默认值（`-n 4000 -loss 5 -eff 0.9
  -dark 0.0001 -sample 0.5 -threshold 0.11 -margin 32 -key 16 -seed 1`）与输出逐字保留。
- 本次修订仅改变两处**对外审计/预估文本口径**（更严格，不改变执行与出钥）：
  1. 容量预估 `QBERThreshold` 由“复制实测 QBER（早期失败时为 0）”改为“恒等于本次生效阈值”；
  2. `internal_error` 的 `Reason` 由转发内部原文改为固定公开说明。
  已知类别错误（窃听终止、无信号、材料不足等）的文案与阶段归类对常规路径保持不变；
  唯一细化的是“抽样阶段抽光材料”这类失败的 `Stage`，由笼统的 `accounting`
  修正为真实的 `qber_estimate`（结论类别仍是 `insufficient_material`）。
- 批量、审计、容量预估与 CLI 的 `-mode estimate/-mode batch` 均为在同一工程、同一二进制上的
  增量能力，复用既有 `Config`、构建方式与结果口径；**没有引入第二个独立工具**，
  既有调用方与单会话命令行无需任何改动。
