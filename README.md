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

# 运行一次会话（默认无窃听、种子 1；无子命令等价于 run）
go run ./cmd/qkdsim -seed 1 -n 4000 -loss 5 -eff 0.9 -dark 0.0001 -key 16

# 模拟窃听（拦截-重发），会话将被终止且不输出密钥
go run ./cmd/qkdsim -seed 1 -n 4000 -eve

# 批量会话（多组参数，-c 并发度，组间互不串扰）
go run ./cmd/qkdsim batch -c 4 -g "-seed 1 -n 4000 -key 16" -g "-seed 2 -eve"

# 容量预估（不产出密钥，只给可行性/公开消耗/缺口）
go run ./cmd/qkdsim capacity -seed 1 -n 1000 -key 32
```

CLI 会打印输入参数、误码估计、纠正统计与密钥账目；单会话成功时输出十六进制
密钥，失败时打印统一结局类别/阶段/公开计数（审计口径）。

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

`RunBatch(items, opts)` 一次提交多组信道/协议参数，每组独立跑完整流程，
并以**统一形态** `GroupResult` 说明结局：

| Category | 含义 |
|---|---|
| `success` | 成功出钥（`Result.Key` 非空） |
| `aborted` | 抽样 QBER 超阈值，安全判定终止 |
| `no_signal` | 筛选后无可用信号（如高损耗） |
| `insufficient_material` | 材料不足 / 不满足目标长度 |
| `reconcile_failed` | 误码纠正未收敛 |
| `invalid_config` | 参数不可行（字段级 `ValidationError`） |
| `internal` | 其他内部错误（审计不转发其裸文本） |

- **隔离**：每组就是一次独立 `Run`，随机源在其内部按各自 `Seed` 新建，
  账目为局部值；随机状态、账目与结论不跨组串扰。
- **可复现**：worker 只把结果写回该组的**固定下标**，因此改变分组顺序
  （按 `Name`/参数匹配）或并发度（`BatchOptions.Concurrency`，`<=0` 为顺序），
  同参数组的结果仍**逐项一致**；返回切片始终与输入等长、按下标对齐。
- 每个 `GroupResult` 都带一份统一公开口径的 `Audit`（见下）。

CLI（同一入口、同一构建，不是独立工具）：

```bash
go run ./cmd/qkdsim batch -c 4 \
  -g "-seed 1 -n 4000 -key 16" \
  -g "-seed 2 -eve" \
  -g "-seed 3 -loss 60 -dark 1e-12"
```

## 安全失败审计（公开口径）

`AuditOf(cfg, result, err)` 产出 `AuditRecord`。无论成功还是失败，
记录只包含四类**公开**信息：

1. 参数摘要 `ParamSummary`（按缺省生效口径）；
2. 结局类别 `Category` 与终止/完成阶段 `Stage`；
3. 公开计数 `Ledger`（各阶段比特**数量**）与误码统计 `QBEREstimate`（计数与比率）；
4. 成功时最终密钥的**字节数**（仅长度）。

**绝不包含**纠正后的比特序列、筛后可用比特、Toeplitz 种子、最终密钥本身等
可直接推导密钥的材料——这一点在测试里以**类型结构反射扫描**强制：
`AuditRecord`/`CapacityEstimate` 在类型层面就不允许出现 `Key`/`Bit`/`Measured`
等字段，任何失败路径都无法借道混入敏感中间量。失败 `Reason` 为固定口径短语，
不转发可能携带中间量的内部错误文本。需要密钥的调用方使用 `Run` 的返回值
（私密通道）；只应看到公开口径的消费者只拿 `AuditRecord`。

## 目标容量预估（先判断值不值得跑）

`EstimateCapacity(cfg, targetKeyBytes)` 在**不走到隐私放大、不产出密钥**的
前提下给出 `CapacityEstimate`：

- `Feasible`：目标能否**严格**满足；
- `KeyPossible` / `MaxKeyBytes`：不限目标时是否仍可产出 `>=1` 字节、最多多少字节；
- `AvailableBits`：账目口径预计可用比特；`ShortfallBits`：距目标的缺口；
- `Cost PublicCost`：制备/探测/筛后/抽样/纠错泄漏/Eve 估计/余量等主要公开消耗；
- `Category` + `Reason`：可区分的结论与原因。

**与真实执行不矛盾**：预估与 `Run` 共用同一条阶段流水线 `preparePipeline`
和同一个纯函数 `decideKeyLength`，所以 `Feasible==true` 当且仅当以
`RequestedKeyBytes=target` 真实 `Run` 成功，且计划输出长度等于真实密钥长度。

- 仍可能出钥、只是材料不足或收益很低的配置归类为 **`low_yield`**
  （对应真实执行的 `insufficient_material`），**不**笼统归成参数矛盾；
- **绝不**为了让结果好看而自动缩短目标或静默降级：目标原值保留在
  `TargetKeyBytes`，达不到就是达不到；
- 非法目标（负数）按 `invalid_config` 处理。

```bash
go run ./cmd/qkdsim capacity -seed 1 -n 1000 -key 32
# feasible=false keyPossible=true 可用=28bit 最多=3 字节 缺口=228bit → low_yield
```

## 本地复现验证

```bash
# 1) 固定种子重复运行，密钥十六进制必须完全一致
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1
go run ./cmd/qkdsim -seed 123 -n 4000 | tail -1

# 2) 批量：换并发度 / 调顺序，同参数组结论逐项一致
go run ./cmd/qkdsim batch -c 1 -g "-seed 1 -n 4000" -g "-seed 2 -eve"
go run ./cmd/qkdsim batch -c 8 -g "-seed 2 -eve" -g "-seed 1 -n 4000"

# 3) 容量预估与真实执行边界一致（单测强制）
go run ./cmd/qkdsim capacity -seed 1 -n 1000 -key 32   # low_yield，不出钥

# 4) 确定性、并发隔离、审计不泄密、容量一致性由单测保证
go test -race -v ./...
```

测试覆盖场景：无窃听（成功+守恒）、存在窃听（终止无密钥）、高损耗（无信号/
材料不足）、材料不足（显式拒绝）、固定种子重复一致、临界阈值、多会话并行；
以及新增的：

- **批量并发隔离**：同种子组在批次中与独立 `Run` 结果一致，组间无串扰；
- **分组顺序/并发度可复现**：顺序、2/4/8/100 并发下逐组 `Audit`/账目/密钥一致；
- **安全失败审计不泄密**：反射扫描审计/容量结构，确认无 `Key`/`Bit`/`Measured`
  字段；成功与失败同形态同口径；
- **容量预估边界一致**：多组参数 × 多个目标下 `Feasible ⇔ Run 成功`，
  计划长度等于真实长度；`low_yield` 独立成类且不缩短目标。

单测日志打印每个场景的输入参数、账目、公开计数与判定依据。

## 兼容范围

- 新增能力是库内追加（`RunBatch` / `AuditOf` / `EstimateCapacity`），
  不改变 `Run`、`Config`、`Ledger`、`Result` 的既有语义与成功/失败边界；
- 唯一小调整：纠错不收敛由匿名错误改为哨兵 `ErrReconcileFailed`
  （仍是非 nil error、仍不输出密钥），便于审计区分失败类别；
- CLI 默认无子命令时等价于原 `run`，原有命令行用法保持可用。

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
| `audit.go` | 统一结局分类与公开口径审计记录 |
| `capacity.go` | 目标容量预估（复用流水线，不出钥） |
| `batch.go` | 批量会话：按下标对齐的并发执行与隔离 |
| `session.go` | 全流程编排（抽出共享流水线与出钥判定） |
| `cmd/qkdsim` | 本地可运行入口：`run` / `batch` / `capacity` 子命令 |
