# Skill 消费契约 — 图谱事实 / 证据词汇与消费纪律（V1 / IR V2）

> 面向消费方 skill `ai-scan-concurrency`（independent extract 1.0.0）维护者。
> 本文档是 **skill 侧「消费契约」**，规范 skill 应当如何消费 ProvenLattice 图谱产出；
> 它 **不改变** 图谱任何生产/投影语义。图谱侧的「生产契约」是 FactBundle v2.1 schema 与
> Canonical Evidence IR V1 / IR V2 schema（见 `src/provenlattice/evidence_projection/schema/`）。
>
> 版本：`skill-interface-requirements-v1` · 对应 Issue #86（Agent/Skill API V1，阶段③ / 走法 B）
> 与 Issue #87（Canonical Evidence IR V2 + 五类并发事实 additive 投影）。
> 本文档只提需求，**不修改 SKILL.md 本体**。

## 0. 消费入口

| 入口 | 位置 | 返回 |
|---|---|---|
| 能力清单 | `provenlattice.evidence_projection.skill_api.list_skill_capabilities()` | 按 `defect_type` 组织的机器可读 manifest（`projected_facts` / `projected_evidence` / `not_projected_facts` / `not_produced_facts`），顶层另含 `ir_versions_supported` 与 `ir_v2`（IR V2 能力目录） |
| 证据接口 | `provenlattice.evidence_projection.skill_api.resolve_evidence(case_workdir, database, *, defect_type, target_symbols=(), run_context=None, ir_version="1", enable_deref=False, file_path=None, **kwargs)` | 经版本对应校验器（`validate_evidence_ir_v1` 或 `validate_evidence_ir_v2`）校验通过的 IR dict |

`resolve_evidence` 是薄 facade：`Registry → adapter → IR`，**不**重新实现投影。异常为 fail-closed：
未知 `defect_type` 抛 `UnknownDefectTypeError`；投影内部异常原样上抛；IR 校验失败抛
`EvidenceIRValidationError`，绝不返回未通过校验的 IR。

**版本协商（显式、fail-closed）**：`ir_version="1"`（缺省）返回冻结 IR V1；`ir_version="2"`
显式进入 IR V2（五类并发事实 additive 投影，需 `file_path`）；任何其它值抛
`UnknownIRVersionError`。**禁止按消费者能力自动猜测版本**，两条转换链路独立、分别校验、
互不修改返回对象（见 §6）。

## 1. 事实 / 证据词汇 ↔ skill §4 字段映射

### 1.1 `supporting_locations[]` — 13 字段（与 skill §4 完全对齐）

| 字段 | 含义 | 消费注意 |
|---|---|---|
| `file` | 源文件路径 | 空串表示未定位（unresolved） |
| `line` | 起始行号 | `0` 表示未定位；掩码行号见 §3 |
| `line_span` | `[start, end]` 行跨度 | 随 `file`/`line` 一起为空/`[0,0]` 时未定位 |
| `role` | 事实字段名（`shared_accesses` / `release_sites`） | 保留 v1 兼容键，不是语义角色 |
| `semantic_role` | 语义角色（见 §1.2） | **主语义键**，据此区分锚点/访问/释放点 |
| `anchor_class` | `primary` / `supporting` / `unresolved` | **主/支撑锚点区分**，见 §3 |
| `owner` | 访问所属 owner（reader/writer） | 可为空 |
| `access_type` | `READ` / `WRITE` / `READ_MODIFY_WRITE` / `RELEASE` / `UNKNOWN` / `""` | 空即未解析 |
| `source_fact_id` | 引擎事实/事件 ID | 空表示该位置无真实引擎事实 ID（不得自造） |
| `event_id` | 访问事件 ID | 与 `source_fact_id` 同为真实引擎 ID；不得自造 |
| `provenance` | 位置来源（`candidate.evidence_v2.access` 等） | 溯源审计用 |
| `candidate_key` | 候选绑定键 | **每个位置都必须绑定到真实候选**（非空） |
| `held_locks` | 该访问点持有的锁集合 | 为空数组表示无锁/未记录，**不是**「无竞态」 |

### 1.2 `semantic_role` 与 `anchor_class` 取值（与能力清单 `anchor_semantics` 一致）

| `semantic_role` | 含义 |
|---|---|
| `candidate_anchor` | 候选主锚点位置 |
| `racing_access` | 已定位的竞争访问（race_condition） |
| `held_lock` | 某访问点持有的锁 |
| `release_site` | 释放点（double_free） |
| `unresolved_location` | 无法解析的位置 |

| `anchor_class` | 含义 |
|---|---|
| `primary` | 候选唯一的**主锚点**，候选身份与溯源的主要依据 |
| `supporting` | **支撑**证据位置（如竞争访问），佐证但不等于主锚点 |
| `unresolved` | 未解析到真实 file/line |

### 1.3 `facts` 块 vs `projected_evidence`（不可混用）

- `projected_facts` = 已投影进 IR `facts` 块的**语义事实类型**（如 `shared_accesses` /
  `release_sites`），描述「发生了什么」（语义记录）。
- `projected_evidence` = 已投影的**证据/锚点位置结构**（`supporting_locations[]` /
  `evidence_locations[]` 的字段与 `anchor_class`/`semantic_role` 取值），描述「事实绑定到
  哪个源码位置」（证据绑定）。

skill 消费时：**语义判断**读 `facts` 面；**源码定位与溯源**读 `projected_evidence` 面。
不要用 `supporting_locations[]` 去推断事实语义，也不要用 `facts` 块去定位源码行。

## 2. 7 类事实现状声明（与能力清单 §B 逐字一致）

> 「produced」= 图谱**存在**该类事实生产者，**不保证每次查询都产出该事实**（是否出现取决于
> case 语义）。`produced_not_projected` 只描述投影状态，**不保证**任一具体 case 的查询结果里
> 必有该事实。skill **不得**据此推断「每个 case 都会收到这些字段」。

| skill §4 事实 | 投影状态 | 说明 / 语义限制（摘要） |
|---|---|---|
| `shared_accesses` | **已投影**（race_condition） | `access_type`/`lock_identity` 可能为空（unresolved） |
| `thread_context` | `produced_not_projected` | WaitForMultipleObjects → unknown；无 handle join 不产 subject；无一般 thread-instance 值流 |
| `parallel_feasibility` | `produced_not_projected` | 恒为 candidate，永不 resolved/decisive；ambiguous 是常态 |
| `common_locks` | `produced_not_projected` | `lock_identity` 可 inexact/unresolved；SAME/DIFFERENT 仅同一 subject 访问对间；RAII 保持 ambiguous |
| `spawn_join` | `produced_not_projected` | 需 handle_decl 相等 + 同 owner + spawn-before-join；否则不配对；WaitForMultipleObjects → unknown |
| `happens_before` | `not_produced` | 图谱**无**一阶 HB relation；IR V1 `relations==[]`；不得虚构 HB 事实 |
| `guarded_by` | `not_produced` | 图谱**无**一阶 GUARDED_BY relation；`held_locks`（逐点持有、恒 ambiguous）与 `protect`（锁保护访问）均**不**升级为字段级 GUARDED_BY 不变量；`protect` ≠ `guarded_by` |
| `interprocedural_path` | `produced_not_projected` | MAY_CALL fail-closed（仅 unique_same_file_assignment 给目标，ambiguous → []）；DEREF_RESOLVES_TO 受限消费 |

补充：`release_sites` 是 double_free 缺陷的已投影事实类型（`access_type=RELEASE`），不在 skill
§4 的 7 类并发事实清单内。double_free 属内存安全缺陷，位于并发事实词汇之外，故其
`not_projected_facts` / `not_produced_facts` 均为空（无并发缺口待声明）。

## 3. 消费纪律（强化）

1. **`UNSUPPORTED ≠ FALSE`**：`UNSUPPORTED` 表示「缺少所需支撑证据」，**不是**对该命题的反驳。
2. **`EMPTY ≠ 安全`**：空结果 / 终止态（`empty`/`failed`/`timeout`/`stale`/`not_built`）只表示
   「证据查询没有交付完整 ok 结果」，**绝不等于**「无缺陷 / 安全」。禁止把终止态当作安全结论。
3. **`anchor_class` 主/支撑锚点区分**：只有 `primary` 锚点是候选身份主依据；`supporting` 只是
   佐证。不要把支撑位置当成主锚点去定位候选。
4. **掩码行号回退**：消费方采用掩码行号（`adopted=0`）时，遇到 `file=""` / `line=0` /
   `anchor_class=unresolved` 的位置必须回退到不采用该行号，**不得**猜测或占位。
5. **事实「出现时如何用」**：`common_locks` / `spawn_join` / `held_locks` 等仅在真实出现时使用；
   不得因字段缺失而伪造「已出现」或反推安全结论。缺失即缺失，保持显式 unknown/unresolved。
6. **不自行派生关系**：图谱未投影的关系（如 `happens_before`）skill 不得自行补造；排序证据仅由
   `spawn_join_pairs` + MAY_PARALLEL 间接表示，skill 不得据此虚构一阶 HB 结论。

## 4. 前向兼容约定（6 类事实落地后如何无损升级）

6 类并发事实的 additive 投影属**另立 Issue**，落地后消费升级必须遵循：

1. **additive 不破坏 source_only**：新事实只**新增**到 `facts` 面 / `supporting_locations[]`，
   不删除、不改写既有字段与既有 `source_only` 消费路径。
2. **以 manifest 为准判定可用性**：skill 应先读 `list_skill_capabilities()`，据
   `projected_facts` 决定「当前能消费哪些事实」，**不要**硬编码假设某事实已投影。
3. **`produced_not_projected` 升为 `projected` 时**：仅在该事实实际出现于该 case 的结果中时使用；
   仍不得把「字段存在」当作「事实成立」（继续遵循 §3 的 UNSUPPORTED/EMPTY 纪律）。
4. **schema 演进**：任何新字段必须 additive（可空/可缺省），保持旧版 skill 仍能解析旧键；
   breaking change 由 owner 决策并单独发版，本文档不授权。

## 5. 依赖闭环与边界

- 本文档只依赖图谱已交付的四层：Registry（#83）、Canonical Evidence IR V1（#79）、
  FactBundle v2.1（#78），以及 Canonical Evidence IR V2（#87，见 §6）。不依赖、不 import
  skill 本体。
- 图谱侧不变：本文档不改 `source.py` / `projection.py` / `adapter.py` / `constants.py` /
  `factbundle_v2_1.schema.json`，不改 `ir.py` / `evidence_ir_v1.schema.json`，不触及
  Engine / parser / CFG / DFG / alias / HB / GT / Prompt / Skill / Scorer。

## 6. Canonical Evidence IR V2（#87）— 五类并发事实 additive 投影

IR V2 是 **新增的独立 IR**（`ir_schema_version="2"`，`run.projector_version="2"`），与冻结的
IR V1 并行，二者均不互相改写返回对象。它打通「候选识别之前即存在的**文件级**图谱事实」到
「Agent 可消费证据」之间的断层：File-level 事实/关系的 `candidate_id` 为 `null`（**不**表示
证据无效），候选绑定事实（`shared_access`）才引用真实候选 id。

### 6.1 类型化 Facts（6 类）与 Relations（8 类）

五类 skill 命名事实被分解为子结构级类型（字段映射逐项来源见映射矩阵）：

| 分类 | 类型 | 来源（Engine 生产入口） | confidence 约束 |
|---|---|---|---|
| Fact | `thread_entry_point` | `build_concurrency_context`（`thread_entry_points`） | `definite` |
| Fact | `thread_spawn` | 同上（`spawns`） | `definite` |
| Fact | `thread_join` | 同上（`joins`） | `definite` |
| Fact | `resource_lifetime` | 同上（`resource_lifetime`） | `candidate` |
| Fact | `may_parallel` | 同上（`may_parallel`） | `ambiguous`/`unresolved`（**永不 definite**） |
| Fact | `held_locks` | `build_access_lockset`（`access_locksets`） | `ambiguous`（**永不 definite**） |
| Fact | `shared_access` | FactBundle v2.1 基线（候选绑定） | `definite` |
| Relation | `spawn_join` | `build_concurrency_context`（`spawn_join_pairs`） | `definite`（仅 handle_decl+owner+顺序齐备） |
| Relation | `protect` | `build_access_lockset`（`PROTECTS`） | `ambiguous` |
| Relation | `unlock_omitted_on_path` | 同上（`UNLOCK_OMITTED_ON_PATH`） | `ambiguous` |
| Relation | `same_lock` | 同上（`SAME_LOCK`） | `ambiguous` |
| Relation | `different_lock` | 同上（`DIFFERENT_LOCK`） | `ambiguous` |
| Relation | `may_call` | `build_call_relation`（`call_relations`） | `unknown`/`unique_same_file_assignment`/`ambiguous_multiple_assignments` |
| Relation | `deref_resolves_to` | `build_deref_resolution`（`deref_resolves_to`） | `must`/`may`/`unknown`（三态，**不互升**） |
| Relation | `same_storage` | 同上（`same_storage`） | `must`（仅跨 owner 且双方 must） |

### 6.2 语义限制（必查，M4/M9）

- `held_locks` 是「锁在此访问上被持有」的**逐点观测**（Fact），`protect` 是「锁保护此访问」的
  Relation；**二者都不合成 GUARDED_BY**。
- `spawn_join` 是配对/协调关系（spawn-before-join），**不**合成 HAPPENS_BEFORE；排序证据仅由
  `spawn_join` + `may_parallel` 间接表示。
- `may_parallel` 恒为候选（`ambiguous`/`unresolved`），**永不**升级为确定并发结论。
- `coverage.not_produced == ["happens_before", "guarded_by"]` 显式列出，relations 中不出现二者。
- **DEREF 默认 OFF**：仅 `enable_deref=True` 才消费 `deref_resolves_to`/`same_storage`；
  `must`/`may`/`unknown` 三态不得互相升级（尤其 `may` 不升 `must`），解析失败不降级为猜测关系。
  manifest 的 `ir_v2.deref.default == "disabled"` 明确披露该默认关闭状态。

### 6.3 消费升级不必改 V1 路径

IR V2 仅经显式 `ir_version="2"` + `file_path` 到达，缺省仍是 IR V1（§0）。新增事实只落在 IR V2
的 `facts`/`relations`/`coverage`/`limitations`，不改写、不删除 IR V1 任何字段；旧 IR V1 消费者
（不改 `ir_version`）不受影响。
