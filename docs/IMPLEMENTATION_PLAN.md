# snapquiz v3 实施计划（Phase 1 优先多模态）

> **状态**：Active
>
> **实施基线**：`2026-08-31`，W06/W07 已进入本地及远端 `main`
>
> **工作区实现快照**：M0–M4/W07 的离线合同已完成、提交并推送；M5–M9 未开始。除用户已有的 `README.md` 改动外，W07 提交后工作区干净。应用仍被有意冻结，没有真实截图、出站传输或可执行解题链。
>
> **规范来源**：[`ARCHITECTURE.md`](./ARCHITECTURE.md) 是目标行为与安全约束的唯一规范；本文只负责依赖顺序、工作包、状态和验收证据，不能弱化 Spec。

## 1. 交付目标与边界

当前目标是先把 `direct_multimodal` 做成可扩展且 fail-closed 的安全主干，再接入第二个不同协议族的多模态模型。`ocr_text` 只保留领域边界，Phase 2 前不进入运行时路由。

Phase 1 的完成条件不是“能调用两个模型”，而是：

1. 真实用户截图只能沿不可绕过的 `Plan → PrivacyGate/Consent → PermissionGate → 明确选区/捕获 → PreparedOutbound 实际预览 → 逐次 EgressApproval → 受控传输` 链发送；截图前的数据政策同意与截图后的实际 payload 批准是两层不同授权；
2. Adapter 只做纯 `prepare/decode`，不能读取密钥、创建客户端、联网或自行重试；
3. GLM 与至少一个不同协议族的 exact binding 分别通过 contract、安全、非敏感 live smoke、统一 eval 与当前 macOS E2E；
4. 只有达到 Spec 的完整门槛才能标记为 `supported`，此前一律是 `experimental`。

## 2. 当前基线与迁移原则

MVP-0 的 45 个 `unittest` 是当前行为刻画，不是 v3 的兼容门槛。以下行为与 v3 目标冲突，迁移时必须有意识地反转或删除对应测试：

| 当前行为 | 风险 | v3 目标 |
|---|---|---|
| 权限 API 导入/调用异常时返回允许 | fail-open | `granted / denied / unknown` 三态，非 granted 全部阻断 |
| 未配置区域时默认捕获主屏全屏 | 远程数据范围扩大 | Phase 1 remote/unknown 只允许明确选区 |
| 启动时读取密钥并构造 OpenAI client | 绕过逐次出站批准 | approval 成功且原子消费后才解析 secret/构造 client |
| Capture 层生成 OpenAI Data URI | Provider 协议侵入核心 | Capture 只产出 bytes 与元数据，序列化属于 Adapter |
| Provider 同时 prepare/send/retry/decode | 无法核对获批 payload，重试可能叠加 | 纯 Adapter + exact-envelope Transport + 单一预算 |
| `{}`、缺字段或自然语言 fallback 可展示 | 坏输出冒充结果并泄露 raw | 严格 `SolveResult` 或 typed error，永不展示 raw response |
| 展示模型自报 confidence 百分比 | 把主观自评伪装成可靠度 | 未校准数值不展示；仅 calibrated score 可数值化 |

迁移采用“离线新链并行建立，安全门禁完成后一次切换入口”的方式。旧 `GLMProvider.answer(image_data_url)` 不作为兼容 API，也不能在新链旁保留为隐藏旁路。

## 3. 不可跨越的全局门禁

- **真实用户截图**：M0–M6 全部通过前禁止远程发送；M6 只能使用仓库内固定、非敏感合成题图。
- **普通测试**：禁止真实 secret、SDK client、DNS、socket、HTTP、真实屏幕捕获和生产响应录制。
- **批准顺序**：实际 outbound bytes 生成后才能预览和批准；批准必须 one-shot、原子消费，并绑定 request/plan/stage/operation、endpoint、应用控制的非密钥 headers、body、credential injection slot/binding digest、capture fingerprint 和所有策略 digest。真实 secret 值只在 approval 消费后注入，既不进入 approval，也不进入 envelope digest；`Host`、`Content-Length` 等库派生 header 由 Transport policy 重算并核验。
- **密钥顺序**：EgressApproval 消费前 secret resolve 和 client construction 必须均为 0。
- **网络边界**：只允许计划内 exact scheme/host/port/path/query/content-type/header；3xx fail-closed；SDK 自动 retry 必须关闭。
- **调用预算**：所有 attempt 共用 monotonic deadline、总网络次数、总计费次数和取消状态；Adapter 不持有自己的重试循环。
- **结果边界**：模型输出先成为不可信 candidate；只有本地严格 Validator 能构造 `SolveResult`。
- **状态声明**：单次 smoke 成功不能晋级 `supported`；配置文件也不能自我声明 supported。

## 4. 里程碑与验收

状态值：`pending`、`in_progress`、`complete`、`blocked`。只有代码和对应证据都存在时才能标记 complete。

| Milestone | 状态 | 范围 | Exit gate |
|---|---|---|---|
| Spec-0 | complete | v3 双通道规范、多模型边界、安全顺序与支持门槛 | 架构和安全 P0/P1 复核为 0；Spec 自洽 |
| M0 | complete | 冻结 MVP-0 真实截图远程旁路 | 所有可达入口无 v3 plan/gate 时均不能 capture、resolve secret、构造 SDK 或联网；fixture-only 入口也不能读取屏幕/真实 key |
| M1 | complete | 纯领域契约、typed errors、canonical digest、严格结果 Validator | 纯标准库测试；无 Quartz/mss/OpenAI import；malformed 输出全拒绝；digest golden vectors |
| M2 | complete | Registry snapshot、能力、Planner、Consent/Authorization、可信 endpoint profile | 截图前得到不可变单-stage Plan；未知 capability/endpoint 拒绝；policy unknown 分维度额外确认；compute unknown 按 remote 约束 |
| M3 | complete | fail-closed 权限、明确选区合同、CapturePolicy、InputValidator、引用清理 | 纯离线权限/拓扑/一次性授权/真实 PNG 解码负向矩阵通过；零真实 capture/secret/SDK/network |
| M4 | complete | 纯 GLM/OpenAI-compatible Adapter 与 typed response/error mapping | prepare/decode 零 I/O；request/response fixtures 和 golden envelope 全通过 |
| M5 | pending | Egress、session、Transport、预算、取消、授权租约、延迟密钥与统一清理 | 完整负向矩阵；approval 并发只能一次成功；每次 attempt 重验 valid_until/撤销；exact envelope；无 redirect/隐式 retry |
| M6 | pending | GLM 固定合成题图 opt-in live smoke | 单次、无自动 retry；记录非内容证据；仍为 experimental |
| M7 | pending | macOS 真实选区接入同一安全链 | 实际发送图可预览；取消零网络；完整 E2E；无旧旁路 |
| M8-A | pending | 第二个不同协议族多模态 Adapter | 核心无 Provider 分支；独立 credential binding；结构化输出降级链；contract/security/synthetic live 通过，保持 experimental |
| M8-B | pending | 两个 binding 的正式支持证明与选择 UX | profile selector + 启动披露；两个 binding 的统一 eval、当前 macOS E2E 与 supported 证据全部留存 |
| M9 | pending | Phase 1C 多模态学习 UX | 图形选区/NSPanel、题面先确认、缓存/预算、错题本及查看删除路径完成验收 |

Phase 映射：Phase 1A = M0–M7；Phase 1B = M8-A/M8-B；Phase 1C = M9；Phase 2 才实现 `ocr_text`。

### M0：冻结遗留远程路径

交付：

- stdin、hotkey、`app/orchestrator` 及所有可达 legacy Provider 调用在 v3 pipeline 未就绪时 fail-closed；
- 如需保留开发演示，只允许明确的 fixture-only 入口，且不能读取屏幕或真实 key；
- 为 capture、secret resolve、SDK construct、DNS/socket/HTTP 建立统一副作用探针；
- 更新旧测试，不再把任意 endpoint、默认全屏或通用异常自动重试当作兼容行为。

非目标：不在 M0 内实现新 Provider，不运行真实 API，不使用真实截图 smoke。

当前证据：CLI 的 stdin/hotkey 参数路径均只返回 legacy-disabled 错误并以退出码 `3` 结束；poison-import 与副作用探针证明产品入口未导入/调用 dotenv、Quartz、mss、pynput、OpenAI SDK、DNS、socket 或 HTTP。旧 `Config`、权限、parse/notify 与 `AnswerResult` 仍在源码树中但不可达；后续里程碑不得复用其 secret dataclass、fail-open 权限或 raw fallback 行为。

### M1：纯领域契约

拆分为：

- **M1-A**：canonical digest、`CaptureScope/CaptureArtifact`、typed errors、`SolveResult` 与严格 Validator；
- **M1-B**：`PolicySnapshot`、`SolveIntent`、不可变 `ExecutionPlan`、`PreparedOutbound` 等剩余纯领域类型；
- **M1-C**：所有 digest 的固定 golden vectors、Unicode/字段顺序/数值/类型域分离测试与模块 import 边界测试。

| 子里程碑 | 状态 | 当前证据 |
|---|---|---|
| M1-A | complete | 新领域/结果模块保持纯标准库；strict result、provenance、capture integrity 与 safe error boundary 测试通过 |
| M1-B | complete | Policy/Intent/Plan/Outbound 契约、预算与 consent 绑定、Phase 1 direct 形状、envelope 完整性、runtime-final/type-exact 边界通过 |
| M1-C | complete | serializer、CaptureScope、ExecutionPlan、body/header/envelope golden；Unicode/顺序/数值/类型域/import、篡改、URL 与序列化泄露负向测试通过 |

验收：

- 空对象、缺字段、`null` 字符串化、错误类型、非有限数、超长字段、未知字段均失败；
- model-self-reported confidence 不能被标为 calibrated；
- domain/result 测试在未安装 OpenAI、mss、Quartz 时仍可运行；
- raw Provider response 不进入 `SolveResult`。

M1 的 URL 工作只证明无 I/O 的规范形与明显 scope 不变量，不证明 endpoint 获准或 DNS 安全。Phase 1 只允许空 query；`QueryPolicyKind.EXACT` 在 M2 绑定可信 endpoint profile/固定非密钥参数前 fail-closed。Registry authority、credential reference、hostname 解析结果、连接 peer 与 DNS rebinding 防护仍分别属于 M2/M5。

### M2：规划、能力与授权快照

交付 Registry/profile/capability snapshot、legacy GLM 到冻结 profile 的映射、RoutePlanner、ConsentGrant、AuthorizationContext 和 endpoint policy。配置只保存 `credential_ref`，不得保存 secret value；未知模型不得继承已知能力。未知 capability 或 endpoint 必须拒绝；`compute_location=unknown` 必须按 remote 规则执行；processing-region/retention/data/cost policy 为 unknown 时必须显著披露并逐维获得额外确认，不能笼统当成同一种 unknown。

Phase 1 的 Plan 只能包含一个 `direct_multimodal` solver stage、一个 inline inference operation、空 fallback，并在截图前固定 endpoint、payload data kinds、token/call/billing/deadline 预算及所有 policy digest。

| 子工作包 | 状态 | 当前证据 |
|---|---|---|
| M2-A / W04 | complete | 纯标准库、runtime-final 的 endpoint operation/policy、credential binding metadata、Provider/Capability/Stage/Pipeline profile 与 Registry generation；全部 digest 逐层绑定并 exact lookup，GLM profile 无 VerificationRecord 时只解析为 `experimental`；legacy mapper 不接受 key 值，只接受冻结的官方 base URL 与 exact model |
| M2-B / W05 | complete | 纯 RoutePlanner 把 explicit intent、同一 Registry generation 与 trusted CaptureConstraints 收紧为 deterministic Phase 1 Plan；runtime-final PlannedExecution 绑定 plan/resolution/generation digest；进程内 ConsentLedger 禁止 grant ID 条款重绑，ConsentGrant 对 processing-region/retention/data/cost 的 unknown 分别确认，PrivacyGate 签发并可复核绑定 grant revisions 的 AuthorizationContext；固定 W05 digest vectors、过期边界、撤销、one-shot 并发消费、热重载与 fresh-process 零副作用均有离线测试 |

M2 的 `complete` 只证明离线 authority snapshot、不可变性、exact binding、同代 planning、consent coverage/lifecycle 和零外部副作用边界。Stage binding 已冻结 Adapter 实际选择的 image encoding、structured-output 与 system/reasoning/usage 行为；M4 直接消费 PlannedExecution/ResolvedStageBinding，不重新查询当前 Registry。W05 的 Ledger 接收可信调用方提交的 confirmation tuple，本身不渲染披露或采集真人手势；产品 ConsentController/UI 仍须在调用 Ledger 前提供可审计的展示与明确动作。当前 ConsentLedger 只是进程内 authority，不是持久化或跨进程撤销方案；Registry/Policy 热重载只产生新 generation，W05 不会主动撤销尚未到期的旧 generation context，M5 必须补 authority revision → lease revocation 传播并逐 attempt 复核。M2 不证明认证、Provider 可用性、价格/限流、DNS/连接 peer、截图授权或 macOS 用户路径；这些证据分别留在 M3–M8。W07 已把实际 Adapter、内容寻址 prompt 与 canonical-PNG pass-through preprocessing 版本写入 profile，并有意使 Registry、Plan、PlannedExecution、Consent 与 Capture 的传递 digest/golden 全部失效后重新冻结。

### M3：本地捕获安全

交付三态 PermissionGate、明确选区、显示器 geometry revision/fingerprint、Provider-neutral 图片 bytes、硬限制、空白/黑帧检查和 `ValidatedCapture` lease 引用释放合同。Quartz 不可用或 API 异常必须是 unknown 并阻断；Phase 1 remote/unknown profile 必须拒绝 full-screen。

当前 W06 已完成的离线边界：

- `PermissionObservation` 只能由显式 platform probe 构造，记录 `granted/denied/unknown` 及不可用平台、API 缺失、API 异常、非法返回等 reason；旧布尔 helper 永久返回 false；
- Plan 的 `CaptureConstraints` 绑定 trusted display topology revision，相关 ExecutionPlan/RoutePlanner schema 在 W06 升为 v2；W07 又因绑定完整 `SolveIntent.intent_digest` 将 PlannedExecution schema 升为 v3。W06 只接受 display-local `physical_pixels` 明确选区，拒绝 stale/unknown/out-of-bounds/whole-display 伪选区；
- `ConsentLedger` 与 `CaptureAuthorizationLedger` 都以账本私有摘要快照和原始 proof identity 校验当前 revision，不能通过修改返回 proof/grant、重算公开摘要或跨 ledger entry alias 来回滚/替换状态；最终 authorization issue、capture consume 与 validation commit 固定按 `ConsentLedger → CaptureAuthorizationLedger` 加锁，在同一 consent revision 内复核并迁移，因此并发 revoke 要么先阻断，要么排在线性化 commit 之后。CapturePolicy 在授权与真正捕获前分别复核 PrivacyGate、permission、topology 和可选 consent scope fingerprint，并原子限制同一 `capture_id`、授权消费、artifact attempt 与 validation attempt 各最多一次；
- `CaptureArtifactFactory` 只物化一次，并在此阶段限制非空 bytes、PNG MIME、尺寸、时间和 Plan 上限；canonical PNG 只能由后续 InputValidator 建立。InputValidator 在捕获后再次复核 privacy/permission/topology/Plan，完整解析 PNG signature/chunk CRC/zlib/真实尺寸，仅接受 8-bit、非交错 RGB 或全不透明 RGBA，并拒绝 ancillary/APNG、截断、尾随、解压超限、黑帧、空白帧和透明帧；
- 下游只能取得 authority-only `ValidatedCapture` lease；其 digest 绑定 Plan、同意、捕获授权、初始 authorization、捕获前 consumption、捕获后 validation 三阶段的权限/topology 证据以及完整 artifact metadata。初始阶段绑定 topology revision，捕获前后另绑定对应 snapshot digest。`release()` 只保证幂等丢弃该 lease 的 Python 引用，不宣称 immutable bytes 已被安全擦除。

W06 的 `complete` 不包含真实 Quartz/TCC 验收、权限请求 UI、真实 display source/scale/rotation transform、图形选区、截图 backend、JPEG decoder、实际预览、deadline/cancel 编排或应用入口接线。这些分别留给 W08–W12；W12 前禁止把真实用户截图接入远程链。

CaptureAuthorizationLedger 只允许 trusted core orchestrator 持有，禁止下放给 Adapter、Provider SDK、UI callback 或插件。W06 证明 public proof/正常调用与并发下 fail-closed，不宣称 Python 私有字段能抵抗已经取得任意同进程代码执行的恶意插件；未来插件必须用进程隔离和窄 IPC capability。

### M4：GLM 纯 Adapter

保留的 legacy 兼容面仅限已冻结的官方 GLM exact profile、模型和 Chat Completions wire shape。`prepare()` 生成确定性的 endpoint/headers/body bytes 与 envelope digest，`decode()` 只产生 candidate/typed error；二者都不能读取环境、创建 SDK、sleep、重试或联网。

W07 必须消费同一 `PlannedExecution` 的 frozen `ResolvedStageBinding` 与 active `ValidatedCapture`，禁止接受 raw `CaptureArtifact`、调用方自带 MIME/限制或重新查询当前 Registry。当前 W06 只签发 canonical PNG，因此首个 Adapter fixture 也必须从 PNG 输入确定性生成 exact inline image payload；若 Adapter 需要 JPEG/缩放，必须先新增版本化 preprocessing policy 和同等严格的本地验证，不能在 Adapter 内暗中转换。

本地 repair 最多允许版本化、确定性的单层 JSON fence 移除；从任意正文中搜索 JSON 或远程 repair 均禁止。

当前 W07 已完成的离线边界：

- `SolveIntent.intent_digest → PlannedExecution v3 → SolveRequest → StageInvocation` 逐层绑定原始 locale/user hint、request/plan/generation、active `ValidatedCapture.validation_digest` 与 exact stage；hint presence 必须与 Plan 的 `outbound_data` 完全一致，调用 Adapter 时不能再传自由字符串、raw `CaptureArtifact`、model、MIME 或限制；
- built-in GLM profile 已冻结实际 Adapter、内容寻址 prompt 与 canonical-PNG pass-through preprocessing 版本。`prepare()` 仅从同一个 PlannedExecution 解析 exact stage/operation/binding，将 canonical PNG 原字节做标准、无换行、保留 padding 的 raw Base64，放入 `image_url.url`；不加 Data URI、不转 JPEG、不缩放，不发送 `response_format`、thinking/reasoning、temperature/top-p、tool 或未声明字段；
- 当前 Adapter v1 只接受空的 `fixed_non_secret_parameters`；冻结 binding 中若出现尚未实现的参数，必须在序列化前 fail-closed，不能静默忽略已经获批的配置；
- `PreparedOutbound` 同时绑定 `capture_id → validation_digest` 与 `invocation_id → invocation_digest`，以及 frozen endpoint/method/content-type/credential-binding/outbound-data/scope。active lease 以同步读取 `ValidatedCapture.artifact` 成功为线性化点；其后的 `release()` 不追溯取消本次纯 prepare，也不表示 secure wipe；
- `TransportResponse` 只保存有上限的 immutable response bytes 与 plan/stage/operation/envelope binding；`decode()` 先关联再解析，只接受 UTF-8、无 BOM、无 duplicate key/NaN/Infinity、深度受限的单 choice assistant JSON。choice index 必须是普通整数 `0`，不能用布尔值或浮点数等价通过；只有 `finish_reason=stop` 进入 candidate；
- Provider 错误先按官方要求同时核对 HTTP status 与严格提取的 `body.error.code`，已知业务码映射为稳定 typed error，未知、畸形或 status/code 不配对时才回退到 HTTP 映射；欠费/权限/额度周期等不会在当前 attempt loop 恢复的错误明确标为 non-retryable，Provider message/raw body 永不进入异常。usage 三项只接受非负普通整数，且 total 必须等于 prompt 与 completion 之和；
- prompt-only content 只接受一个完整 JSON object，唯一 repair 是移除一次恰好包住全文的 JSON 代码围栏（带 `json` 或无语言标记）；禁止任意正文 JSON 搜索和 legacy coercion。`AnswerCandidateResult` 绑定 request/plan/stage/operation/invocation/envelope/response-body digest，ResultValidator 必须先复核 correlation 才能构造 `SolveResult`；candidate 不保留 Provider wrapper 或 reasoning content；
- 因 PlannedExecution v3 摘要传递绑定了实际 user hint，`repr` 与 safe metadata 不再暴露该摘要前缀，避免低熵 hint 的离线猜测 oracle；
- Adapter import、prepare、decode 的成功/失败路径均不读取环境/secret，不导入 legacy Provider/OpenAI SDK/Quartz/mss，不构造 client，不做文件 I/O、DNS/socket/HTTP、sleep、retry、fallback 或远程 repair。

M4 `complete` 仍只表示纯本地请求/响应合同成立。没有 EgressApproval、one-shot send session、credential resolve、HTTP Transport、Provider live 响应、真实 macOS capture 或可执行 pipeline；GLM binding 继续为 `experimental`，不能据此声称模型当前可用或应用能够解题。

### M5：出站与传输安全核

交付 `EgressGate → EgressApproval → AuthorizedSendSession → RemoteTransport`。实际 preview 必须表示将要发送的变换后图像与 metadata；任何应用控制的 body/非密钥 header/endpoint mutation 都改变 envelope digest 并使 approval 失效。

授权有效期统一为 deadline、EgressApproval、AuthorizationContext 与 ConsentGrant 到期时间的最小值；接入 Registry/Policy authority revision，把 reload 或行政撤销传播到旧 generation lease；在首次发送和每次 retry 前都必须重新检查 generation、有效期、撤销、取消与预算，任一失败都不得开始下一次网络 attempt。

如果继续使用 OpenAI SDK，必须证明实际发送 bytes 与获批 envelope 一致，并显式关闭自动 retry 和 redirect；无法证明时改用能原样发送 body bytes 的低层 HTTP Transport。

### M6：合成图 live smoke

live smoke 必须显式 opt-in、一次调用、无自动 retry，只用固定非敏感合成图。受控 `VerificationRecord` 保存完整的 profile/adapter/policy digest、真实 origin/path/TLS、调用数、usage、延迟和 typed outcome，以便复核 exact binding；普通 console/log 只显示这些配置 digest 的短前缀。任何位置都不得记录 key、请求正文、截图、完整 capture/content/envelope digest 或原始响应。

### M7：真实选区纵切

只有 M0–M6 全部通过后，才能把 macOS selected-region source 接入同一链。预览取消、权限变化、显示器拓扑变化、approval 失效、secret 失败和退出取消必须分别验证；此时仍只标记 `experimental`。

### M8-A：第二协议族实验接入

第二个 Adapter 必须是不同原生协议族，并复用相同的安全与领域合同。Provider 选择依据账号可用性、地域、成本与 eval 决定；实现前重新核验官方协议。第二 binding 必须使用独立 credential binding，并验证 native schema、tool/schema、prompt-only 等结构化输出能力的确定性降级链；先完成 contract、安全与 synthetic live smoke，状态保持 `experimental`。

### M8-B：正式多模型支持证明

交付显式 profile selector、启动时 Provider/host/data-kind 提示、两个 binding 的统一 eval 与当前 macOS E2E，并为所有 supported 条件生成可复核 VerificationRecord。两个 exact binding 均达到完整 supported 门槛后，才可对外称为“正式多模型支持”。

### M9：Phase 1C 多模态学习 UX

在 M8-B 的安全主干上实现图形化选区、NSPanel 实际预览、区域记忆与敏感提醒；模型响应后先确认题面摘要再揭示答案；增加本地哈希缓存、调用预算、SQLite 错题本和查看/删除入口。截图仍默认不保存，所有 UI 状态必须经主线程 dispatcher 更新。M9 不改变 M0–M8 的出站、支持状态和安全门槛。

## 5. 工作包与依赖

| ID | 工作包 | 依赖 | 主要文件 | 验收测试 |
|---|---|---|---|---|
| W01 | 领域 digest 与基础值对象 | Spec-0 | `domain/digest.py`、`domain/capture.py` | golden vectors、不可变性、边界 |
| W02 | typed errors 与严格结果 | W01 | `domain/errors.py`、`domain/solve.py`、`result/validator.py` | malformed/limits/confidence 矩阵 |
| W03 | 冻结 legacy 远程入口 | Spec-0 | `app.py`、旧 orchestrator/config tests | stdin/hotkey/app/orchestrator/legacy Provider 全部零 capture/secret/SDK/network |
| W04 | profile/capability Registry | W01 | `config/`、`routing/registry.py` | exact binding、digest、legacy mapping |
| W05 | Planner/Consent/Authorization | W04 | `routing/planner.py`、`privacy/consent.py` | 单 stage、空 fallback、过期/撤销/热重载 |
| W06 | 权限、拓扑、一次性 CapturePolicy 与严格 InputValidator | W01,W05 | `core/permissions.py`、`capture/` | tri-state、Plan/topology/scope binding、canonical PNG、one-shot ledger、零副作用 |
| W07 | GLM 纯 Adapter | W02,W04,W05,W06 | `adapters/openai_chat_compatible.py` | request/response fixtures、零 I/O |
| W08 | Egress 与 one-shot session | W05,W06,W07 | `privacy/egress.py`、`transport/session.py` | mutation、并发消费、撤销 |
| W09 | HTTP Transport 与预算 | W08 | `transport/http.py`、`runtime/` | TLS/redirect、attempt/deadline/cancel |
| W10 | 新 multimodal pipeline | W06,W07,W09 | `pipelines/multimodal.py` | 完整 gate 顺序和故障矩阵 |
| W11 | GLM synthetic live smoke | W03,W10 | `scripts/`、非敏感 fixture | M0 已完成；opt-in 单次实调证据 |
| W12 | macOS 选区/预览纵切 | W03,W10,W11 | `capture/`、`present/`、`app.py` | 当前 macOS E2E |
| W13 | 第二协议族 experimental Adapter | W12 | `adapters/`、profile | 独立 binding；结构化输出降级；共用 contract/security/live |
| W14 | 双 binding 支持证明与选择 UX | W12,W13 | profile selector、VerificationRecord | 统一 eval、启动披露、两个 binding 当前 macOS E2E |
| W15 | Phase 1C 学习 UX | W14 | `present/`、`study/`、缓存 | 图形选区/预览、题面确认、数据查看删除与 E2E |

W01/W02 可以与 W03 并行，但 W04 之后的任何运行时接线都必须等待 W03；W11/W13 的任何 synthetic live 之前均必须完成 W03/M0；W12 之前禁止真实用户截图远程发送。

当前工作包状态：W01–W07 complete；W08 是下一工作包；W08–W15 pending。W07 complete 仅表示冻结 request/invocation、纯 Adapter、严格 decode/candidate 与离线 fixture 证据存在，不表示应用、Provider、真实 macOS 捕获、传输或发布链可用。

## 6. 测试与证据矩阵

### 6.1 统一副作用断言

| 失败位置 | capture | secret resolve | SDK/client construct | DNS/socket/HTTP |
|---|---:|---:|---:|---:|
| plan/privacy/permission/scope 前置失败 | 0 | 0 | 0 | 0 |
| capture/input/prepare/Egress 失败 | 最多 1 | 0 | 0 | 0 |
| snapshot/envelope/binding/session 失败 | 最多 1 | 0 | 0 | 0 |
| secret 解析失败 | 最多 1 | 1 | 0 | 0 |
| response Schema 失败 | 最多 1 | 1 | 1 | 只允许已经获批的次数；之后不得再调用 |

### 6.2 分层证据

| 层级 | 证明内容 | 不证明内容 |
|---|---|---|
| domain/unit | 不变量、Schema、digest、预算算法 | SDK/HTTP、Provider 可用性、macOS 用户路径 |
| contract/fixture | exact request/response 映射和 typed errors | 当前 endpoint、认证、限流、计费 |
| security integration | gate 顺序、零副作用、原子 approval、取消/清理 | 模型质量与真实 macOS 权限体验 |
| synthetic live smoke | 当前 exact endpoint/auth/wire shape 可用 | 真实截图安全、准确率、supported |
| eval | 分题型质量、拒答、校准与限制 | UI、TCC、进程退出安全 |
| macOS E2E | 真实选区/预览/确认/展示用户路径 | 未来 OS/模型版本持续有效 |

普通 CI 与本地默认测试不得依赖 secret 或网络。live smoke 必须使用独立命令和显式环境开关，不能被 `unittest discover` 或 `pytest` 自动收集执行。项目声明 `requires-python >=3.10`，因此 CI 必须至少在真实 Python 3.10 与当前主版本各跑一次完整离线 suite；`ast.parse(feature_version=(3, 10))` 只能作为语法补充证据，不能替代 3.10 runtime 证据。

## 7. 近期执行顺序

1. 实现 M5/W08 的 EgressApproval 与 one-shot AuthorizedSendSession，并把 exact PreparedOutbound 与当前 Authorization/Consent lease 逐项绑定；
2. 实现 M5/W09 的 HTTP Transport、预算、deadline、取消、redirect/TLS/DNS/peer 约束与延迟 secret 注入，并跑完整安全负向矩阵；
3. 完成 M5 后组装 W10 新 multimodal pipeline；
4. M6/W11 synthetic live smoke 通过后，再进入 M7/W12 的真实 macOS topology/选区/截图纵切；
5. 选定不同协议族并实施 M8-A/W13，再以 M8-B/W14 完成选择 UX 与两个 binding 的正式支持证明；
6. 实施 M9/W15 学习 UX；Phase 1 exit gate 全部满足后再启动 Phase 2 的 OCR 实现。

每个里程碑结束时必须记录：代码 SHA、测试命令与结果、是否联网、是否使用真实用户数据、未覆盖项、状态变化依据。合并、发布、部署或 live API 调用均是独立授权边界，不由本文自动授权。

## 8. 本轮变更记录

- 将 Phase 1A 从单个大里程碑拆成 M0–M7，把第二协议族与支持证明拆为 M8-A/M8-B，并为 Phase 1C 建立 M9；
- 明确旧远程链不是兼容目标，M0–M6 前禁止真实用户截图远程发送；
- 增加目标模块、工作包依赖、副作用矩阵和分层证据定义；
- 完成 M0：冻结所有 MVP-0 产品入口，CLI 明确以退出码 `3` fail-closed，并用 poison-import/副作用探针证明零截图、零 secret resolve、零 SDK、零网络；
- 完成 M1-A/M1-B/M1-C：加入 runtime-final 领域值对象、Plan/consent/预算/PreparedOutbound 绑定、canonical URL 与 literal scope 负向约束、固定 digest vectors、严格结果 Validator；Phase 1 的 query 暂只允许空值；
- 完整离线 `unittest` 为 112/112（含独立新进程 poison-import/network CLI 探针），并通过 Python 3.10 grammar、compileall 与 diff 静态检查；M0/M1 实现已由独立授权提交并推送至 `main`，实现与验证过程没有截图、真实 secret、SDK client、DNS/socket/HTTP、live API 或 macOS E2E，也未执行额外 merge 或部署。
- 完成 M2-A/W04：把旧 secret-bearing `config.py` 隔离为未接线的 `legacy_config.py`，建立无 I/O 的 `config/` 包、Provider-neutral capability/profile snapshots、受控 GLM exact Registry 与纯 legacy 非秘密映射；未知 profile/model/capability 不回退，非空 query、自定义 legacy endpoint、generic serialization、摘要篡改与快照代际混用均 fail-closed；W04 已独立提交并推送为 `5852501 feat: add immutable model registry`，未调用 Provider API、合并或部署。
- W04 完整离线 `unittest` 为 138/138，其中 Registry contract/security 为 25/25；固定 Registry golden digest、fresh-process poison-import/secret/network 探针、Python 3.10 grammar、compileall 与 diff 静态检查均通过。2026-08-29 只读复核了官方 GLM model 与 Chat Completions/OpenAI-compatible 文档，但未使用真实 secret、截图、SDK client 或 Provider live 调用。
- 完成 M2-B/W05：新增 deterministic RoutePlanner、generation-bound PlannedExecution、processing-region/retention/data/cost 分维度 unknown consent、grant terms/revision digest、进程内 ConsentLedger 与可撤销复核的 AuthorizationContext；intent timeout/token 与 trusted capture bounds 只能收紧，hint 缺失时 Plan 只声明 image，remote full-screen、过期/未来 policy、潜在计费却无费用政策、grant 缺失/重绑/撤销/消费、授权 ID 别名、旧 context/新 generation 与额外 consent 均 fail-closed。
- W05 专项离线 `unittest` 为 30/30，提交 `65c867e feat: add plan-bound consent authorization` 已推送到 `origin/main`；包含固定 W05 identifier/digest vector、fresh-process poison env/import/capture/secret/network 边界、16 组 all-unknown confirmation 子集、四个 single-unknown profile、grant expiry 半开边界、one-shot 并发单赢家、热重载/代际混用、typed-error 收敛与 digest/slot 篡改。提交与推送未触发截图、真实 secret、SDK/client、DNS/socket/HTTP、live API、合并或部署。
- 完成 M3/W06：新增 probe-only tri-state PermissionObservation、trusted topology/scope 合同、Plan-bound CaptureAuthorization、ledger-owned one-shot artifact/validation state、strict canonical PNG InputValidator 与可幂等 release 的 ValidatedCapture lease；Plan/Planner/PlannedExecution schema 因新增 topology binding 升为 v2，并为 permission/topology/scope/capture authorization/consumption/artifact/validation 冻结端到端 literal golden vector。权限或 topology 在授权前、捕获前、捕获后任一变化均阻断；同 capture id 重绑、跨 entry alias、返回 proof 状态回滚、并发 revoke、直接消费 ledger、artifact swap、失败后重试、并发重复物化/签发、RGBA 透明度、伪 PNG、CRC/解压/尺寸/黑帧/空白帧均有负测。
- W06 完整离线 `unittest` 为 247/247，并通过 Python 3.10 grammar、compileall 与 diff 静态检查；实现已提交并随 W07 推送为 `14a099a feat: add fail-closed capture contracts`。该提交明确排除了用户已有的 `README.md` 改动；未调用真实 Quartz/TCC、截图 backend、secret、SDK/client、DNS/socket/HTTP 或 Provider live API，也未执行合并或部署。
- 完成 M4/W07：新增完整 SolveIntent digest 与 PlannedExecution v3、authority-only SolveRequest/StageInvocation、内容寻址 prompt policy、GLM raw-Base64 OpenAI Chat-compatible pure Adapter、bounded TransportResponse、execution-bound AnswerCandidateResult、correlation-first ResultValidator 入口、HTTP + GLM business-code/finish typed-error mapping，以及 literal request/response fixtures 与并发/release/冻结参数/篡改/strict JSON/usage/零 I/O 负向矩阵；同步更新 Registry generation 与 W05/W06 transitive golden vectors。
- W07 专项离线 `unittest` 为 26/26（其中一个用例固定覆盖当前官方 34 个 GLM business code 的 status/type/retryability 全矩阵），工作区完整离线 `unittest` 为 273/273；`compileall`、76 个 Python 文件的 3.10 AST grammar 与 `git diff --check` 均通过。本机实际运行时为 Python 3.12.13，真实 Python 3.10 runtime suite 证据仍缺失。实现与验证未使用真实截图、secret、SDK/client、DNS/socket/HTTP、Provider live API 或真实 macOS TCC/E2E；W07 已提交并推送为 `1066a99 feat: add pure multimodal adapter contracts`，`README.md` 用户改动仍保持未暂存且未被修改。
