# snapquiz v3 实施计划（Phase 1 优先多模态）

> **状态**：Active
>
> **实施基线**：`2026-09-04`，远端 `main@5fe5eab` 已完成 W09-B2a；当前未提交工作区已完成 W09 剩余的 local/offline 实现与全部可在无生产身份条件下构建的 production-closure foundations，包括 B2b S1–S6、caller-preheld native resolver/output owner 及 async adapter、Keychain staged source→CredentialResolver bridge、opaque numeric/TLS owner 与原生 C-to-C transfer、B3 exact TLS/HTTP/1.1 single-request Transport、可复现 native build 和扩展 B4/readiness v5。W09 的本地可完成范围为 `complete`；整个 W09-B 与 M5 的 production activation/acceptance 因正式身份、最终 artifacts、真实系统 vtable/entitlement、S7 接线与授权门槛标记为 `blocked`
>
> **实现快照**：M0–M4、M5/W08、W09-A、W09-B0、W09-B1 与 W09-B2a 已完成并推送至 `main@5fe5eab`。当前未提交 W09 增量已补齐 Darwin process/message IPC、S1/S2a/S2b-I1/I2/S2c/S3/S4/S5/S6、native resolver/output owner、durable async adapter、Keychain caller-preheld publication 与 CredentialResolver bridge、opaque numeric/TLS owner、C-to-C descriptor transfer、exact TLS/HTTP Transport、hardened native build、readiness v5 和 B4 inventory。三轮独立退出审查最终为 P0=0/P1=0；Python 3.12.13 与 Python 3.10.20 完整离线 suite 均为 1235/1235，B4 均为 7/7，native build 均为 16/16，numeric/TLS/transfer 联合回归均为 112/112。跨解释器实际构建的 4 个 dylib 逐字节一致、固定 `@rpath`、输入/manifest `0400`、输出 `0500`、均 `nlink=1`；它们只有 linker ad-hoc 签名且无 TeamIdentifier，manifest 明确 `production_signed=false`、`production_authority=false`。Production W09/M5 仍需 fixed Team-signed app/supervisor/helper/native artifacts、最终 bundle/signing IDs 与 Keychain access group/entitlements、绑定这些 artifacts 的真实 syscall/SSL/Security.framework vtable、真实 control/liveness/DNS/TLS/Keychain 证据、S7/app cutover 及另行明确的 activation/acceptance 授权。所有 production flags 保持 false，`ResolverHelperLauncher.production()` 与 CLI 继续 fail-closed；本地完成不等于已发送 Transport、已执行解题链或已具备 production authority。
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

- **真实 API 与用户截图**：首次真实 API 只能在 M6/W11，且必须保留已完成的 W09-A 证据、关闭 W09-B production exit gates，并完成 W10 与完整离线负向矩阵；随后还须另行明确授权，才可用仓库内固定、非敏感合成题图单次调用并关闭自动 retry。真实用户截图只能在该 smoke 通过后的 M7/W12 接入。
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
| M5 | blocked | Egress、session、Transport、预算、取消、授权租约、延迟密钥与统一清理 | W09 本地可完成范围 complete，双版本 full 1235/1235 且最终审查 P0/P1=0；production Team-signed artifacts、真实系统 vtable/Keychain entitlement/liveness 与 S7 app cutover 仍需外部身份、证据和授权 |
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

W06 的 `complete` 不包含真实 Quartz/TCC 验收、权限请求 UI、真实 display source/scale/rotation transform、图形选区、截图 backend、JPEG decoder、真实人机预览、deadline/cancel 编排或应用入口接线。W08 已完成 preview boundary/exact subject 合同，但 NSPanel 人机证据仍在 W12，deadline/cancel 在 W09；W12 前禁止把真实用户截图接入远程链。

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

M4 `complete` 仍只表示纯本地请求/响应合同成立；后续 W08 已补 EgressApproval 与静态 one-shot send session，W09-B1/W09-B2b 又补了 credential lifecycle、Keychain staged-source bridge 与 native owner foundations，当前 B3 也只有 local/fake-edge exact HTTP Transport；仍没有已绑定最终签名应用与 entitlement 的 production credential authority、production-wired HTTP Transport、Provider live 响应、真实 macOS capture 或可执行 pipeline。GLM binding 继续为 `experimental`，不能据此声称模型当前可用或应用能够解题。

### M5：出站与传输安全核

交付 `EgressGate → EgressApproval → AuthorizedSendSession → RemoteTransport`。实际 preview 必须表示将要发送的变换后图像与 metadata；任何应用控制的 body/非密钥 header/endpoint mutation 都改变 envelope digest 并使 approval 失效。

授权有效期统一为 deadline、EgressApproval、AuthorizationContext 与 ConsentGrant 到期时间的最小值；接入 Registry/Policy authority revision，把 reload 或行政撤销传播到旧 generation lease；在首次发送和每次 retry 前都必须重新检查 generation、有效期、撤销、取消与预算，任一失败都不得开始下一次网络 attempt。

W08 已完成的离线边界：

- `AuthorizationContext` 私下绑定 exact ConsentLedger；Consent、Approval、Session 三类 ledger 都独立保存首次 terms、当前 revision digest 与原对象 identity，调用方返回的 proof/capability 不是账本事实来源；
- phase1 pass-through EgressGate 在预览前后用 trusted GLM Adapter 重建 `PreparedOutbound` 并逐 slot/逐 body byte 比较，绑定 request/plan/planned execution/registry/privacy authorization/stage/operation/invocation/source/scope/exact envelope；自洽 alternate body、预览期间 mutation 或 capture release 都 fail-closed；
- factory-only、immutable EgressPreview/Decision 绑定 exact review subject；decision 在 approval ledger 中只能使用一次，取消与 controller 异常均产生安全错误且零 approval。ApprovalLedger 不保留 preview/decision/图片/hint；trusted controller 必须在终态释放 UI buffer/引用，但 Python immutable bytes 不宣称 secure wipe，pipeline 统一清理仍属 W09，NSPanel 真人预览/动作与 UI 清理留给 W12；
- EgressApproval 以五分钟为最大寿命，并受 AuthorizationContext expiry 与 Plan wall-clock timeout 上界收紧；EgressGate 允许单 network-stage、单 operation、单 grant 的 one-shot ConsentGrant 进入预览/approval，但该阶段不消费 grant。多阶段或多 operation 的 one-shot 组合继续 fail-closed，等待 OCR 路由另行设计；
- SendSessionFactory 固定按 `ConsentLedger → EgressApprovalLedger → SendSessionLedger` 加锁，先不可逆提交 consumed approval revision，再登记 AuthorizedSendSession；one-shot 路径同时登记 grant consumed revision 与 session-bound `ConsentUseLease`。persistent 与 one-shot 的 session 发布只要发生部分写入或发布后异常，都精确回滚 session 映射/revision，approval 仍保持 burned；one-shot 还同步回滚 lease/grant。persistent grant 不消费，也不产生 lease。session 只冻结 exact authority/envelope、max attempts、billable 与 timestamp validity，不包含 secret/client/I/O，也不伪造 W09 的 attempt state、monotonic deadline、budget、cancel、credential handle 或 HTTP state；
- approval/session ledger 单独的 `validate_active` 只证明各自 lifecycle，不是完整 send authority；SendSessionFactory 只原子消费 approval 并签发静态 session，不解析 credential、构造 client 或执行 I/O。

W09-A 已提交并推送的离线边界：

- `RuntimeCallFactory` 在 PrivacyGate 成功后、PermissionGate/Capture 前建立每个 request 唯一的 `CallContext`，以 trusted triple-sample clock 创建不受 wall-clock 回拨延长的 `MonotonicDeadline`；
- `RegistryPolicyAuthorityLedger/Lease` 把 exact Registry generation、transport binding 与 reload/revocation epoch 绑定到 CallContext；operation/global/billable budget 与 cancellation/close 状态均由 Context ledger 持有；
- `AttemptGate` 使用固定的 `ConsentLedger → EgressApprovalLedger → SendSessionLedger → RegistryPolicyAuthorityLedger → CallContextLedger` 锁序，先签发 one-shot `CredentialResolutionPermit`，只有 resolver 确认 exact non-secret binding 后才可原子预留预算并签发 `AttemptPermit`；transport wire work 前还必须再次 claim 并复核全部 authority；
- factory-only、immutable `ConsentUseLease` 绑定 grant 的授权前/消费后 revision、Authorization、approval、exact session/ledger、plan/stage/operation/invocation、capture/credential/envelope 与半开有效期；AttemptGate 不接收 lease 或 bypass 参数，而是在每个 resolver pre-read、budget reserve 与 transport pre-wire 阶段从 exact session 自动查询账本映射。普通 PrivacyGate 在 grant 消费后仍拒绝旧 AuthorizationContext，只有该 exact session 的 lease-aware authority 路径可以继续；
- 当前 permit 路径是零 I/O 原语，不读取 secret、不构造 client、不解析 DNS，也不发送 HTTP；已消费的 attempt budget 不因失败或取消退还。

因此 M5 当前为 production `blocked`：W09-B2a 的 owner-bound AttemptGate、纯地址策略、offline coordinator、helper/RESULT wire v2、completion/recovery/deadline 合同已在远端 `main@5fe5eab` 完成。当前未提交工作区又完成 B2b S1–S6、caller-preheld native resolver/output owner 与 async adapter、Keychain staged source→CredentialResolver bridge、opaque numeric/TLS owner 与原生 C-to-C transfer、B3 exact TLS/HTTP/1.1 + fake-edge single-request Transport，以及 B4 fault/race/cleanup + readiness v5 exact exit inventory；三轮独立退出审查最终 P0/P1=0，Python 3.12.13 与 Python 3.10.20 完整离线 suite 均为 1235/1235。上述证据使 W09 的 local/offline 与无生产身份可构建范围 `complete`；production 仍需外部身份、最终签名 artifacts、真实系统 vtable/entitlement 接线与真实 macOS liveness 授权，不能把 production-unwired native foundation 或 fake-edge B3/B4 当作 production completion。Phase 1 Transport 仍固定走自有 exact 单请求 HTTP/1.1，禁止 SDK/httpx 隐式行为、自动 retry、redirect、连接池复用、HTTP/2、proxy、chunked request 与透明压缩；任何额外 HTTP 请求都必须是新的获批 attempt。

Production W09/M5 的硬门槛不只包含 DNS：解析必须由 durable owner 可取消、可观测并受同一 monotonic deadline 约束，校验全部结果并在连接后核对 actual peer。当前 native resolver/output、numeric/TLS、C-to-C transfer 与 Keychain source 都是 injected-vtable、production-unwired foundations；production 还必须提供 fixed Team-signed app/supervisor/helper/native artifacts 与最终 bundle/signing IDs，把受审查的真实 process/signal/wait/FD、DNS、numeric socket、system SSL/TLS、Security.framework Keychain vtable exact 绑定到这些 artifacts，证明最终 Keychain access group/entitlements、真实 control/liveness 与 S7/app cutover，并取得另行授权的真实 macOS evidence。把不可取消的 `getaddrinfo` 留在后台、只让前台超时，或把 local/fake-edge/native fixture matrix 接到产品入口，都不满足门槛；这些 production 门槛关闭前，W09-B 与 M5 的 production 范围保持 `blocked`，不否定已完成的本地范围。

W09-B0 已冻结后续实施顺序与边界：

- **B1 CredentialHandle/resolver**：唯一顺序为 AttemptGate claim/full-authority recheck → 从 permit 的 frozen PlannedExecution 唯一定位并核对 binding → exact locator 单次 backend read → post-read full-authority recheck → 原子发布/确认 handle。factory-issued `handle_id + handle_digest` 必须进入 permit ledger state 与 AttemptPermit digest；`reserve_attempt` 还必须由已经收到 handle 的调用方提交同一 primitive proof，防止 handle 返回前被旁线程预占；只确认公开可知的 binding digest 不构成解析证明；
- **B1 secret lifecycle**：secret 只由私有 ledger 的 mutable buffer 持有，不进入 handle digest/repr/metadata/error/fixture；Transport 只可在 exact AttemptPermit 下以 owner-only one-shot callback 借用，终态在 `finally` 中释放并 best-effort 清零，但不宣称 Python 环境字符串可 secure wipe。Bearer value 必须是 1..4096 ASCII bytes，exact 匹配一个或多个字母/数字/`-._~+/` 后可跟 `=` padding；CR/LF/NUL、C0/C1、空白、非 ASCII、空值、超长、trim/normalize 全拒并安全映射为无 cause/context 的 non-retryable ConfigError。当前 Darwin Keychain foundation 以 caller-preheld 4096-byte buffer、exact frozen service/account/access-group mapping、staged publication/commit 与 readonly one-shot borrow 接入 CredentialResolver，并验证失败/回收时清零；它仍是 injected Security.framework backend，默认 suite 只用 fake/native fixture，绝不读取真实 Keychain item；
- **B1 Phase 1 限制**：只支持内置 GLM 的 `AUTHORIZATION_HEADER + BEARER`。`PROVIDER_HEADER` 因缺少纳入 binding digest 的 exact header name、`RAW` 因缺少已验证注入合同而继续 fail-closed；禁止按 Provider 猜 header；
- **B1 dependency**：`transport.credentials` 单向依赖 `runtime.attempt`，后者只接收 primitive handle proof，禁止反向 import CredentialHandle；`transport/__init__.py` 不得 eager re-export credentials/http，调用方使用 concrete-module import 或受测 lazy export；
- **B2a offline helper deadline/cancellation**：由 AttemptGate 在 lifecycle reservation/spawn 前从 exact credential permit 签发 `HelperStopAuthority`，exact 绑定 Gate/context/session/request deadline/cancellation token 与 helper lifecycle；每次 `HelperWaitSlice` 都通过五账本路径取 trusted monotonic sample 和 request/session effective deadline，以独立 ledger postcondition 拒绝 stale/replay/no-op，取消优先于 timeout，半开边界相等即到期。spawn、READY、atomic START、RESULT、EOF、成功 reap/close 均以 `min(remaining, 50 ms)` 前后 checkpoint；read 的 `PENDING` 不得等同 EOF，START 只允许全帧 `COMPLETE` 或零进度 `PENDING`。DNS START commit 线性化 stop；RESULT terminal proof 后还须 one-shot Gate completion claim，且 `build_resolution_set()` 本身必须查询该 proof，才能发布 direct `ResolutionSet` 或由 coordinator 返回 Prepared。business stop 不阻止 cleanup；cleanup-only terminate/reap/close 每 action 至多 8 个 50 ms poll，pending 耗尽或 outcome 不确定必须保持 caller ticket recoverable/nonterminal；helper terminal 必须另由 Gate observer 证明 stop authority 及七个 owner refs 已释放。caller-supplied synchronous lifecycle/cleanup observer API 全部删除；该项只验 injected fake contract，不宣称真实 OS liveness；
- **B2b production cancellable DNS/peer**：选择应用级、pre-secret、persistent supervisor/broker，而不是把同步 direct `posix_spawn` 塞入 50 ms request slice。supervisor bootstrap 是唯一允许的同步 acquisition，必须发生在 capture/credential read/target/Attempt 前且不得宣称 hard-bounded；per-attempt 路径固定 `RESERVE(zero child) → exact proxy publication/observer → ARM → async spawn`，main 不持有 resolver PID，supervisor 是 child 的唯一 signal owner/reaper。cancel 与 spawn completion/START 由单一 event owner 线性化；late spawn success 仍须 broker-owned kill/reap/close，broker epoch/crash 或 PID/OS-action uncertainty 全局 poison。START 使用经 Darwin 验证的 `AF_UNIX/SOCK_DGRAM` 单 record，16384-byte 双端 buffer + 4096-byte pre-spawn canary，helper 单次 `recvmsg` 拒绝 truncation/ancillary；stdout/stderr 继续有界 pipe。只有 AttemptPermit reserve 且 owner-claim 为 `io_claimed` 后才发送唯一 START(host/port/policy/attempt proof)。Internet v1 使用 Spec 冻结的 IANA-2025-10-09 literal address policy，不依赖 `ipaddress.is_global`；raw 最多 32 条/16 KiB，IPv4-mapped IPv6/zone/special/local 全拒，任一 forbidden/malformed candidate 整组拒绝；规范化后按 family/packed IP/port 排序，numeric single-connect 并 exact 核对 peer；
- **B3 exact TLS/HTTP**：DNS/TLS 后与首字节前通过 `AttemptGate.commit_wire_start` 在五账本锁序中原子提交 `io_claimed → wire_committed`；自有 nonblocking TCP/TLS/HTTP/1.1 的 `snapquiz.tls.system-default-h1.v1` 在 `OPENSSL_CONF`、`OPENSSL_CONF_INCLUDE`、`OPENSSL_ENGINES`、`OPENSSL_MODULES`、`SSL_CERT_DIR`、`SSL_CERT_FILE` 或 `SSLKEYLOGFILE` 任一存在时零 wire fail-closed且不记录值，并要求 `SSLContext.keylog_filename is None`，否则固定 default SERVER_AUTH trust、TLS 1.2 minimum、CERT_REQUIRED、hostname/canonical SNI 与 negotiated h1；禁止 caller SSLContext/CA。请求固定 Content-Length/Connection close/identity encoding，禁止 proxy/pool/redirect/retry/H2/Expect/chunked request/compression。request body 上限 8 MiB；response 沿用 2 MiB body、64 KiB headers、128 fields、8 KiB/line，拒绝 close-delimited、所有 duplicate CL、CL+TE、1xx/encoding；TE 只允许 exact chunked，禁止 extension/trailer，最多 4096 chunks/64 KiB framing metadata，所有 limits 增量执行；
- **B4 fault/race/cleanup**：覆盖每个 resource acquisition 点、并发 claim/replay、blocked resolver cancellation、mixed DNS、peer mismatch、TLS、partial wire、wire commit vs revoke、3xx 不二发、framing 与 terminal cleanup；claimed attempt 在任一 BaseException 下 exactly-once 终结，handle/helper/pipe/selector/raw+TLS socket/Gate activity/in-flight 全清，预算不退且 cleanup error 无 raw cause/context。B4 local/offline 已完成；production exit gates 与真实 macOS resolver liveness 证据关闭前，W09-B/M5 production 保持 `blocked`，live API 不得启用，Provider 不得声明 available 或 `supported`。

W09-B1 本工作包已完成：`CredentialResolver.resolve()` 只消费 exact permit，并以 caller-generated resolver owner 先独占 Gate；built-in GLM binding 的 exact lookup、一次 fake-source read、1..4096-byte Bearer 校验、post-read full-authority recheck、handle proof 确认与安全异常映射均已落地。`CredentialHandle` 不可复制/序列化，secret 只在私有 mutable buffer 中持有；borrow 期间 Gate 以 owner-specific marker 阻止 attempt 终结或第二借用者释放其状态，完成后先释放 view/清零 ledger secret，再释放 marker。resolve/close/borrow 的 pre-commit、commit-then-raise、BaseException、并发 owner/publication/close 与 traceback-local 泄漏均有永久回归；默认测试阻断 environment/file/DNS/socket 并只用 fake source。在 `main@543d390` 的历史快照中，完整离线测试为 401/401、W09 三模块为 61/61，且当时只有 Python 3.10 AST、没有真实 Python 3.10 runtime suite；当前证据已经更新为 Python 3.12.13 与 3.10.20 各 1235/1235，见本节当前状态与第 7 节。当前工作区新增的 Keychain bridge 完成了 caller-preheld buffer 与 CredentialResolver 的本地边界，但仍不包含真实 Keychain item/entitlement、DNS、socket、HTTP、Provider API 或 production authority。

W09-B2a 第一批离线原语已提交并推送至 `main@62c53c1`：AttemptGate transport claim 使用 caller UUID 并线性化为 `io_claimed`，terminal guard 与 DNS START 以 primitive ID/digest exact 绑定；finish/abandon 的 commit-then-raise 不再错误重开终态。`transport/address_policy.py` 冻结内容寻址 IANA literal policy，严格解析 canonical JSON transcript，在去重前限制 32 条/16 KiB，任一非法候选整组拒绝，随后确定性去重排序并生成 AttemptPermit-bound `ResolutionSet`；pure peer matcher 只做 family/packed/port 精确比较。`transport/resolver.py` 只接受 injected `HelperSpawner/HelperKernel`，以 ledger object identity 执行 READY→ownership transfer→single START→bounded result→cleanup 状态，production spawner 始终零进程 fail-closed。

`main@1ac6fca` 的第二批离线增量新增 `transport/http.py` 的唯一 offline coordinator，固定 READY → credential resolve → attempt reserve/claim → helper transfer/guard bind → DNS START commit → single START/RESULT 顺序，并返回 factory-only `PreparedResolverAttempt` 作为 B2b 后续接点。helper wire 为 v2；terminal guard 只发行 factory-only `ResolverResultReceipt`，ledger 独立保存 exact START frame、原始 transcript 与 receipt 快照，并把每个 receipt 的单次 `ResolutionSet` 及 candidates identity/digest/canonical payload 锚定到同一发行事实。credential handle recovery 必须匹配 resolver/Gate 两侧的 per-call publication ID；READY reservation 在调用前取得 owner identity，READY lifecycle publication capability（非 `ResolverCleanupTicket`）在 spawn 前预占并 exact consume/recover，reservation 自身和 guard 返回的 return-then-raise 窗口均只能回收本次 owner。它们只用于清理，不授予新发送权限。

`main@d455c8e` 的 completion-attestation 增量把 receipt schema 升为 v2，并以 ledger-owned snapshot exact 绑定 `stdout_eof=true`、`child_reaped=true`、`child_exit_status=0` 与 `helper_pipes_closed=true`。同 chunk/下一 chunk 第二帧、EOF read 合同异常、正数/负数/bool/None/text/float exit status、reap/close Exception/BaseException、action commit-then-raise 和 observer fault 均无 receipt；外部 reap/close 只执行一次，一旦 reap 已 claim 便不再 terminate 可能复用的进程身份。成功 `PreparedResolverAttempt.close()` 也不重复 helper action。

`main@5468b52` 已提交 capability/recovery-sealing 增量：launcher 在 spawn 前生成四个互异 role ID，并将 spawn request digest 与它们 domain-separate 绑定为 immutable lifecycle capability；launcher reservation 与 lifecycle ledger 都保存独立 snapshot，READY guard 与 terminal guard 只持有同一 exact capability object。spawner 必须通过 publication sink 先把 kernel 锚定到 ledger；launcher registry 从该时刻强持有 ledger，直到 terminal proof 后才释放，terminal callback 的 bookkeeping fault 可由 cleanup recovery 幂等补做。cross-launcher、tamper、replay、旧 public API、无 authority 与 caller proof 参数均在外部动作前拒绝；同 lifecycle capability 并发只允许一次 spawn；reservation/READY/credential/attempt/Prepared 的 raise-after-return、normal-return alias 与 public proof tamper 只按独立 snapshot 回收 exact owner，合法的其他 capability/handle/attempt/guard alias 保持不受影响。kernel attach、READY acceptance、credential claim/confirm、budget reservation、attempt claim、DNS START 与 borrow begin/finish 均有 normal-return commit postcondition；wrapper recovery 的返回布尔值不构成 terminal 证据，必须由 cleanup-only observer 复核，必要时走独立 state path。helper 外部动作证明完成而 `finish_cleanup` no-op 时，状态保持 `cleaning` 供 bookkeeping-only retry，绝不重复 terminate/reap/close；真实 action proof 不确定则保持 `cleanup_failed` 与 strong recovery anchor。终态同步释放 Attempt/Credential recovery refs。该已推送基线的完整离线 suite 为 532/532，W09 为 227/227，核心五模块为 172/172；101 个 Python 文件通过 3.10 AST grammar、`compileall`、依赖方向与 `git diff --check`，本机仍为 Python 3.12.13。

`main@8047b9d` 已提交并推送 caller-owned recovery 增量：新增 factory-only、runtime-final、不可复制/序列化的 `ResolverCleanupTicket`。调用方必须在任何 lifecycle reservation、spawn、secret read 或 budget reserve 前调用 `issue_resolver_cleanup_ticket()`，并把 exact ticket 作为 `coordinate_resolver_attempt(..., cleanup_ticket=...)` 的必填参数；factory attach 与 bind 的正常返回都必须经独立 postcondition。同 ticket 只能绑定一次；commit-then-raise 由预创建 owner 精确恢复，未提交 ownership transfer 的 bind no-op 则保持 caller permit 与 ticket 可复用。除 `policy_version` 和安全 `repr` 外，ticket 公开面只含 `safe_metadata()`、`is_terminal` 与 `retry_cleanup()`，不返回 permit/handle/guard/secret，也不具备 resolve/reserve/claim/START/RESULT/borrow 权限。聚合 ledger 在每个风险边界前冻结 launcher、credential permit/publication/handle、attempt 与 guard owner，固定按 helper terminal → Attempt/Gate terminal → credential closed/Gate terminal 清理；credential terminal state 只保留 primitive owner proof，不在长寿命 resolver ledger 强持有 permit/Gate。每层只信独立 ledger observer，不信 recovery 布尔值。`publish_recoverable` 是 coordinator 返回 Prepared 前的 cleanup ownership 线性化点，正常返回仍须由 `prepared_publication_is_committed` 独立确认；该点后 caller ticket 可以并发完成 cleanup，即使 coordinator 尚未返回，Prepared 也必须先同步为 closed，未来 B2b consume 必须原子拒绝 terminal ledger。`retry_cleanup()` 在 issued/coordinating 时返回 false，不会变成 cancellation；并发 retry 串行化，瞬时 wrapper fault 返回 false 且恢复 recoverable，terminal 后幂等返回 true。`PreparedResolverAttempt.close()` 与 caller ticket 共用同一聚合 ledger，所以 Prepared return 被外层丢失时 ticket 仍可回收，而任一侧先完成后另一侧只观察 terminal。ticket/ledger 不持有 primary 或 traceback；失败路径以 bare raise 保留原异常的 identity、type 与 traceback，cleanup fault 不替换它，也不作为 cause/context 附着。

真实 helper external-action uncertainty 仍是诚实的不可同步恢复边界：一旦 ledger 为 `cleanup_failed`，ticket 必须保持 recoverable/nonterminal，后续 retry 不得重放 terminate/reap/close，Attempt 与 secret owner 继续保留；这里的 recoverable/retryable 只表示 cleanup-only owner 仍可安全调用，不保证状态能推进，每次仍可能返回 false。只有资源 action 已证明完成、仅 `finish_cleanup` bookkeeping no-op 时，retry 才能补做终态 bookkeeping 并继续清 Gate/credential。三层独立 observer 全部通过后先不可逆记录 `resources_terminal_proven`；若随后 strong-ref release 或其 observer 失败，后续 retry 只补引用释放/terminal bookkeeping，不再运行 helper、Attempt 或 credential cleanup。只有 terminal proof 与全部聚合引用释放 postcondition 都成立，ticket 才可转为 terminal。B2a 最终的 helper monotonic deadline/cancellation 离线切片已经完成并验证，故 W09-B2a 为 `complete`。当前未提交工作区已完成 B2b S1–S6、native resolver/output、Keychain、numeric/TLS 与 C-to-C transfer foundations、B3 fake-edge exact Transport 及 B4/readiness v5；这些模块没有绑定 fixed Team-signed artifacts、真实系统 vtable/entitlement 或 app authority，因此 W09-B2、W09-B3、W09-B4 与 M5 的本地范围 `complete`、production 范围 `blocked`，S7 保持未启用。

W09-B2a deadline/cancellation 最终切片的 exit gate（本次实现已通过）固定为：

- `AttemptGate` 在任何 helper reservation/spawn 前从 exact `CredentialResolutionPermit` 签发唯一 `HelperStopAuthority`，并把 Gate/permit、CallContext/ledger、session/terms、request `MonotonicDeadline`、`CancellationToken` 与 lifecycle capability 的 exact identity/digest 全部冻结；公开 coordinator 不新增 raw time/token/authority/bypass 参数；
- 每个 `HelperWaitSlice` 都经既定五账本 authority path 使用 trusted `ClockSample.monotonic_after_ns`，effective deadline 为 request deadline 与 exact session conservative monotonic deadline 的较小值，`max_wait_ns=min(remaining_ns, 50_000_000)`；Gate 必须在返回后通过独立 ledger exact 确认 sequence/identity/digest/phase/deadline，前一 slice 随新 sequence 立即 stale，stale/replay、normal-return no-op 或替换返回均不能授权 poll；取消优先于 timeout，`now == deadline` 已到期，clock rollback、alias/tamper/cross-owner 全部 fail-closed；
- spawn/publication、READY、START、RESULT、EOF、success reap/close 在每次 poll 前后都重新 checkpoint；stdout 的 identity `PENDING` 与 EOF `b""` 严格区分，START write 只有 full-frame atomic `COMPLETE` 或 zero-progress `PENDING`，其余/partial 返回全拒；
- DNS START commit 与 stop 的竞态只有一个线性化赢家：stop 先赢保持零 START，commit 先赢也最多一次 START且 stop 后立即转 cleanup；RESULT/EOF/reap(0)/close proof 之后还必须完成 exact one-shot Gate completion claim，并由独立 ledger postcondition 确认。`build_resolution_set()` 自身必须在解析 transcript 或发布 ledger-bound `ResolutionSet` 前查询 exact completion proof，因此 direct internal publication 与 coordinator 的 Prepared publication 都受同一 gate；stop 先赢则无 publication，claim 先赢也不产生 B2b connect authority；
- cancel/deadline 不得阻止或授权跳过 cleanup；cleanup-only terminate/reap/close 每个 selected action 只允许最多 8 个 poll，每个 poll 最多 50_000_000 ns。`PENDING` 耗尽、非法返回、异常或 outcome uncertainty 均保持 `ResolverCleanupTicket` recoverable/nonterminal，保留 helper/Attempt/credential owner，禁止假报 terminal、提前写入 `resources_terminal_proven` 或重放 outcome 不确定的 action；
- helper lifecycle terminal 必须清除 exact `HelperStopAuthority` 的 context/ledger/session/deadline/token 七个 owner refs，并由 Gate 的独立 helper-stop release observer exact 证明 authority terminal、refs 全空、credential terminal 与 session 无 active owner；lifecycle terminal、cleanup true 或 aggregate 三层 terminal 任一单独结果都不能替代此 proof。所有 caller-supplied synchronous lifecycle/cleanup observer 或 callback API 必须删除，安全 postcondition 只允许 module-private ledger 查询；
- B2a 默认验收只使用 injected fake spawner/kernel，并以 poison process/DNS/socket/network 固定零真实 I/O；native executable/spawn shim、真实 process/pipe/poll/kill/waitpid/reap/FD liveness、DNS、numeric socket/connect 与 peer/rebinding 全部属于 W09-B2b，production spawner 继续零进程 fail-closed。B2a 切片通过完整离线 580/580、W09 九模块 275/275、核心五模块 198/198 及独立终审，因此 W09-B2a 为 `complete`；当前工作区随后完成 B2b S1–S6 及其可在无生产身份下构建的 native owner foundations，整个 W09-B2 与 M5 的 production 范围则因外部门槛为 `blocked`。

W09-B2b 当前未提交状态为 **local/offline `complete`、production `blocked`**：S1、S2a、S2b-I1、S2b-I2、S2c、S3、S4、S5、S6 的 local/offline foundations 已实现并通过双版本全量与独立终审，但 production wiring 与 S7 未完成：

- 私有 `DarwinResolverProcessSpawner` 以 libc `posix_spawn` 和 flags `0x400c` 创建固定 argv/envp 的 helper；一个 `AF_UNIX/SOCK_DGRAM` record channel 映射 stdin，两组 pipe 映射 stdout/stderr，parent endpoints nonblocking/non-inheritable，`CLOEXEC_DEFAULT` 阻断高低位 canary FD 继承；kernel 以 poll 执行 READY/START/RESULT、单次 kill、`waitpid(WNOHANG)`、stderr 上限与 IPC close，争锁直接 `PENDING`。reap terminal bookkeeping 可在一次异步中断后幂等补齐；spawn outcome state 只在 libc exact success + positive PID 后信任 cell，非零返回的 undefined positive cell 与未 attested spawn outcome 均零 kill/wait；destructive wait return 未 attested 时同样永久 poison，后续零 waitpid replay/kill，但不提供 resource-liveness proof；
- START channel 两端显式设置并验证 16384-byte send/receive buffer，spawn 前 round-trip 一个不含 target 的 4096-byte canary；helper 用一次 `recvmsg(MAX+1)` 拒绝 truncation/ancillary。专项测试用真实 `encode_start_frame()` 最大合法输入生成约 1.1 KiB record，已经跨过本机 `PIPE_BUF=512`，并由 byte-size/SHA-256 证明 exact 单报文到达；`ENOBUFS` 保持零提交 `PENDING`，同帧幂等且不同帧不重放；
- production 继续 exact 使用 `FailClosedProductionHelperSpawner`，并有 poison `socketpair/libc` 的零 native-edge 回归。native owner、S5/S6/B3 与 Keychain edge tests 都只运行 injected/fixture 路径，不读取真实 credential、不运行外部 DNS/HTTP 或 Provider API，也不改变 production availability；
- 同步 `posix_spawn` 的 request deadline blocker 已裁决为 pre-secret persistent supervisor/broker：main application thread 唯一直接执行的同步 bootstrap 位于 per-attempt spawner 外；resolver child 的同步 spawn 只在 supervisor worker 内执行。per-operation 必须先 `RESERVE` 零 child、exact 发布 proxy 并独立观察，再 `ARM`；supervisor event owner 线性化 cancel/spawn completion/START，main 不接触 PID，late success 仍由 broker kill/reap/close；epoch/crash 或 ownership uncertainty 全局 poison。当前工作区已把该裁决做成 injected local/offline contract，并实现 caller-preheld native resolver owner/adapter；但它尚未绑定最终签名 supervisor/helper 与真实系统 vtable，不能成为 production authority；
- 各切片的当前状态与剩余门槛如下；任何 local/offline 完成项都不得据此提前把 B2b 标为 production complete：

  1. **B2b-S1 supervisor pure contract（implemented，pure/local only）**：冻结 broker authoritative 与 parent proxy state、独立 cleanup/action phase、factory-only parent session/publication capability、role-separated ports、revision/digest、query/release recovery、payload-bound START 与 claim-before-action。它不执行或证明真实 terminate/reap/close/liveness；
  2. **B2b-S2 bootstrap（local/offline implemented，production-unwired）**：S2a fixture bootstrap 与 S2b-I1 accepted-peer proof 保留其既有边界；`_darwin_suspended_identity.py`/`_darwin_process_events.py` 已实现 S2b-I2 的 suspended spawn、pre-resume dynamic validation、same-audit-token reconnect 与 lifelong `EVFILT_PROC` watcher foundation；`_resolver_startup_composition.py` 已冻结 S2c 的 process-singleton、pre-secret guarded-boundary composition；`native/darwin_resolver_owner.c` 与 Python owner wrapper 提供 caller-preheld、零 child publication gap 的 native lifecycle foundation。它没有 fixed production bundle manifest/Team-signed app/supervisor/helper，也未绑定真实生产 syscall table，所以 S2 production gate 与 `PRODUCTION_STARTUP_INTEGRATION_AVAILABLE` 保持 false；
  3. **B2b-S3 proxy handshake/lifecycle integration（local/offline implemented）**：canonical wire 与 injected proxy 已实现 bounded `RESERVE → publish once → observe → ARM`、exact-operation reentry 和 ARM-attested publication。`PENDING`/ACK loss 只允许重投同一 cached control frame，`frame_id`、digest、canonical bytes 必须完全相同；channel/broker 去重并返回 cached ACK/tombstone 或 bound STATE，不重复逻辑 mutation/OS action，同 ID 改 bytes/digest 立即 fail-closed。该规则只覆盖 `RESERVE/ATTACH/ARM/CANCEL/RELEASE`；START datagram、numeric connect、TLS 与 HTTP bytes 在 outcome 不确定后不得重放。真实 attested production channel 尚未接入；
  4. **B2b-S4 async spawn/late recovery/cleanup integration（local/offline implemented）**：injected event owner 已线性化 ARM/CANCEL/SPAWN_DONE/START critical section，处理 late child/cleanup waiting/release；`_resolver_output_cache.py`、native resolver owner 与 `_darwin_resolver_async_adapter.py` 已实现 READY/RESULT/EOF 先 durable publication、后 exact ACK，以及 signal/wait/FD lanes、sole-reaper/uncertain-action 的 foundation。production 仍缺最终签名 artifact 所绑定的真实 process/signal/wait/FD vtable、attested control/liveness channel 与真实运行证据；
  5. **B2b-S5 helper/DNS（local/offline implemented）**：strict Python helper 已冻结 fixed READY、single-datagram START、一次 `getaddrinfo`、bounded canonical RESULT 与全结果 policy validation。它不是 fixed bundled/Team-signed native helper；现有 durable output owner foundation 也未绑定真实 DNS/helper artifact 与 production liveness authority；
  6. **B2b-S6 numeric connect/peer（local/offline implemented）**：只选 `ResolutionSet.selected`、至多一次 numeric connect、同 FD bounded polling、`getpeername()` exact 比对与 rebinding 负向合同已实现；native numeric/TLS owner、descriptor C-to-C transfer 与 exact Python adapter 已完成 caller-preheld/opaque ownership foundation，并覆盖 alias mutation、adopt publication、deinit/retire race 与 ambiguous tombstone capacity。它们尚未绑定真实 socket/system SSL vtable 与签名 artifact，AttemptGate/app integration flags 仍为 false；
  7. **B2b-S7 production switch（not enabled）**：readiness v5 已冻结 exact TLS、Keychain、resolver、native capability interface、app bundle/entitlement、entrypoint digest 与 two-layer cutover DAG/probe 的证据形状；它要求 content-digest-bound generic attestation 与专用 fresh probe 同时通过，并拒绝旧 v1/version-only、generic-only substitution、stale/cross-manifest/same-manifest replay 与 tamper。v5 尚未消费 native build manifest v2 或四个 dylib 摘要，也不能自行签发 production authority；未来若将 build evidence 作为 S7 正向门禁必须升版并绑定最终 artifacts。只有最终 Team-signed artifacts、真实系统 vtable/Keychain item 与 entitlement、真实 liveness/transport evidence 和独立 activation/acceptance 授权全部通过后，才可替换 production placeholder。

因此 W09 的本地可完成范围已经收口；下一步若要关闭 **production closure**，必须先取得 fixed Team-signed app/supervisor/helper/native artifacts、最终 bundle/signing IDs 与 Keychain access group/entitlements，再把已审查 owner 接到这些 artifacts 的真实 process/signal/wait/FD、DNS、numeric socket、system SSL/TLS、Security.framework vtable，取得真实 control/liveness/Keychain/transport evidence，最后执行 S7 app cutover，并另行获得 activation/acceptance 授权。双版本 full suite 已通过，但在这些外部门槛全部关闭前，B2b-S2、W09-B2b、W09-B3、W09-B4、整个 W09-B2 与 M5 均不得宣称 production complete，production 继续 fail-closed。

### M6：合成图 live smoke

首次真实 API 测试只属于 M6/W11：必须保留已完成的 W09-A 证据、关闭 W09-B production exit gates，并完成 W10 与完整离线安全负向矩阵，之后再取得另行明确授权。live smoke 必须显式 opt-in、只使用仓库内固定非敏感合成图、只调用一次且无自动 retry。受控 `VerificationRecord` 保存完整的 profile/adapter/policy digest、真实 origin/path/TLS、调用数、usage、延迟和 typed outcome，以便复核 exact binding；普通 console/log 只显示这些配置 digest 的短前缀。任何位置都不得记录 key、请求正文、截图、完整 capture/content/envelope digest 或原始响应。

### M7：真实选区纵切

只有 M0–M6 全部通过后，才能在 M7/W12 把真实用户的 macOS selected-region source 接入同一链。预览取消、权限变化、显示器拓扑变化、approval 失效、secret 失败和退出取消必须分别验证；此时仍只标记 `experimental`。

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
| W09-A | Runtime authority、ConsentUseLease 与 two-stage attempt permits | W08 | `privacy/consent.py`、`transport/session.py`、`runtime/clock.py`、`runtime/authority.py`、`runtime/context.py`、`runtime/attempt.py` | privacy 后立即建 Context、deadline/cancel、generation/session lease、原子预算、resolver/transport one-shot claim |
| W09-B0 | Credential/DNS/Transport 合同冻结 | W09-A | Spec、Plan | handle proof、post-read/pre-wire authority、可取消 DNS、全结果/peer、wire framing 与 limits |
| W09-B1 | CredentialHandle 与 frozen-binding resolver | W09-B0 | `transport/credentials.py`、`runtime/attempt.py`（单向依赖） | exact-one-read、handle proof、post-read authority、header value、并发/重放、泄漏/清理、零 DNS/socket |
| W09-B2a | owner、地址策略与 helper 离线生命周期（complete） | W09-B1 | `runtime/attempt.py`、`transport/address_policy.py`、`transport/resolver.py`、`transport/http.py` | Gate-issued exact stop authority、trusted request/session effective deadline、50 ms bounded PENDING/COMPLETE poll、stale/no-op slice postcondition、direct Resolution publication gate、DNS/completion 线性化、每动作 8×50 ms cleanup 与独立 stop release proof 已通过 fake-only 验收；caller sync observer API 已删除，production 继续 fail-closed |
| W09-B2b | production 可取消 DNS、numeric connect 与 peer binding（local/offline + native foundations complete；production blocked，S7 disabled） | W09-B2a | `transport/_darwin_*`、`transport/_resolver_*`、`transport/_numeric_connect.py`、`transport/native/`、`scripts/build_w09_native.py` | local suspended identity/startup composition、wire/proxy、native resolver/output owner+async adapter、helper DNS、numeric/TLS owner 与 C-to-C transfer complete；production Team-signed artifacts、真实系统 vtable/control/liveness 与 S7 app cutover 仍缺 |
| W09-B3 | exact nonblocking TLS/HTTP/1.1 `send_once`（local/offline + native ownership foundations complete；production blocked） | W09-B2b | `transport/_exact_tls.py`、`transport/_exact_http1.py`、`transport/_exact_transport.py`、`transport/_darwin_transport_adapter.py` | fake-edge single request、7-key ambient TLS lockdown、TLS/hostname/SNI、strict framing/limits、零 redirect/retry、opaque numeric/TLS transfer complete；真实 socket/system SSL vtable 与 app integration flags 仍 false |
| W09-B4 | Transport 故障/竞态/终态矩阵（本地可完成范围 complete；production blocked） | W09-B3 | `tests/test_w09_*`、`transport/_production_readiness.py` | local/offline fault/race/cleanup、readiness v5 exact exit inventory 与双版本 full 1235/1235 complete；正式身份/最终 artifacts、真实 Keychain/system vtable/liveness/transport evidence 与 activation authority blocked |
| W10 | 新 multimodal pipeline | W06,W07,W09-B4 | `pipelines/multimodal.py` | 完整 gate 顺序和故障矩阵 |
| W11 | GLM synthetic live smoke | W03,W10 | `scripts/`、非敏感 fixture | M0 已完成；opt-in 单次实调证据 |
| W12 | macOS 选区/预览纵切 | W03,W10,W11 | `capture/`、`present/`、`app.py` | 当前 macOS E2E |
| W13 | 第二协议族 experimental Adapter | W12 | `adapters/`、profile | 独立 binding；结构化输出降级；共用 contract/security/live |
| W14 | 双 binding 支持证明与选择 UX | W12,W13 | profile selector、VerificationRecord | 统一 eval、启动披露、两个 binding 当前 macOS E2E |
| W15 | Phase 1C 学习 UX | W14 | `present/`、`study/`、缓存 | 图形选区/预览、题面确认、数据查看删除与 E2E |

W01/W02 可以与 W03 并行，但 W04 之后的任何运行时接线都必须等待 W03；W11/W13 的任何 synthetic live 之前均必须完成 W03/M0；W12 之前禁止真实用户截图远程发送。

当前工作包状态：W01–W09-B2a complete，远端基线为 `main@5fe5eab`。当前未提交工作区已完成 W09 的 B2b S1–S6、native resolver/output/Keychain/numeric/TLS/C-to-C transfer foundations、B3 exact TLS/HTTP/fake-edge Transport 与 B4/readiness v5；三轮独立退出审查最终 P0/P1=0，Python 3.12.13 与 Python 3.10.20 完整离线 suite 均为 1235/1235。Production W09/M5 仍阻塞于 Team-signed 最终 artifacts/bundle facts、真实 process/DNS/socket/SSL/Security.framework vtable 与 Keychain entitlement、真实 control/liveness/transport evidence、S7/app cutover 及另行授权的 activation/acceptance。故 B2b/B3/B4、整个 W09-B 与 M5 的本地可完成范围 complete、production 范围 blocked；这些本地证据不表示 Provider、真实 macOS 捕获、传输或发布链可用。

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

1. **已完成并推送** M5/W08、W09-A、W09-B0、W09-B1 与完整 W09-B2a，远端基线为 `main@5fe5eab`；B2a full 580/580、W09 275/275 与独立终审已通过；
2. **W09 本地可完成范围 complete，当前未提交** B2b S1–S6、native resolver/output/Keychain/numeric/TLS/C-to-C transfer、reproducible native build、B3 exact TLS/HTTP/1.1 + fake-edge single-request Transport 与 B4/readiness v5 均已完成；三轮独立退出审查最终 P0/P1=0，Python 3.12.13/3.10.20 full suite 均为 1235/1235；production 范围保持 blocked；
3. **关闭 W09 production blockers 需要外部输入**：取得 fixed Team-signed app/supervisor/helper/native artifacts、最终 bundle/signing IDs 与 Keychain access group/entitlements；把受审查 owner 绑定真实 process/signal/wait/FD、DNS、numeric socket、system SSL/TLS、Security.framework vtable；取得真实 control/liveness/Keychain/transport evidence；最后完成 S7/app cutover，并另行获得 activation/acceptance 授权。control ACK loss 只允许 exact cached control-frame re-delivery，START/connect/TLS/HTTP 均不得在 ambiguous outcome 后重放；
4. W09-B production blockers 全部关闭后组装 W10 multimodal pipeline，跑从 PrivacyGate 到 result validation 的完整 gate 顺序和副作用负向矩阵；
5. 只有 W09 production closure 与 W10 离线验收全部通过并获得另行明确授权，才在 M6/W11 使用固定非敏感合成图执行一次、无自动 retry 的首次真实 API smoke；
6. M6/W11 通过后，再于 M7/W12 接入真实 macOS topology/选区/用户截图纵切；
7. 选定不同协议族并实施 M8-A/W13，再以 M8-B/W14 完成选择 UX 与两个 binding 的正式支持证明；
8. 实施 M9/W15 学习 UX；Phase 1 exit gate 全部满足后再启动 Phase 2 的 OCR 实现。

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
- 在 `main@1066a99` 的 W07 历史快照中，专项离线 `unittest` 为 26/26（其中一个用例固定覆盖当时冻结的 34 个 GLM business code 的 status/type/retryability 全矩阵），工作区完整离线 `unittest` 为 273/273；`compileall`、76 个 Python 文件的 3.10 AST grammar 与 `git diff --check` 均通过，当时尚无真实 Python 3.10 runtime suite。当前双版本证据已更新为各 1235/1235。该实现与验证未使用真实截图、secret、SDK/client、DNS/socket/HTTP、Provider live API 或真实 macOS TCC/E2E；W07 已提交并推送为 `1066a99 feat: add pure multimodal adapter contracts`，`README.md` 用户改动仍保持未暂存且未被修改。
- 完成 M5/W08：强化 AuthorizationContext 的 exact ConsentLedger identity；新增 factory-only/immutable EgressPreview、EgressPreviewDecision、EgressApproval、EgressApprovalLedger、EgressGate、AuthorizedSendSession、SendSessionLedger 与 SendSessionFactory。当前 phase1 pass-through Gate 在 preview 前后用 trusted Adapter 重建并逐字段/逐字节比对 PreparedOutbound，decision exact-object/one-shot，approval 先不可逆 consumed 再签发 static session；mutation/replay/cross-ledger/concurrency/revoke/expiry/controller-error/capture-release 均 fail-closed，session issue 失败不会复活 approval。preview 期间 consent revoke、approval revoke vs consume、consent revoke vs session create 与 session 签发后撤销均已固化为确定性线性化回归。
- W08 专项离线 `unittest` 为 31/31，工作区完整离线 `unittest` 为 305/305；三类新增竞态又重复执行 90 次通过。实现与验证未读取 secret、构造 SDK/client、访问文件/环境、sleep、执行真实截图、DNS/socket/HTTP、Provider live API 或真实 macOS TCC/E2E。W08 已提交并推送为 `8333adf feat: add one-shot egress authorization`；`README.md` 用户改动仍保持未暂存且未被本轮修改。
- 完成 M5/W09-A 并连同 W09-B0 提交推送为 `8a50b7d feat: add runtime attempt authorization`：新增 trusted clock/monotonic deadline、Registry/Policy lease、RuntimeCallFactory/CallContext、operation/global/billable budget、cancellation/close、session-bound one-shot ConsentUseLease 与 two-stage AttemptGate permit；同时冻结 B1 CredentialHandle/frozen-binding resolver、B2 production cancellable DNS/all-result/peer、B3 exact nonblocking TLS/HTTP/1.1 与 B4 fault/race/cleanup。该提交不包含真实 secret、capture、DNS/socket/HTTP、Provider API、合并或部署；用户 `README.md` 改动未被纳入。
- 完成 M5/W09-B1：新增 factory-only `CredentialHandle`、私有 mutable-secret ledger、built-in GLM exact frozen-binding resolver、resolver claim owner、caller-supplied handle proof、AttemptPermit v2 与 owner-specific one-shot borrow marker；严格 Bearer 校验与 typed error/source-traceback 清理、resolve/close/borrow 的单故障和 commit-then-raise、handle-return publication、并发 owner/close/finish、replay/tamper/zero-I/O 均有回归。在 `main@543d390` 的历史快照中，W09 三模块 61/61、完整离线测试 401/401、关键六场景连续 20 轮通过；96 个 Python 文件通过 3.10 AST grammar、`compileall`、依赖方向与 `git diff --check`，但当时真实 3.10 runtime suite 仍缺失，W09-B2–B4 尚未实现，M5 为 `in_progress`。当前状态见第 4、7 节：双版本完整离线 suite 各 1235/1235，W09 本地可完成范围 complete，production blocked。该历史实现未读取真实环境凭据，未执行 capture、DNS/socket/HTTP 或 Provider API。
- W09-B1 已提交并推送为 `543d390 feat: add frozen credential resolution`；仅包含 Spec/Plan、AttemptPermit v2、CredentialHandle/resolver 与对应测试，用户已有 `README.md` 改动继续保持未暂存且未纳入。提交与推送未读取真实 secret，未执行 capture、DNS/socket/HTTP、Provider API、合并或部署。
- 完成 M5/W09-B2a 第一批离线原语：AttemptGate 增加 caller-owned `io_claimed`、exact terminal guard 与 one-shot DNS START proof，并修复 terminal commit-then-raise 的错误重开风险；新增冻结 IANA-2025-10-09 policy 的 `address_policy`、AttemptPermit-bound `ResolutionSet`、pure peer matcher，以及 injected fake-kernel 的 resolver READY/owner-transfer/single-START/bounded-result/cleanup ledger。该批已提交并推送为 `62c53c1 feat: add offline resolver security contracts`；用户已有 `README.md` 改动未被纳入，也未执行真实进程、凭据、DNS/socket/HTTP、Provider API、合并或部署。
- 完成 W09-B2a 第二批离线增量：新增唯一 offline coordinator 与 factory-only `PreparedResolverAttempt`，将 READY、secret resolve、budget reserve、attempt claim、helper ownership、DNS START、RESULT parsing 强制成单一离线顺序；升级 helper/RESULT wire v2，新增 ledger-issued receipt、单次 ledger-anchored `ResolutionSet`、per-call credential publication ID 与 caller-owned pre-spawn READY reservation/ticket，exact 绑定 claim、terminal guard、DNS START/START frame、canonical target/policy、原始 transcript/candidates，并拒绝 active/unclaimed attempt、terminal receipt、跨 proof replay、跨调用 owner recovery 与对象内摘要重算。该批完整离线测试 466/466、W09 161/161，已提交并推送为 `1ac6fca feat: bind resolver result publications`；用户已有 `README.md` 改动未被纳入，production spawner 保持零进程 fail-closed。
- 完成并推送 RESULT completion attestation 为 `d455c8e feat: attest resolver completion`：`HelperKernel.reap()` 必须返回 exact plain status；首帧后单字节 probe 只接受 EOF，随后必须 single reap(0) 并关闭 parent pipes，receipt v2 才能发行。ledger 在外部 action 前 claim；reap/close 异常或 commit-then-raise 不重试，一旦 reap 已 claim 也不再 terminate 未知进程身份。用户已有 `README.md` 改动未被纳入；未执行真实进程、凭据、DNS/socket/HTTP 或 Provider API。
- capability/recovery-sealing 增量已提交并推送为 `5468b52 feat: seal resolver lifecycle recovery`：launcher factory 在 spawn 前生成 READY publication、lifecycle、transport claim 与 DNS START 四个互异 role ID，以 capability digest、reservation snapshot、exact lifecycle capability identity、构造时 request/spawner snapshot 与 lifecycle ledger snapshot 绑定；kernel 必须由 publication sink 在 spawner 返回前锚定，launch owner 隔离并发赢家/输家，launcher strong registry 在 terminal 前保留 recovery owner。公开 coordinator 不再接收 caller proof UUID，旧 public launcher/guard lifecycle API 已移除，私有入口缺少 authority 时零外部动作；cross-launcher/replay/tamper 在 spawn 前拒绝，同 lifecycle capability 并发只有一个赢家。normal-return alias、return-then-raise、public proof tamper、cleanup action/callback fault 的 cleanup-only recovery、独立 commit/terminal observer、state recovery 与 terminal ref release 已加入回归。该提交完整离线测试 532/532、W09 227/227、核心五模块 172/172；101 个 Python 文件通过 3.10 AST/compileall 复核，且未包含用户 `README.md` 修改。
- caller-owned cleanup ticket 增量已提交并推送为 `8047b9d feat: add caller-owned resolver recovery`：新增 `ResolverCleanupTicket`/`issue_resolver_cleanup_ticket()` 与聚合 recovery ledger，把 factory attach、ticket bind 及每个 helper/credential/attempt/guard snapshot 在下一风险动作前独立确认；caller 在 coordinate 抛错或 Prepared return 被外层丢失后仍可 cleanup-only retry。ticket factory/构造/metadata 零 I/O，不可复制/序列化，同 ticket bind one-shot；`publish_recoverable` 是 return 前的 cleanup ownership 线性化点，并发 cleanup winner 会使 Prepared 同步为 closed。public retry 在 coordinating 时不取消，按 helper → Attempt/Gate → credential 串行推进，不调用 resolve/reserve/claim/START/RESULT/borrow，也不信 recovery 返回值；瞬时 wrapper fault 恢复 recoverable。三层 observer 通过后先记录 `resources_terminal_proven`，ref-release fault 只重试 bookkeeping；credential terminal ledger 只保留 primitive owner proof。helper bookkeeping-only fault 可重试且不重放动作，真实 external-action uncertainty 则保持 recoverable/nonterminal。该已推送增量的完整离线测试为 557/557、W09 252/252、核心五模块 197/197、coordinator 82/82，101 个 Python 文件通过 3.10 AST/compileall/依赖方向/diff 检查；在该远端提交快照中 helper deadline/cancellation 仍是 B2a 唯一剩余项，B2b native process/DNS/numeric connect/peer、B3 exact HTTP/TLS 与 B4 全资源矩阵仍待完成。
- W09-B2a deadline/cancellation 收口切片已加入 Gate-issued exact `HelperStopAuthority`、trusted request/session effective deadline 与每次最多 50 ms 的 `HelperWaitSlice`；每个 slice 由独立 ledger postcondition 拒绝 stale/replay/no-op。spawn/READY/atomic START/RESULT/EOF/success reap/close 均在 bounded poll 前后 checkpoint，DNS START 与 stop 线性化；RESULT terminal proof 后由 one-shot Gate completion claim gate `build_resolution_set()` 的 direct publication 与 Prepared publication。cleanup 不复用过期 business slice，而是对 terminate/reap/close 每个 selected action 最多执行 8 个 50 ms poll；pending 耗尽或 outcome uncertainty 保持 caller ticket recoverable/nonterminal。helper lifecycle terminal 后还须独立证明 stop authority 的七个 owner refs 全部释放；全部 caller-supplied synchronous lifecycle/cleanup observer API 已删除。该切片通过完整离线 580/580、W09 九模块 275/275、核心五模块 198/198 与独立终审，W09-B2a 为 `complete`；在远端 `main@5fe5eab` 快照中 production 继续零进程 fail-closed，后续未提交 B2b/B3/B4 local/offline 增量见下一条。
- 当前未提交 W09 增量完成 B2b S1–S6、caller-preheld native resolver/output owner 与 async adapter、Keychain staged source→CredentialResolver bridge、opaque numeric/TLS owner 与原生 C-to-C descriptor transfer、B3 exact TLS/HTTP/1.1 + fake-edge single-request Transport、reproducible native build，以及 B4 fault/race/cleanup + readiness v5 exact exit inventory。native owner 修复了 TLS alias mutation、retire double-failure、transfer deinit/accept、adopt publication 与 tombstone capacity 等原子性边界；exact TLS 把 ambient lockdown 扩展到 7 个环境键并禁止 key logging；readiness v5 精确绑定 TLS、Keychain、resolver、native capability interfaces、app entitlement/entrypoint 与 two-layer cutover DAG/probe，要求 content-digest-bound generic attestation 和专用 fresh probe 同时通过，并拒绝旧 v1/version-only、generic-only substitution、stale/replay/tamper。native build manifest v2 与四个 dylib 是独立 development evidence，尚未被 readiness v5 消费。三轮独立退出审查最终 P0/P1=0；Python 3.12.13 与 Python 3.10.20 完整离线 suite 均为 1235/1235，B4 均 7/7，native build 均 16/16，numeric/TLS/transfer 联合回归均 112/112。跨解释器实际构建的 4 个 dylib 逐字节一致、固定 `@rpath`、输入/manifest `0400`、输出 `0500` 且均 `nlink=1`；仅有 linker ad-hoc 签名、无 TeamIdentifier，manifest 明确 `production_signed=false`、`production_authority=false`。Production W09/M5 仍需 fixed Team-signed app/supervisor/helper/native artifacts、最终 bundle/signing IDs 与 Keychain entitlement、真实 process/DNS/socket/SSL/Security.framework vtable 和 control/liveness/transport evidence、S7/app cutover 与独立 activation/acceptance 授权；所有 production flags 保持 false。用户已有 `README.md` 改动继续保持未暂存且未被修改。
