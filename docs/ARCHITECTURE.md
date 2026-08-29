# snapquiz 产品与技术规格（v3 · 多模型双通道）

> **状态**：v3 实现基准。本文描述目标架构；当前工作区只完成 M0 安全冻结与 M1 离线领域契约，不代表 v3 用户链路已经可用。交付顺序、状态与逐项验收见 [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md)。
>
> **已定方向**：模型能力分为两条推理通道：
>
> 1. `direct_multimodal`：截图直接交给多模态模型；
> 2. `ocr_text`：截图先经 OCR 形成结构化题面，再交给非多模态文本模型。
>
> 第一阶段只交付 `direct_multimodal`。`ocr_text` 在第一阶段只定义边界与契约，不参与运行时路由或自动回退。

---

## 0. 规范词、版本边界与当前基线

本文中的 **MUST / 必须**、**MUST NOT / 禁止**、**SHOULD / 应该**、**MAY / 可以** 表示实现约束。

审计起点是单 Provider 的 MVP-0（`2026-08-28`，`main@93a7b2b`）。该起点曾具有以下行为：

- 触发：默认 stdin；可选 `pynput` 全局热键；
- 捕获：`mss` 主屏全屏或环境变量固定区域；
- 模型：OpenAI SDK 指向 GLM OpenAI-compatible Chat Completions；
- 输出：prompt 约束 JSON，终端与系统通知展示；
- 尚无：选区预览、Provider registry、严格结果契约、NSPanel、SQLite、错题本、缓存、签名应用。

当前未提交工作区已经进入迁移态：

- **M0 complete**：stdin、全局热键、app/orchestrator、legacy GLM Provider 与截图入口全部 fail-closed；CLI 只解释参数并以退出码 `3` 说明 legacy pipeline 已禁用，不读取 `.env`、权限或屏幕，也不构造 SDK/联网；
- **M1 complete**：已建立纯标准库 canonical digest、Capture/Intent/Policy/ExecutionPlan/PreparedOutbound、typed errors、严格 `SolveResult` 与本地 Validator；敏感值对象禁止通用 dataclass 序列化并在运行时禁止继承；
- **尚不可用**：没有 Registry/Planner/Consent、三态权限/真实选区、纯 Adapter、Egress/session/Transport 或任何 live/E2E 证据，因此当前没有可执行的解题用户路径，不能称为 `experimental` 或 `supported`；
- legacy `Config`、权限探测、parse/notify 与 `AnswerResult` 仍留在源码树中，但被 M0 产品入口隔离；M2/M3/M4 必须替换而不得重新接回。结构化 URL 只完成无 I/O 的规范形校验；endpoint authority、profile allowlist、DNS 结果与连接 peer 验证仍属于 M2/M5。

因此本文必须区分：

- **Current**：仓库当前真实行为；
- **Target**：本规格要求的目标行为；
- **Planned**：尚未排入当前阶段的能力。

README 尚未纳入本轮同步；不能把 Target/Planned 写成已实现能力。

---

## 1. 产品目标与非目标

### 1.1 目标

snapquiz 是 macOS 上的个人学习辅助工具。一次显式触发后，它应：

1. 在用户明确知道捕获范围和数据去向的前提下获取题目图像；
2. 选择一个已配置、已验证、满足隐私约束的解题通道；
3. 返回可验证状态的“题面摘要 + 答案 + 简明解析 + 风险提示”；
4. 对信息不足、模型拒答、输出损坏和 Provider 故障作明确区分；
5. 为后续错题本、缓存、复习与模型评测保留稳定领域契约。

### 1.2 非目标

第一阶段明确不做：

- OCR + 文本模型的生产实现；
- 根据题目内容自动选择“最聪明/最便宜”模型；
- 同时把同一截图发给多个云模型投票；
- 未经用户同意的跨 Provider、跨地域或本地转云 fallback；
- 把模型自报置信度包装为经过统计校准的正确率；
- 反监考、隐藏窗口、绕过检测或其他规避评估监管的能力；
- 对外分发前的签名、公证和完整学习产品 UI。

---

## 2. 核心架构决策

| ID | 决策 | 约束 |
|---|---|---|
| D1 | 两条执行通道 | 固定为 `direct_multimodal` 与 `ocr_text` |
| D2 | 第一阶段范围 | 运行时只启用 `direct_multimodal`；OCR 通道不得暗中回退 |
| D3 | Provider 中立输入 | 核心层持有图片 bytes 与元数据；data URL/base64/文件上传只在 Adapter 内生成 |
| D4 | 四层 binding 标识 | `pipeline_kind`、`adapter_family`、`provider profile`、生成 `model_id` / OCR `component_id+version` 必须分离 |
| D5 | 显式能力声明 | 按 exact model/component binding 声明能力，禁止根据模型名字符串猜测 |
| D6 | 确定性选择 | 第一阶段由用户显式选择 profile，不做隐式智能路由 |
| D7 | 统一结果契约 | JSON 可解析不等于成功；必须经过本地 Schema 与业务规则验证 |
| D8 | 隐私不扩张 | 一次执行不得超出其预先声明并获同意的数据接收方、数据类型、地域或费用边界 |
| D9 | 单一重试预算 | SDK 内建重试与应用重试必须统一，受总 deadline 与调用次数限制 |
| D10 | 以验收定义支持 | 只有通过契约、安全、非敏感实调 smoke、分题型 eval 与 macOS E2E 的 exact binding 才能标为 supported；pipeline 状态由其必需 bindings 派生 |
| D11 | 不可变执行计划 | 每次触发在截屏前生成 `ExecutionPlan`；运行中禁止自行改模型、endpoint、通道或数据接收方 |
| D12 | 第一阶段远程只传选区 | Phase 1 的 remote profile 必须拒绝 `full_screen`；未来放开需独立 ADR 与逐次确认，不能作为普通设置持久授权 |

---

## 3. 双通道总体架构

```text
显式触发
   ↓
RoutePlanner（显式 profile + 能力 + endpoint + 总预算）
   ↓
ExecutionPlan（不可变，列出所有阶段、接收方与数据类型）
   ↓
PrivacyGate（校验用户同意是否覆盖整个计划）
   ↓
AuthorizationContext（绑定 plan 与实际 privacy grants）
   ↓
PermissionGate（macOS 上未知状态也 fail-closed）
   ↓
CapturePolicy（选区 / 预览 / 尺寸限制）
   ↓
CaptureArtifact（bytes + mime + dimensions + scope + digest）
   ↓
InputValidator（MIME / 像素 / 字节 / 空白帧 / 黑帧）
   ↓
SolveRequest → PipelineExecutor
   ├─ direct_multimodal：StageInvocation(CaptureArtifact)
   └─ ocr_text（Phase 2）：
        StageInvocation(CaptureArtifact)
          → QuestionDocumentValidator / OcrQualityGate
          → StageInvocation(QuestionDocument)

每个 stage 独立执行：
   ├─ network_operations 非空：
   │    PayloadPreparer（纯本地、无密钥、无网络）
   │      → EgressGate（实际预览 + exact payload/endpoint/data-kind）
   │      → EgressApproval
   │      → SendSessionFactory（原子消费 approval + 按需解析 credential）
   │      → AuthorizedSendSession（仅同一 operation/payload 的有界重试）
   │      → RemoteTransport
   └─ network_operations 为空且 compute_location=local_verified：
        LocalExecutor（无 approval、无 credential、零网络）

各 stage 输出为带判别字段的 StageResult
   ├─ AnswerCandidateResult → ResultValidator → SolveResult
   ├─ OcrCandidateResult → QuestionDocumentValidator / OcrQualityGate → QuestionDocument
   └─ OperationReceipt → 对应 operation 状态机
最终 SolveResult → Presenter / StudyStore / Metrics
```

### 3.1 第一阶段数据流：`direct_multimodal`

1. 用户触发一次查询。
2. RoutePlanner 在截屏前读取显式 profile，校验通道、模态、credential reference/binding 元数据、endpoint、能力与总 timeout budget，并生成不可变 `ExecutionPlan`；此时禁止读取密钥值、联网鉴权或远程模型发现。
3. PrivacyGate 根据计划中的 Provider、origin、地域和数据类型校验同意；不满足时停止，截图与网络调用次数均为零。
4. PermissionGate 必须明确确认屏幕录制权限；macOS 上导入或预检异常等同未授权。
5. Phase 1 的 remote profile 必须要求有效选区并拒绝整屏；`full_screen` 只保留给已验证本地通道或未来另行批准的设计。
6. 捕获层返回 Provider-neutral 的 `CaptureArtifact`，不生成 OpenAI 专用 data URL，并按 profile 限制验证 MIME、像素与字节。
7. InputValidator 检查实际 artifact；direct pipeline 形成唯一的 `StageInvocation`，Adapter 的纯本地 PayloadPreparer 依据 plan snapshot 生成待发送 payload 与摘要，不得读取密钥、联网或改变计划。
8. EgressGate 复核选区、实际预览、AuthorizationContext、plan snapshot、exact endpoint/data-kind，以及最终 payload 的 digest/字节数；通过后为该 network operation 产生限时、单次 `EgressApproval`。Gate 失败、取消或 payload 不匹配时，密钥读取、DNS、socket 与 HTTP 调用次数都必须为零，并立即释放临时 artifact/payload。
9. SendSessionFactory 原子消费 approval 后，才可按 plan 解析所需 credential（明确无需认证时为 `not_applicable`）、构造 transport，并创建仅允许同一 operation/endpoint/payload 的 `AuthorizedSendSession`。Phase 1 请求期间禁止远程 model discovery；未来若需要，必须作为独立预声明 operation，且结果不能修改当前 plan。
10. RemoteTransport 在 session 的 attempt budget 内发送已经获批的 payload。Phase 1 direct plan 只允许请求内 inline bytes / raw base64 / Data URI 的 inference operation，禁止预上传、file id、公共 URL 与远程 repair。
11. Adapter 优先使用 Provider/模型真实支持的结构化输出能力；无原生能力时才使用 prompt JSON。
12. 所有响应必须经过本地 Schema 与语义校验。
13. Presenter 展示题面摘要，让用户先确认模型读到的是正确题目，再展示答案与解析。
14. 日志与 metrics 只记录非内容元数据。StudyStore 的内容持久化默认关闭；首次启用必须经过独立 StoragePolicy/同意并显示保留期，且支持查看、导出与删除。即使启用，也默认不保存截图、prompt、原始响应或密钥。

### 3.2 第二阶段数据流：`ocr_text`

```text
CaptureArtifact
  → OCR StageInvocation
  → [若 OCR 远程：独立 Prepare / EgressGate / AuthorizedSendSession]
  → OcrAdapter / LocalExecutor
  → QuestionDocumentValidator
  → OcrQualityGate
  → QuestionDocument（文本、块、顺序、坐标、公式、OCR 质量）
  → Text StageInvocation
  → [若文本模型远程：独立 Prepare / EgressGate / AuthorizedSendSession]
  → TextModelAdapter / LocalExecutor
  → SolveResult
```

第二阶段必须遵守：

- OCR 与文本模型是两个独立的数据处理方；若任一为云服务，UI 必须分别披露。
- 每个含网络操作的 stage 必须单独生成 PreparedOutbound、EgressApproval 与 AuthorizedSendSession；OCR stage 的图片授权不能复用为 text stage 的 OCR 文本授权。
- 优先考虑本地 OCR，避免为了调用文本模型而额外上传原始截图。
- 不能把纯字符串作为唯一 OCR 契约；至少保留块顺序、bounding box、语言、公式标记和质量指标。
- OCR 质量不达标时返回 `insufficient_input`，不得把残缺文本硬交给文本模型猜测。
- 文本模型只能接收规范化 `QuestionDocument`，不能依赖某个 OCR 厂商的原始响应结构。
- Text stage 的 `outbound_data` 只能包含已批准的 `ocr_text`/`user_hint`，不得夹带原图、base64、OCR 厂商原始响应或未声明附件。

---

## 4. 统一领域契约

以下为逻辑 Schema；最终可用 dataclass、Pydantic 或等价实现，但字段语义必须稳定。本文的 `Digest256` 是 64 字符小写十六进制 SHA-256。所有安全 digest 统一按 `Digest(type_tag, schema_version, canonical_serializer_version, canonical(fields_except_own_digest))` 计算，并对各段做长度定界/类型域分离；禁止对普通字典的偶然遍历顺序做 hash。

具体排除规则必须进入契约：`CaptureScope.fingerprint` 排除自身，`ExecutionPlan.plan_digest` 排除自身，`QuestionDocument.content_digest` 排除自身，request-envelope digest 排除自身和真实 secret 值、但包含 credential-binding digest。Profile、capability、credential-binding 等受控对象也必须有版本化字段清单。Contract tests 必须提供固定 golden vectors，覆盖字段顺序、Unicode、数字规范化与类型域分离。

所有会影响同意或路由的数据、保留与费用政策必须以不可变快照引用，不能只保存可变名称：

```text
PolicySnapshot
  ref: string
  content_digest: Digest256
  verified_at: timestamp
  expires_at: timestamp | null
```

同名 `ref` 的内容 digest 改变等同新政策；旧 Plan、ConsentGrant、AuthorizationContext、credential/profile binding 与 supported evidence 均失效。

### 4.1 `CaptureScope` 与 `CaptureArtifact`

```text
CaptureScope
  kind: selected_region | full_screen
  display_id: string
  coordinate_space: screen_points | physical_pixels
  rect: {left, top, width, height} | null
  display_geometry_revision: string
  fingerprint: Digest256

CaptureArtifact
  id: UUID
  bytes: bytes                 # 仅内存；默认不落盘
  mime_type: image/png|image/jpeg
  width_px: positive int
  height_px: positive int
  byte_size: positive int
  scope: CaptureScope
  captured_at: timestamp
  sha256: Digest256            # 本地缓存键；日志中不得输出完整值
```

约束：

- `width_px`、`height_px`、`byte_size` 必须有硬上限；
- 远程调用前必须确认选区落在有效显示器范围内，并以解析后的 display、坐标空间、rect 与 geometry revision 重算 fingerprint；
- 显示器拓扑、缩放、坐标空间或 rect 变化会产生新的 fingerprint，并使既有 EgressApproval 失效；
- 编码与缩放策略属于 CapturePolicy，不属于 Provider；
- 传输序列化属于 Adapter，不属于 Capture。

### 4.2 `QuestionDocument`（第二阶段）

```text
QuestionDocument
  schema_version: "snapquiz.question-document.v1"
  document_id: UUID
  content_digest: Digest256
  source_artifact_id: UUID
  source_sha256: Digest256
  page_width_px: positive int
  page_height_px: positive int
  bbox_coordinates: pixel | normalized_0_1
  bbox_origin: top_left
  plain_text: string
  blocks[]: {text, bbox, kind, confidence, reading_order}
  formulas[]: {source, normalized, bbox, confidence}
  tables[]: {cells, row_spans, column_spans, bbox, confidence}
  detected_languages[]: string
  overall_quality: 0..1 | unknown
  confidence_semantics: provider_specific | normalized
  warnings[]: string
```

`content_digest` 必须覆盖除自身外的规范化文档内容。QuestionDocumentValidator 负责 Schema、bbox 范围/坐标空间、reading order、语言、长度和 source binding；OcrQualityGate 再按已验证能力判断公式、表格、布局与质量。`overall_quality=unknown` 不能自动通过 `supported` OCR pipeline，除非另有版本化、确定性的质量规则与证据。

### 4.3 `SolveIntent`

```text
SolveIntent
  schema_version: "snapquiz.solve-intent.v1"
  request_id: UUID
  pipeline_profile_id: string
  capture_scope_preference: selected_region | full_screen
  locale: BCP-47
  timeout_budget_ms: positive int
  max_output_tokens: positive int | profile_default
  requested_result_schema_version: "snapquiz.solve-result.v2"
  user_hint: optional string
```

`SolveIntent` 是截屏前输入。它不得包含尚未产生的 `CaptureArtifact`；RoutePlanner 使用它和本地 Registry 生成计划。

### 4.4 `ExecutionPlan`

RoutePlanner 必须在截屏和任何网络调用前生成不可变计划：

```text
ExecutionPlan
  plan_id: UUID
  plan_digest: Digest256
  canonical_serializer_version: string
  request_id: UUID
  pipeline_profile_id: string
  pipeline_profile_digest: Digest256
  pipeline_kind: direct_multimodal | ocr_text
  prompt_policy_digest: Digest256
  result_validator_version: string
  image_preprocessing_policy_version: string
  capture_scope_kind: selected_region | full_screen
  capture_constraints: {allowed_display_ids[], max_width_px, max_height_px, max_pixels, max_bytes}
  preview_required: bool
  required_consent_scopes[]:
    binding_id: string
    provider_profile_id: string
    provider_profile_digest: Digest256
    network_scope: none | loopback | lan | internet
    compute_location: local_verified | remote | unknown
    processing_region: string | unknown
    retention_policy: PolicySnapshot | not_applicable | unknown
    data_policy: PolicySnapshot | not_applicable | unknown
    cost_policy: PolicySnapshot | not_applicable | unknown
    network_operation_ids[]: UUID
  stages[]:
    stage_id: UUID
    role: solver | ocr | text_solver
    binding_id: string
    provider_profile_id: string
    provider_profile_digest: Digest256
    provider_id: string
    model_id: string | null
    component_id: string | null          # OCR 等非生成模型组件
    component_version: string | null
    adapter_family: string
    adapter_version: string
    capabilities_ref: string
    capabilities_digest: Digest256
    endpoint_policy_version: string
    network_policy_version: string
    tls_policy_ref: string | not_applicable
    credential_binding_ref: string | not_applicable
    credential_binding_digest: Digest256 | not_applicable
    network_scope: none | loopback | lan | internet
    compute_location: local_verified | remote | unknown
    processing_region: string | unknown
    max_attempts_per_operation: non-negative int   # 无网络 stage 为 0
    network_operations[]:
      operation_id: UUID
      purpose: upload | inference | delete | remote_repair | model_discovery
      http_method: string
      canonical_endpoint: scheme + host + port + normalized path template
      canonical_query_policy: empty | exact non-secret keys/values
      content_type: string
      allowed_non_secret_headers[]: lowercase header names
      credential_injection_slot: authorization_header | provider_header | not_applicable
      outbound_data[]: image | ocr_text | user_hint | provider_response_text
      retention_policy: PolicySnapshot | not_applicable | unknown
      data_policy: PolicySnapshot | not_applicable | unknown
      billable: bool | unknown
  requested_result_schema_version: "snapquiz.solve-result.v2"
  max_output_tokens: positive int
  timeout_budget_ms: positive int
  max_network_calls_total: non-negative int
  max_billable_calls: non-negative int
  cost_policy: PolicySnapshot | not_applicable | unknown
  fallback_branches[]: ExecutionPlan          # Phase 1 必须为空
```

Plan 中每个 stage 是 Registry/安全配置的完整快照，不是运行时重新解析的松散 ID。CredentialResolver、PayloadPreparer 与 Transport 必须核对所有 digest/version；profile 热重载或 Registry 变化不能影响已经生成的计划。运行过程中禁止更改 pipeline、模型、endpoint、数据类型、输出 token 上限或结果 Schema。任何未来 fallback 分支都必须包含在初始计划中并一次性通过 PrivacyGate；动态发现“另一个可用模型”不能自动扩展本次计划。

`not_applicable` 表示经契约证明该政策/操作不适用，`unknown` 表示缺少资料，二者禁止混用；retention、data 或 cost 为 `unknown` 时必须显著披露并额外确认。Phase 1 的 remote direct stage 只能有一个 inline `inference` operation；`upload`、`delete`、`remote_repair` 与 `model_discovery` 均不可出现在 Phase 1 计划中。

### 4.5 `SolveRequest`

```text
SolveRequest
  schema_version: "snapquiz.solve-request.v1"
  request_id: UUID
  plan_id: UUID
  input: CaptureArtifact
  requested_result_schema_version: "snapquiz.solve-result.v2"
  locale: BCP-47
  user_hint: optional string

StageInvocation
  invocation_id: UUID
  request_id: UUID
  plan_id: UUID
  stage_id: UUID
  input: CaptureArtifact | QuestionDocument
  input_digest: Digest256
```

`SolveRequest` 只能在 ExecutionPlan、PrivacyGate、PermissionGate、CapturePolicy 与 InputValidator 全部通过后交给 PipelineExecutor；结果 Schema、token 上限与 runtime timeout 一律从 plan/CallContext 读取，SolveRequest 没有覆盖入口。PipelineExecutor 为每个 stage 构造独立 StageInvocation；direct pipeline 只有图片 invocation，OCR pipeline 的第二个 invocation 必须绑定已验证 `QuestionDocument.content_digest`。AuthorizationContext、EgressApproval、AuthorizedSendSession 与运行时 `MonotonicDeadline` 属于调用上下文或 transport capability，不写回 SolveRequest，因此不存在“先有 approval 才能 prepare、先 prepare 才能 approval”的构造循环。

### 4.6 `SolveResult`

```text
SolveResult
  schema_version: "snapquiz.solve-result.v2"
  status: answered | insufficient_input | refused | unsupported_input
  question_summary: string | null
  answer: string | null
  rationale: string
  confidence: number 0..1 | null
  confidence_kind: model_self_reported | calibrated | none
  confidence_calibration_ref: string | null
  warnings[]: string
  provenance:
    pipeline_kind
    plan_id
    stages[]:
      stage_id
      role
      binding_id
      provider_profile_id
      provider_profile_digest
      provider_id
      model_id
      component_id
      component_version
      adapter_family
      adapter_version
      capabilities_ref
      capabilities_digest
      attempts
      network_calls
      latency_ms
      usage                     # 若 Provider 可提供；不得包含内容
```

业务校验规则：

- `answered`：`question_summary`、`answer`、`rationale` 必须为非空、限长字符串；
- `insufficient_input`：`answer` 必须为 `null`，`rationale` 必须说明缺失信息；
- `refused`：`answer` 必须为 `null`，`rationale` 必须提供用户可理解的原因；
- `unsupported_input`：`answer` 必须为 `null`，并说明当前通道无法可靠保真的输入特征；
- 非 `answered` 状态允许 `question_summary=null`；
- `{}`、字段缺失、`null` 被转成字符串、错误类型、超长字段都必须判为 `InvalidOutputError`；
- `confidence_kind=model_self_reported` 时，UI MUST NOT 展示数值或百分比；可以隐藏，或仅显示“低/中/高（模型自评，未校准）”；
- 只有经过离线标注集校准并提供 `confidence_calibration_ref` 的分数才能使用 `calibrated`；
- `confidence=null` 时 `confidence_kind` 必须为 `none` 且 calibration ref 为 `null`；有数值时 kind 只能为 `model_self_reported` 或 `calibrated`；
- `rationale` 是面向用户的简明解释，不要求、记录或展示隐藏思维链。

### 4.7 操作错误与业务结果分离

以下情况不得伪装成 `SolveResult`：

```text
ConfigError
PermissionDeniedError
CaptureError
EndpointPolicyError
AuthError
RateLimitError
NetworkError
TimeoutError
ProviderUnavailableError
ProviderServerError
ContentPolicyError
PayloadTooLargeError
InvalidOutputError
CancelledError
OcrProviderError              # 第二阶段的 OCR 基础设施故障
```

Presenter 必须能展示稳定、用户可行动的错误类别；原始 SDK 异常只进入本地受控诊断，不直接作为 UI 契约。

所有操作错误共享：`code`、`stage`、`retryable`、`safe_message`、`provider_profile_id`（可空）和 `attempt`（可空）。Provider 返回可验证的语义拒答对象映射为 `SolveResult.refused`；API 在生成结果前阻断请求映射为 `ContentPolicyError`。

OCR 引擎/服务故障映射为 `OcrProviderError`；OCR 成功但题面语义不完整应映射为 `insufficient_input` 或 `unsupported_input`，不能混为基础设施故障。

### 4.8 `ConsentGrant`

```text
ConsentGrant
  grant_id: UUID
  request_id: UUID | null
  policy_version: string
  binding_id: string
  provider_profile_id: string
  provider_profile_digest: Digest256
  pipeline_kind: direct_multimodal | ocr_text
  endpoint_policy_version: string
  network_policy_version: string
  tls_policy_ref: string | not_applicable
  allowed_network_operations[]:
    purpose: upload | inference | delete | remote_repair | model_discovery
    http_method: string
    canonical_endpoint: scheme + host + port + normalized path template
    canonical_query_policy: empty | exact non-secret keys/values
    content_type: string
    credential_injection_slot: authorization_header | provider_header | not_applicable
    outbound_data[]: image | ocr_text | user_hint | provider_response_text
  capture_scope_kind: selected_region | full_screen
  capture_scope_fingerprint: Digest256 | null
  compute_location: local_verified | remote | unknown
  processing_region: string | unknown
  retention_policy: PolicySnapshot | not_applicable | unknown
  data_policy: PolicySnapshot | not_applicable | unknown
  cost_policy: PolicySnapshot | not_applicable | unknown
  issued_at: timestamp
  expires_at: timestamp | null
  one_shot: bool
  consumed_at: timestamp | null
  revoked_at: timestamp | null

AuthorizationContext
  authorization_id: UUID
  plan_id: UUID
  plan_digest: Digest256
  consent_grant_ids[]: UUID
  authorized_at: timestamp
  valid_until: timestamp | null
```

ExecutionPlan 只声明需要什么同意，不引用尚未存在的 grant。PrivacyGate 必须逐个包含网络操作的 stage 证明它被有效 ConsentGrant 覆盖，随后签发绑定 `plan_id + plan_digest + grant ids` 的 AuthorizationContext；真正无网络操作的 `local_verified` stage 不要求远程数据同意。Provider/profile digest、endpoint、path、数据类型、处理地域、保留/数据政策或费用策略变化都会使旧授权失效。持久 grant 可以只覆盖 `selected_region` 类别，但每次上传仍必须由 EgressApproval 绑定实际 scope fingerprint；若 grant 自身绑定了 fingerprint，任何显示器拓扑、缩放、坐标或选区变化都会使它失效。任何未来允许的 `full_screen` grant 必须绑定本次 `request_id`、`one_shot=true`，且消费后不能复用；Phase 1 的 remote profile 不得产生此类 grant。

### 4.9 每个网络操作的出站授权

```text
PreparedOutbound
  plan_id: UUID
  plan_digest: Digest256
  stage_id: UUID
  operation_id: UUID
  source_ids[]: UUID
  source_digests[]: Digest256
  capture_scope_fingerprint: Digest256 | not_applicable
  http_method: POST | other explicitly allowed method
  canonical_url: scheme + host + port + normalized concrete path + normalized non-secret query
  content_type: string
  non_secret_headers[]: {lowercase_name, normalized_value}
  non_secret_headers_digest: Digest256
  credential_binding_digest: Digest256 | not_applicable
  outbound_data[]: image | ocr_text | user_hint | provider_response_text
  body_digest: Digest256
  payload_byte_size: positive int
  request_envelope_digest: Digest256
  body: ephemeral bytes

EgressApproval
  approval_id: UUID
  privacy_authorization_id: UUID
  plan_id: UUID
  plan_digest: Digest256
  stage_id: UUID
  operation_id: UUID
  source_digests[]: Digest256
  capture_scope_fingerprint: Digest256 | not_applicable
  http_method: string
  canonical_url: normalized concrete URL
  content_type: string
  non_secret_headers_digest: Digest256
  credential_binding_digest: Digest256 | not_applicable
  body_digest: Digest256
  payload_byte_size: positive int
  request_envelope_digest: Digest256
  outbound_data[]: image | ocr_text | user_hint | provider_response_text
  max_network_attempts: positive int
  approved_at: timestamp
  expires_at: timestamp
  consumed_at: timestamp | null

AuthorizedSendSession
  session_id: UUID
  approval_id: UUID
  privacy_authorization_id: UUID
  operation_id: UUID
  request_envelope_digest: Digest256
  credential_binding_digest: Digest256 | not_applicable
  credential_handle_id: opaque string | not_applicable
  attempts_remaining: non-negative int
  global_network_budget_id: UUID
  billable_budget_id: UUID
  authorization_lease_id: UUID
  runtime_deadline: MonotonicDeadline
  valid_until: monotonic instant
  cancellation_token_id: UUID
  revoked_at: monotonic instant | null

CallContext
  runtime_deadline: MonotonicDeadline
  global_network_budget: AtomicBudget
  billable_budget: AtomicBudget
  authorization_lease: RevocableLease
  cancellation_token: CancellationToken
```

PayloadPreparer 必须是确定性的纯本地步骤。`request_envelope_digest` 必须覆盖 method、完整规范化 URL（含非敏感 query）、content type、应用控制的非敏感 headers、credential-binding digest（无认证时为明确的 `not_applicable` 标记）与 body digest。EgressGate 每次只审批一个 PreparedOutbound，并重新证明 AuthorizationContext/grants 未过期、未撤销且与 plan digest 匹配。SendSessionFactory 在读取 secret（如适用）或构造 SDK client 前原子消费 approval，核对冻结的 profile/capability/adapter/endpoint/network/TLS/credential-binding snapshot，然后创建一个 AuthorizedSendSession；消费失败时 secret resolver 与网络调用均为零。

Transport 只能向 envelope 的已批准 slot 注入由该 binding 解析出的 Authorization/API-key secret；binding 为 `not_applicable` 时禁止注入任何认证 header/query。禁止添加其他数据承载 header/query，禁止修改 method、URL、非敏感 headers、content type 或 body。非秘密 header/query 的值只能来自冻结 Profile、transport policy 或协议固定元数据，不得依赖 StageInvocation、截图、OCR 文本、答案或 user hint。Host、Content-Length 等库派生 header 必须由已批准 URL/body 确定，并受版本化 transport policy 约束。Phase 1 的 canonical query 必须为空，任何用户内容都只能位于已批准 body；session 的 credential handle id 与 binding digest 必须匹配，否则零网络失败。

`valid_until` 必须取 request deadline、approval expiry、AuthorizationContext expiry 与所有 ConsentGrant expiry 的最早有效时刻。一次 `network_attempt` 定义为：在任何 DNS/socket 动作前，先对 session attempt、pipeline 全局网络预算，以及 `billable=true|unknown` 时的计费预算各原子扣减一次，随后完成这一次端到端发送尝试；底层 DNS/连接/HTTP 子步骤不重复计数。每次 attempt 前以及可中断的退避等待后，必须重新检查 cancellation token、authorization lease、有效期和 envelope/binding digest。即使连接中断也计数；用户取消或 grant 撤销必须原子阻止后续 attempt，已在途请求只能 best-effort 取消但不得再发下一次。session 只允许向同一 canonical URL 重放完全相同的 request envelope，不能用于另一个 operation、stage、Provider 或 fallback。OCR route 因此可有两个独立 approval/session；direct route 只有一个。过期、撤销、重复消费、并发双消费、选区/显示器变化、payload mutation 或任一 snapshot/digest 不一致均返回 `EndpointPolicyError` 并保持零网络。

严格 `local_verified` 且 `network_operations=[]` 的 in-process stage 走 `LocalExecutor.execute_local(invocation, frozen_runtime)`，不构造 PreparedOutbound、EgressApproval、credential 或 send session。loopback HTTP 仍属于网络操作，不能借 local 标签绕过该链路。

---

## 5. 能力模型、Registry 与 Adapter

### 5.1 分层

```text
pipeline_kind
  └─ adapter_family
       └─ provider profile
            └─ model_id | component_id + component_version
```

- `pipeline_kind`：`direct_multimodal` 或 `ocr_text`；
- `adapter_family`：协议与序列化方式，例如 `openai_chat_compatible`、`openai_responses`、`anthropic_messages`；
- `provider profile`：endpoint、凭据引用、地域、隐私属性、能力声明与默认参数；
- `model_id`：生成模型标识；OCR 用 `component_id/version`。这些标识可变且不得被当作能力来源。

### 5.2 `ModelCapabilities`

每个 profile/model 组合必须显式声明：

```text
input_modalities: [image, text]
roles: [multimodal_solver, text_solver]
image_inputs: [data_uri, raw_base64, public_url, file_id] | not_applicable
structured_output: json_schema | tool_schema | json_object | prompt_only
supports_system_instruction: bool
supports_reasoning_control: bool
supports_usage: bool
api_version: string
provider_application_state: disabled | provider_default | required | unknown
max_images: positive int | not_applicable
max_image_bytes: positive int | not_applicable
max_image_pixels: positive int | not_applicable
max_output_tokens: positive int
supported_mime_types[] | not_applicable
data_residency: string | unknown
network_scope: none | loopback | lan | internet
compute_location: local_verified | remote | unknown
availability: experimental | supported | disabled
verification_evidence:
  record_id: string
  binding_id: string
  provider_id: string
  exact_model_id: string | not_applicable
  component_id: string | not_applicable
  component_version: string | not_applicable
  profile_digest: Digest256
  pipeline_profile_digest: Digest256
  capabilities_digest: Digest256
  adapter_version: string
  prompt_policy_digest: Digest256
  result_validator_version: string
  image_preprocessing_policy_version: string
  endpoint_policy_version: string
  runtime_version: string | not_applicable
  network_policy_version: string
  tls_policy_ref: string | not_applicable
  retention_policy_digest: Digest256 | not_applicable | unknown
  data_policy_digest: Digest256 | not_applicable | unknown
  cost_policy_digest: Digest256 | not_applicable | unknown
  contract_ref: string
  security_ref: string
  smoke_ref: string
  eval_ref: string
  eval_dataset_version: string
  threshold_policy_version: string
  macos_e2e_ref: string
  verified_at: timestamp
  expires_at: timestamp
  resulting_availability: experimental | supported | disabled
```

规则：

- 能力来自版本化 profile 与验证结果，禁止 `if "vision" in model_id` 一类推断。
- 未知能力按不支持处理。
- 含 `multimodal_solver` role 的 binding 必须声明非空 image_inputs、正的图片上限和 MIME 白名单；纯 `text_solver` 必须把所有图片字段设为 `not_applicable`，且 Adapter 收到图片时 fail-closed，不能伪造数值或把 `unknown` 当作零。
- 兼容端点只发送 profile 显式允许的字段；禁止把未知 OpenAI 参数盲目透传。
- Pipeline profile、prompt、结果 Validator/Schema、图片预处理、Provider profile、model、Adapter/runtime、endpoint/path/TLS/network policy、capability、处理地域、保留/数据政策或评测阈值任一实质变化，旧 `supported` 立即失效；必须重跑所有受影响的 contract、安全、live smoke、eval 与 macOS E2E 门槛。
- `availability` 由受控 Registry 的版本化验证记录派生，不能由用户 profile 自行把值写成 `supported`；custom profile 在纳入内置验证目录前最高只能是 `experimental`。
- `network_scope` 可由实际连接策略验证，`compute_location` 不能由用户 profile 自报；custom、LAN 和普通 loopback 默认均为 `unknown`，只有受控验证记录才能派生 `local_verified`。`unknown` 一律采用 remote 的选区、确认和 consent 规则。
- 验证记录必须绑定 exact `provider_id + model_id/component + adapter/runtime version + provider/pipeline/capabilities digest + prompt/validator/preprocessing versions + endpoint/network/TLS policy`；任一项变化或记录过期都自动降为 `experimental`，不能沿用旧证据。
- 技术能力为 unknown 时按不支持处理；地域、保留等政策元数据为 unknown 时必须显著披露并要求额外确认，且不得参与自动选择或 fallback。
- Provider 的可配置 application state / interaction storage 必须显式建模，不能因为 snapquiz 本地不保存 raw response 就推断供应商端也不保留；协议支持时，截图求解 profile 默认设置为 `provider_application_state=disabled`。这不等于 Zero Data Retention：abuse/safety logging 等其他保留仍必须按供应商当前政策单独披露。
- `public_url` / `file_id` 是传输能力，不是上传授权。把本地 bytes 变成 URL/file id 所需的创建、上传、推理和删除操作必须分别进入 ExecutionPlan；Phase 1 默认禁用这条路径。

### 5.3 统一 Adapter 边界

核心接口概念上拆成纯本地准备、受权远程传输与严格本地执行：

```text
StageAdapter.prepare(
  invocation: StageInvocation,
  frozen_stage: ExecutionPlanStage,
  frozen_operation: ExecutionPlanNetworkOperation
) -> PreparedOutbound

RemoteTransport.send(
  prepared: PreparedOutbound,
  session: AuthorizedSendSession,
  credential_handle: CredentialHandle | not_applicable,
  call_context: CallContext
) -> TransportResponse

StageAdapter.decode(
  response: TransportResponse,
  frozen_stage: ExecutionPlanStage,
  frozen_operation: ExecutionPlanNetworkOperation
) -> StageResult

LocalStageAdapter.execute_local(
  invocation: StageInvocation,
  frozen_stage: ExecutionPlanStage,
  runtime: VerifiedLocalRuntime
) -> StageResult
```

`prepare` 的返回 `operation_id` 必须与显式传入的 frozen operation 一致，Adapter 不能自行挑选 stage 内的其他 operation。`prepare` 不得读取 credential、构造可能触网的 SDK client 或执行 I/O；`send` 只能消费 session 已批准的原始 body，不能重建或修改它。`execute_local` 只适用于 plan snapshot 证明 `compute_location=local_verified`、`network_scope=none`、`network_operations=[]` 的 in-process stage；否则必须走远程传输链。

Adapter 负责：

- 图片传输编码；
- Provider 专用消息角色与请求字段；
- 结构化输出参数；
- Provider SDK 异常映射；
- usage/request id 提取；
- 原始响应到统一候选结果的转换。

Adapter 不负责：

- 选择捕获区域；
- 决定是否允许把图片发给该 Provider；
- 跨 Provider fallback；
- 把未通过本地验证的 JSON 标为成功；
- 写入错题本或直接操作 UI。

传输与 stage 语义必须分层：

```text
TransportResponse
  plan_id: UUID
  stage_id: UUID
  operation_id: UUID
  request_envelope_digest: Digest256
  http_status: int
  provider_request_id: string | null
  usage: object | null
  raw_response: ephemeral object | bytes | null

StageResult = AnswerCandidateResult | OcrCandidateResult | OperationReceipt

AnswerCandidateResult
  candidate_payload: object | string | null
  refusal: normalized refusal | null
  finish_reason: string | null
  provider_request_id: string | null
  usage: object | null

OcrCandidateResult
  candidate_document: object
  provider_request_id: string | null
  usage: object | null

OperationReceipt
  operation_id: UUID
  kind: uploaded | deleted | discovered
  opaque_reference: ephemeral string | null
```

TransportResponse 的 plan/stage/operation/envelope 必须与 session 和显式 frozen operation 完全一致，否则在 decode 前失败。`raw_response` 只允许在当前调用栈内用于 Decoder/ErrorMapper，默认不得持久化或记录。只有 AnswerCandidateResult 可以进入 ResultValidator 并转换为 SolveResult；OcrCandidateResult 必须先进入 QuestionDocumentValidator 与 OcrQualityGate；未来 upload/delete/model-discovery 使用 OperationReceipt，不能冒充答案结果。Adapter 不得自行绕过对应 Validator。

第二阶段的 OCR 最小能力契约为：

```text
OcrCapabilities
  component_id: string
  component_version: string
  supported_languages[]: BCP-47
  supports_bounding_boxes: bool
  bbox_coordinate_spaces[]: pixel | normalized_0_1
  supports_reading_order: bool
  formulas: none | text | structured
  tables: none | text | structured
  quality_signal: none | provider_specific | normalized
  min_verified_quality: number 0..1 | not_applicable
  supported_mime_types[]
  max_image_bytes: positive int
  max_image_pixels: positive int
  network_scope: none | loopback | lan | internet
  compute_location: local_verified | remote | unknown
  capabilities_ref: string
  capabilities_digest: Digest256
```

OCR stage 可以使用 `component_id/version`，不强制伪装成生成模型 `model_id`。缺少公式、表格或布局保真能力时，OcrQualityGate 必须根据题面特征返回 `unsupported_input` 或 `insufficient_input`，不能继续交给文本模型猜测。

### 5.4 第一阶段候选适配族

候选表表示架构兼容方向，不表示全部在第一阶段实现，也不承诺某个具体型号永久可用。

| Provider | Adapter family | 图片序列化 | 结构化输出基线 | 角色 |
|---|---|---|---|---|
| 智谱 GLM | `openai_chat_compatible` + `zhipu` profile | URL / Data URI | 视觉型号首版按 `prompt_only`，实测后才能升级 | Phase 1A 显式开发迁移起点，不是发布默认项 |
| OpenAI | `openai_responses` | `input_image` URL / Data URI / file id | 支持的型号可用原生 JSON Schema；按 profile/model 验证 | 不同协议族候选 |
| Anthropic Claude API | `anthropic_messages` | image block：base64 / URL / file id | 支持的型号/平台可用原生 JSON Schema | 不同协议族候选；不依赖其兼容层 |
| Google Gemini | `gemini_interactions` 或 `openai_chat_compatible` + `gemini_beta` profile | Interactions：`image.data` raw base64 / `image.uri`；兼容层：`image_url` Data URI | 按 adapter/profile 验证 Schema | native profile 钉住 API version 并设置 `store=false`；兼容层仍按 beta 对待 |
| 阿里 Qwen / DashScope | `openai_chat_compatible` + 地域 profile | URL / Data URI | `json_object` / `json_schema` 按型号和思考模式门控 | 第二个兼容 profile；不计作不同协议族 |
| Ollama | `ollama_api_chat` + local profile | REST `messages[].images[]` raw base64 | 仅已验证本地 runtime/模型按 Schema 能力启用 | 本地实验路线；loopback 不等于本地执行 |

第一阶段最低交付不是“实现所有候选”，而是：

1. GLM profile 迁移到新契约；
2. 至少增加一个不同协议族的真实多模态 Adapter，以证明核心层没有绑定 Chat Completions；
3. 其余候选的 exact binding 只在通过验收后加入 supported registry。

当前官方参考：

- 智谱：[GLM-4.6V-Flash](https://docs.bigmodel.cn/cn/guide/models/free/glm-4.6v-flash)、[OpenAI API 兼容](https://docs.bigmodel.cn/cn/guide/develop/openai/introduction)、[Chat Completions API](https://docs.bigmodel.cn/api-reference/模型-api/对话补全)
- OpenAI：[Responses API](https://developers.openai.com/api/reference/cli/resources/responses/methods/create)、[Image inputs](https://developers.openai.com/api/docs/guides/images-vision)、[Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)、[Data controls / retention](https://developers.openai.com/api/docs/guides/your-data)
- Anthropic：[Vision](https://platform.claude.com/docs/en/build-with-claude/vision)、[Structured Outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)、[OpenAI compatibility limits](https://platform.claude.com/docs/zh-CN/cli-sdks-libraries/libraries/openai-sdk)
- Google：[Interactions API](https://ai.google.dev/gemini-api/docs/interactions-overview)、[API versions](https://ai.google.dev/gemini-api/docs/api-versions)、[Gemini OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai)、[Image understanding](https://ai.google.dev/gemini-api/docs/image-understanding)、[Structured Outputs](https://ai.google.dev/gemini-api/docs/structured-output)
- 阿里云：[Qwen OpenAI-compatible Chat Completions](https://www.alibabacloud.com/help/en/model-studio/qwen-api-via-openai-chat-completions)、[视觉模型](https://www.alibabacloud.com/help/en/model-studio/vision-model)、[Structured Outputs](https://help.aliyun.com/zh/model-studio/qwen-structured-output)
- Ollama：[Vision](https://docs.ollama.com/capabilities/vision)、[Structured Outputs](https://docs.ollama.com/capabilities/structured-outputs)、[Cloud / local-only mode](https://docs.ollama.com/cloud)

型号、价格、限流、地域和数据政策在实现每个 profile 时必须重新核验；本文不把这些易变信息写成永久事实。

---

## 6. 路由、选择与 fallback

### 6.1 第一阶段选择规则

- 用户必须通过配置或 UI 显式选择 `pipeline_profile_id`。
- RoutePlanner 只做硬性校验，不根据题型偷偷更换模型。
- 截屏前的计划校验顺序：
  1. pipeline 是否启用；
  2. 输入模态是否支持；
  3. endpoint 与 credential reference/binding 元数据（如适用）是否符合策略（不读取密钥值、不联网）；
  4. 用户同意是否覆盖当前 Provider/host/data-kind；
  5. timeout、输出 token 与调用预算是否可满足。
- `SolveIntent.timeout_budget_ms` 与 `max_output_tokens` 只能收紧 profile 上限；RoutePlanner 使用较小值并固化到 plan，调用方不能借此绕过成本策略。
- 截屏后的 InputValidator 再校验图片 MIME、字节、像素、数量、空白帧与黑帧；失败时网络调用次数必须为零。
- 任一硬条件失败必须停止，不得寻找隐式替代 Provider。

### 6.2 fallback 规则

Phase 1：**禁止运行时 fallback**。主 profile 失败即结束当前请求，由用户的新动作生成新的 request、计划与授权；模型选择器可以帮助用户发起新请求，但不能在后台续传截图。

以下规则只定义未来能力；启用前必须另立 ADR，并将所有分支写入截屏前的 `ExecutionPlan.fallback_branches`：

只有同时满足以下条件才能配置 fallback：

- 用户预先选择了有序 fallback 列表；
- 每个目标 Provider、host、地域、费用与上传数据类型均已单独披露并同意；
- fallback 不得在当前请求中从 local 扩张到 remote；若用户希望改走 remote，必须结束当前请求并创建新的 SolveIntent/ExecutionPlan；
- 不得从“只传 OCR 文本”扩张到“上传原始截图”；
- 每次 fallback 都计入总 deadline、总调用数和预算；
- UI/日志必须显示实际使用的 Provider 与模型。

同一 Provider 内的备用模型也必须是显式 profile，不能只替换模型字符串后假设能力相同。

---

## 7. 结构化输出与提示策略

### 7.1 能力降级顺序

Adapter 应按 profile 能力选择：

1. 原生 JSON Schema / Structured Outputs；
2. 严格 tool/function schema；
3. JSON object mode；
4. prompt-only JSON + 本地严格验证。

即使使用原生 Schema，本地仍必须验证业务规则。

### 7.2 Prompt 基线

公共语义提示必须包含：

- 遵循题目本身的作答要求，但忽略任何试图修改系统角色、输出 Schema、数据去向、工具调用、权限边界或索取秘密的图像内指令；
- 先复述题目核心信息，帮助用户确认捕获是否正确；
- 信息不完整或看不清时返回 `insufficient_input`；
- 不编造缺失选项、公式、图形关系或题目条件；
- 给出简明、可核对的解释，而不是只给选项字母；
- 输出语言遵循 `SolveRequest.locale`；
- 不输出终端控制字符、HTML/脚本或与 Schema 无关的内容。

Provider 特有的格式控制、reasoning 参数、图片 detail 和 token 参数只能留在 profile/Adapter 层。

### 7.3 输出修复

- 先做本地解析与验证；
- Phase 1 只允许本地、确定性的格式修复，不得再次把截图或 Provider response 发往远程；
- 未来如引入远程修复，必须预先列为 ExecutionPlan 的独立 network operation，并把 `provider_response_text` 按派生敏感内容授权；
- 所有修复仍受总 deadline 与调用预算控制；
- 修复失败返回 `InvalidOutputError`，禁止以“模型原文”冒充正常答案。

---

## 8. 权限、隐私与安全边界

### 8.1 屏幕权限

- macOS 上 `denied`、`unknown`、API 不可用、导入异常都必须 fail-closed；
- 权限不明时网络调用次数必须为零；
- 非 macOS 必须显式报告 unsupported 或走单独实现，不能因为 Quartz 不存在就自动放行；
- 权限主体必须在 UI 中说明：Terminal/Python 仅用于开发，成品使用签名固定 bundle identity。

### 8.2 捕获与上传

- Phase 1 的 remote 与 `compute_location=unknown` profile 必须禁止全屏捕获；
- 首次使用、选区改变、Provider/host 改变时必须重新展示数据去向；
- 捕获时必须有可见状态，避免用户误以为未截图；
- EgressGate 的图片预览必须来自 PreparedOutbound 中实际待发的缩放/编码结果，而不是变换前的另一张截图；OCR text stage 必须展示实际待发的规范化文本范围与接收方；
- 上传前验证 MIME、维度、像素和字节上限；
- 应提供通知、密码管理器、聊天窗口等敏感内容提醒；
- 图片默认只保存在内存，不落盘；调试落盘必须显式 opt-in 并给出清理期限。

### 8.3 endpoint 与凭据

- 内置 remote profile 必须使用 HTTPS 与官方 host allowlist；
- 所有 `network_scope=lan|internet` 请求都必须启用证书链与 hostname 校验；`verify=false` 或跳过 hostname 一律 fail-closed，experimental/dev 也不例外。受控 custom CA 可以使用，但仍必须实际验证并绑定版本化 `tls_policy_ref`；用户任意指定 CA 不得进入 supported。显式建模的 loopback HTTP 是唯一例外；
- 自定义 endpoint 默认关闭；启用时必须显式 `allow_custom_endpoint`、显示实际 host，并拒绝明文远程 HTTP；
- loopback 服务可以使用 HTTP，但必须确认地址是 loopback，不接受任意局域网地址冒充 local；loopback 只描述网络入口，不能证明模型在本机执行，`local_verified` 必须由受控运行时检查与配置证明；
- Ollama 只有在已验证 daemon 禁用 cloud 功能（例如渲染配置满足 `OLLAMA_NO_CLOUD=1`）、exact model 由本地 inventory/运行时证据证明已安装并在本机执行、且出站网络检查符合发布策略时才能标为 `local_verified`；禁止按 model id 命名猜测本地性，否则只能是 `unknown` 或 `remote`；
- 禁止 URL userinfo、query 中的密钥；Phase 1 禁止自动跟随任何 HTTP 重定向，不能重放凭据、图片或请求体；
- 每个 Provider 使用独立 credential reference，禁止把 GLM Key 自动发往其他兼容端点；
- 所有 remote/custom credential 的权威绑定必须来自受控 Registry 或 secret-store 元数据，并覆盖 `provider_id + canonical scheme/host/port + normalized allowed base-path set + endpoint_policy_version + network_policy_version + tls_policy_ref`；用户可编辑配置中的字符串只能引用该绑定，不能成为权威来源；
- URL 策略必须按解析后的组件比较并规范化 IDNA host、默认端口、`.`/`..` path segment 与 percent encoding，禁止字符串前缀判断、userinfo、fragment 和含 secret 的 query；任意 3xx 都映射为 `EndpointPolicyError`，不得重放 body/credential；
- loopback endpoint 必须验证解析后的所有地址和实际连接 peer 都是 loopback；LAN 或混合解析结果不能标为 local；
- 目标形态使用 Keychain；开发期可用环境变量，但 Config `repr`、日志和异常中不得暴露密钥；
- endpoint/path/TLS/network policy 改变后旧 Plan、supported evidence、隐私同意和 credential binding 都失效；custom endpoint 必须建立新的 profile 与 credential reference。
- 无状态截图求解 profile 在协议支持时必须显式关闭可配置的 application state / interaction storage，例如 OpenAI Responses 与 Gemini Interactions 均发送 `store=false`。这不代表零保留；profile 仍必须披露其余 abuse/safety logging 与 retention，禁止宣称 Zero Data Retention，除非该 exact 账号/组织配置有可验证证据。Gemini native profile 还必须钉住已验证 API version，且不能使用依赖服务端留存的 background execution 或 `previous_interaction_id`。无法关闭的状态存储也必须进入 ConsentGrant 的 retention policy。

### 8.4 输出与日志

- 默认不记录截图、base64、OCR 全文、prompt、答案正文、原始响应或密钥；
- 内容持久化默认关闭；启用 StudyStore 必须使用版本化 StoragePolicy，包含保存字段、保留期、导出、逐条/全部删除与过期清理行为；
- 终端和通知输出必须过滤 C0/C1、ANSI/OSC 控制序列并限制长度；
- Presenter 必须把模型输出当作不可信纯文本；禁止渲染 HTML、Markdown 图片、自动链接预览或任何会产生二次网络请求的富文本；
- 通知可关闭或隐藏答案预览；
- 允许记录的字段：request id、profile id、模型、pipeline、图片尺寸/字节、阶段耗时、重试次数、错误类别和 usage；
- 完整图片 hash 只用于本地缓存，不进入普通日志。
- 所有成功、失败、超时和取消终态都必须在统一 `finally` 中释放 CaptureArtifact bytes、PreparedOutbound body、credential handle 与 raw response，并关闭临时流/文件；可变 secret buffer 做 best-effort 清零，但不得声称 Python immutable bytes 可安全擦除；
- 终态后 StudyStore、日志、回调、retry timer 与后台任务不得继续持有上述内容对象，除非用户已通过独立 StoragePolicy 明确授权的字段。

---

## 9. 错误、重试、deadline 与取消

### 9.1 可重试性

| 错误 | 默认行为 |
|---|---|
| 配置、权限、endpoint 策略 | 不重试 |
| 认证/授权失败 | 不重试 |
| 无效请求、模型不存在、payload 过大 | 不重试 |
| 可验证的语义拒答 | 不重试，映射为 `SolveResult.refused` |
| API 在生成结果前的内容策略阻断 | 不重试，映射为 `ContentPolicyError` |
| 输出 Schema 损坏 | Phase 1 最多一次本地确定性格式修复；网络调用 0 次；失败返回 `InvalidOutputError` |
| 429 | 仅遵守 `Retry-After` 且预算允许时重试 |
| 网络中断、连接超时、可重试 5xx | 有限指数退避 + jitter |

### 9.2 总预算

- `ExecutionPlan.timeout_budget_ms` 是可序列化的 duration；PrivacyGate 成功签发 AuthorizationContext 后、进入 PermissionGate/Capture 前，CallContext 立即计算唯一 `MonotonicDeadline`。权限检查、捕获、编码、上传确认等待、网络、retry 与结果验证都计时，wall-clock 调整不能延长请求；超时发生在上传确认前时必须丢弃临时内容且零网络。最终 `awaiting_question_confirmation` 已无后续 Provider 调用，使用单独 UI interaction timeout，不延长或复活执行 deadline；
- 捕获、编码、所有 SDK 内建重试、应用重试、修复和 fallback 共用该时间预算；
- SDK 自动重试必须关闭，或接入同一个可观察的 AttemptBudget；无法证明实际调用次数受控的 Adapter 不得进入 `supported`；
- retry 只能重放计划中的同一个 network operation，不能改变 Provider/profile、model、canonical endpoint、处理地域或 outbound data；次数必须被 consent/cost policy 覆盖，且不得跟随重定向或触发 fallback；
- `max_network_calls_total` 统计每次 outbound operation attempt（含 SDK retry）；一次 attempt 内的 DNS/连接/单个 HTTP 请求合计为一次，但任何额外 HTTP 请求都必须另计。`max_attempts_per_operation` 是每个 operation 的上限；`max_billable_calls` 是其中可能计费的子集，`billable=unknown` 必须按可能计费扣减；
- 本地确定性 repair 不增加网络调用；未来上传/file-id 流程必须预留 delete 调用，不得因预算耗尽而悄悄放弃计划中的清理；
- 三类计数都必须配置并可观察，实际尝试前先原子扣减对应预算；
- 调用方等待时间必须覆盖整个 pipeline，不能只等单次 HTTP timeout；
- 退出时必须取消或等待非 daemon 工作，禁止静默杀死仍在发送截图的线程。

### 9.3 用户可见状态

Presenter 至少支持：

```text
idle → planning → awaiting_consent → awaiting_permission
     → capturing → validating_input → awaiting_upload_confirmation → requesting

requesting ──retryable + budget──→ retrying ──→ requesting
requesting ──next remote stage───→ awaiting_upload_confirmation
requesting ──valid answered──────→ awaiting_question_confirmation → answered
requesting ──non-answer result───→ insufficient_input | refused | unsupported_input
任意进行中状态 ────────────────→ failed | cancelled
```

`retrying` 是可选分支，不是每次请求的必经状态。`awaiting_upload_confirmation` 属于每个远程 stage 发送前的 EgressGate；`awaiting_question_confirmation` 只在已得到可展示的题面摘要后让用户核对，二者不得合并。

全局热键模式下也必须可见失败、限流和重试状态，不能只写到隐藏终端。

---

## 10. 配置规格

目标配置使用 profile，而不是不断增加全局 `GLM_*` 变量。以下仅为开发/迁移示意；`experimental` profile 不得成为发布版默认项：

```toml
active_pipeline_profile = "direct-zhipu-glm"

[pipeline_profiles.direct-zhipu-glm]
pipeline_kind = "direct_multimodal"
stages = ["zhipu/glm-4.6v-flash"]
timeout_budget_ms = 40000
max_network_calls_total = 2
max_attempts_per_operation = 2
max_billable_calls = 2
max_output_tokens = 1024

[provider_profiles.zhipu]
adapter_family = "openai_chat_compatible"
provider_id = "zhipu"
base_url = "https://open.bigmodel.cn/api/paas/v4"
allowed_origins = ["https://open.bigmodel.cn"]
allowed_path_prefixes = ["/api/paas/v4/"]
endpoint_policy_version = "zhipu-official-v1"
network_policy_version = "remote-https-v1"
tls_policy_ref = "system-trust-hostname-verify-v1"
credential_ref = "env:ZHIPU_API_KEY"
credential_binding_ref = "registry:zhipu-official-v1"
api_version = "v4"
network_scope = "internet"
compute_location = "remote"
processing_region = "unknown"
provider_application_state = "unknown"
retention_policy_snapshot = "registry:zhipu-retention@2026-08-28"
data_policy_snapshot = "registry:zhipu-data-policy@2026-08-28"

[[provider_profiles.zhipu.models]]
model_id = "glm-4.6v-flash"
capabilities_ref = "zhipu/glm-4.6v-flash@verified-date"
```

规范：

- 配置文件只保存 credential reference，不保存真实 key；
- policy snapshot reference 只能解析到受控 Registry 中的不可变 ref+digest+verified/expiry 元数据；解析出的 digests 必须进入 provider/pipeline profile digest，不能由用户配置覆盖；
- `availability` 不属于用户可编辑配置；它只能由受控 VerificationRecord 计算并通过只读 Registry 暴露；
- `pipeline_profile_id` 与各 stage 的 `provider_profile_id/model_id` 必须分离；direct pipeline 展开为一个 stage，OCR pipeline 展开为 OCR 与 text solver 两个 stage；
- 字段按 stage/transport 条件校验：生成 stage 必须有 `model_id`，OCR stage 必须有 `component_id/version`；含网络 operation 的 stage 必须有完整 endpoint/path policy，严格 in-process local stage 不要求 `base_url`；需认证 operation 必须有权威 credential binding，无认证 loopback operation 必须显式为 `not_applicable`，不得以空白/缺失冒充；
- 空白字段、非法 URL、非正宽高、未知 capability 必须在启动时失败；
- M2 可以把现有 `GLM_API_KEY`、`GLM_BASE_URL`、`GLM_MODEL` 名称作为迁移期输入，但当前冻结入口不得读取；未来也只能映射到一个显式 legacy profile 并给出弃用提示，且 legacy `GLM_BASE_URL` 只接受官方 origin，自定义地址必须创建独立 profile；
- profile 的 verified date、测试结果、处理位置/地域和数据政策必须可追踪；
- 不在 Spec 中固化“永久免费”或永久限流数字。

---

## 11. 测试、评测与 supported 定义

### 11.1 测试层级

1. **纯领域单测**：Schema、路由硬条件、权限 fail-closed、配置、错误映射、预算计算，以及各安全 digest 的 canonical golden vectors；
2. **Adapter contract tests**：用录制 fixture 验证请求序列化、响应解析、usage、错误映射，禁止触网；
3. **安全回归**，至少覆盖：
   - consent、权限、选区、输入校验或 EgressGate 任一失败时，secret resolver、SDK client/model discovery、DNS/socket/HTTP 均为零；
   - scope fingerprint 或 credential binding 不匹配时零网络，exact endpoint 由 network spy 验证；
   - one-shot EgressApproval 在并发下也只能原子消费一次；grant/AuthorizationContext/approval 过期或撤销、重复消费、method/URL/query/header/body/envelope digest 改变均失败；
   - plan 生成后 profile/capability/adapter/endpoint/credential snapshot 热重载不影响该 plan；snapshot mismatch 必须零网络失败；
   - retention/data/cost policy 同名 ref 的 digest、有效期或内容变化会使旧 Plan/grant/evidence 失效；
   - AuthorizedSendSession 只能重放同一 operation/request envelope；用户取消或授权撤销会中断退避并阻止下一次 attempt，超过授权 attempt 或总调用/计费预算时不得触网；
   - Phase 1 remote/unknown 全屏拒绝、无隐式 fallback、任意 3xx 不重放 body/credential；
   - 使用 taint sentinel 证明截图/OCR/user hint/答案内容不会出现在 URL、query、header、日志或异常中，只能位于获批 body；
   - custom profile 不能把自己提升为 `supported`，`compute_location=unknown` 必须采用 remote 规则；
   - TLS/hostname 校验不可关闭，network/TLS policy mismatch 为零网络；
   - 日志、异常和 fixture 不含 key、Authorization、data URL、图片、prompt 或原始响应；输出控制字符被过滤，富文本不触发二次网络；所有终态后内容对象不被 Store/后台任务持有；
4. **opt-in live smoke**：每个 profile 使用非敏感合成题图做真实 API 验证；不得在普通单测中运行；
5. **macOS 用户路径 E2E**：授权、选区、触发、取消、重试、通知、退出；
6. **离线题型 eval**：比较不同 profile 的能力，而不是以单次成功判断支持。

### 11.2 Eval 数据集

首版至少覆盖：

- 中文、英文与中英混合；
- 选择、判断、填空、简答；
- 公式、几何、图表、表格、电路或示意图；
- 小字、低对比度、裁切不完整、含无关窗口；
- 明确不可答样例；
- 图像内 prompt injection 与恶意控制字符样例。

数据集必须是自建、获授权或合成数据，不收录真实敏感屏幕。

### 11.3 指标

- 题面识别正确率；
- 最终答案准确率（按题型拆分）；
- `insufficient_input` 的正确拒答率与误拒答率；
- Schema 合法率与修复率；
- p50/p95 端到端延迟；
- 平均上传字节、输入/输出 usage；
- 429/5xx/timeout 与重试放大率；
- 单次触发对应的实际 Provider 调用数；
- 退出/取消后仍在运行的请求数。

模型自报 confidence 不作为准确率指标。

### 11.4 `supported` 门槛

支持状态按 exact binding 计算，而不是给整个 Provider 粗略贴标签：

- `model_binding = provider_profile_id + provider_profile_digest + exact model_id + capabilities_digest + adapter_version + endpoint/network/TLS policy versions`；
- OCR 使用等价的 `component_binding`，以 `component_id/version` 代替 model id；
- `pipeline_profile` 还绑定自身 digest、prompt policy、结果 Validator/Schema 与图片预处理版本；只有所有必需 binding 均为 `supported`、组合契约/eval/E2E 也通过时才是 `supported`。任一 binding 或行为版本降级会使 pipeline 同步降级。

一个 binding 只有满足以下条件才能成为 `supported`：

- 配置、capability、runtime（如适用）与 endpoint/network policy 经过版本化 VerificationRecord 绑定；
- contract tests 全部通过；
- 非敏感 live smoke 通过；
- malformed 输出绝不进入 answered；
- 权限未知、endpoint 不可信、未获同意、没有有效选区或图片校验失败时网络调用为零；
- 无静默跨 Provider fallback；
- 完成分题型 eval 并公开记录基线、日期、模型 id 与限制；
- 完成当前 macOS 版本上的端到端验收。

`supported` 还必须满足已经批准的分题型准确率与拒答阈值；阈值在首轮基线完成后由产品决策确定。阈值确定并满足之前只能标为 `experimental`。发布版默认列表只显示 supported pipeline；开发模式可显式选择 experimental binding，但必须醒目标注且不能被配置自我晋级。

---

## 12. 分阶段实施计划

### Spec-0：本次规格更新

- 固化双通道、统一契约、隐私边界和验收门槛；
- 不修改运行代码；
- README 同步作为独立工作项，本轮不把目标能力写成当前功能。

### Phase 1A：多模态基础重构

- `M0`：冻结 MVP-0 的真实截图远程旁路；新链未完成前，stdin、hotkey、app/orchestrator 及所有可达入口均不得继续直连 `capture_data_url → provider.answer`；
- `M1`：引入纯标准库领域契约、typed errors、版本化 canonical digest 与严格结果校验；
- `M2`：实现 Registry snapshot、显式 RoutePlanner、不可变单 stage ExecutionPlan、PrivacyGate 与 AuthorizationContext；
- `M3`：实现三态且 fail-closed 的 PermissionGate、明确选区、Provider-neutral `CaptureArtifact`、CapturePolicy 与 InputValidator；
- `M4`：将 GLM 迁入 Registry + 纯 `prepare/decode` 的 `openai_chat_compatible` Adapter；
- `M5`：实现实际 outbound 预览、逐次 EgressApproval、AuthorizedSendSession、延迟 secret/client、exact envelope、总 deadline/attempt budget、取消与清理；
- `M6`：仅用仓库内固定、非敏感合成题图执行 opt-in GLM live smoke；
- `M7`：把 macOS 真实选区接入已经通过 M0–M6 的同一安全链，并保持 `experimental`；
- 严格验证结果，禁止空 JSON 成功；GLM 不进入默认用户列表；当前 fail-open、默认全屏、任意 endpoint、raw fallback 与不受控重试均不属于兼容目标。

**当前实现状态（2026-08-28 工作区）**：M0 与 M1 已完成；M2–M9 均未完成。应用被有意冻结，没有截图、密钥解析、SDK 构造、网络、live smoke 或真实 macOS E2E。Phase 1 的 query 固定为空；`exact` query 仅保留枚举位置，在 M2 由可信 endpoint profile 约束前一律拒绝。

`M1` 的离线脚手架已与 `M0` 并行完成；任何真实 Provider、真实截图或默认入口切换仍必须严格按 M2→M3→M4→M5→M6→M7 的剩余门禁推进。详细工作包、依赖和当前状态以 Implementation Plan 为准；Plan 不得弱化本 Spec 的约束。

**验收**：迁移后的纯逻辑测试通过；新增安全与契约测试；GLM 合成题图 live smoke 通过；真实用户远程截图路径只有在最小选区/预览/Egress 链完整且 M0–M6 全部通过时才可启用。所有 pre-gate 失败均为零 secret resolve、零 SDK 构造、零 DNS/socket/HTTP。

### Phase 1B：证明多 Provider 抽象

- 新增至少一个不同协议族的原生多模态 Adapter；
- 加入 profile selector 与启动时 Provider/host/data-kind 提示；
- 完成两个 profile 的同一 eval 集对比；
- 验证不同结构化输出能力的降级链。

**验收**：核心编排代码无需出现供应商条件分支；第二个不同协议族 binding 至少完成 contract/live smoke/eval 并明确标为 experimental。只有两个不同协议族的 exact binding 及其 direct pipeline 均达到 `supported`，才可以宣称“正式多模型支持”。

### Phase 1C：多模态可用性与学习 UX

- 图形化选区、NSPanel 预览、区域记忆与敏感内容提醒（在 Phase 1A 最小安全链上做体验升级）；
- 主线程状态/UI 调度；
- 先确认题面，再查看答案；
- 本地哈希缓存、调用预算和非敏感可观测性；
- SQLite 错题本与复习入口。

**验收**：远程上传前可以核对实际选区与接收方；模型响应后可以先核对题面摘要再揭示答案；持久化内容可查看、删除，且截图默认不保存。

**Phase 1 exit gate**：GLM 与至少一个不同协议族的 exact binding、以及引用它们的 direct pipeline 均达到 `supported`；OCR route 仍不可执行；安全合同、统一 eval 与当前 macOS E2E 全部通过。未达到时只能称为“多 Provider 抽象/实验支持”。

### Phase 2：OCR + 文本模型

- 实现 `OcrAdapter` 与 `QuestionDocument`；
- 先接一个本地 OCR，再接一个 TextModelAdapter；
- 增加公式、布局、OCR 质量与拒答评测；
- 单独披露 OCR 与文本模型的数据处理边界；
- 只有用户显式选择 `ocr_text` profile 时才启用。

**验收**：OCR 故障与低质量/不支持题面能稳定区分；QuestionDocument Schema、source/content digest 与质量门控全部通过；原图绝不进入 text model payload；每个远程 stage 都有独立且不可复用的 EgressApproval/AuthorizedSendSession；OCR 专项 eval 与当前 macOS E2E 通过。未满足前 `ocr_text` 不得进入默认列表，也不得作为 direct pipeline fallback。

### Phase 3：分发与生产级本地隐私路线

- 签名、公证 `.app` 与固定 TCC identity；
- Keychain；
- Carbon 或签名 helper 热键；
- 把 Phase 1/2 的实验性本地 profile 升级为随签名应用分发、可验证不出网的生产 profile；
- 依赖锁、SBOM、CI、安全扫描、发布与回滚流程。

---

## 13. 目标目录结构

```text
snapquiz/
├── app.py
├── config/
│   ├── loader.py
│   ├── models.py
│   └── profiles.py
├── domain/
│   ├── capture.py              # CaptureArtifact
│   ├── solve.py                # SolveRequest / SolveResult
│   ├── digest.py               # versioned canonical digest
│   ├── errors.py
│   └── capabilities.py
├── capture/
│   ├── screen.py
│   └── policy.py
├── routing/
│   ├── registry.py
│   └── planner.py
├── pipelines/
│   ├── multimodal.py
│   └── ocr_text.py             # Phase 2 前不可运行
├── adapters/
│   ├── base.py
│   ├── openai_chat_compatible.py
│   ├── openai_responses.py
│   ├── anthropic_messages.py
│   ├── gemini_interactions.py
│   ├── ollama_api_chat.py
│   └── ocr/                    # Phase 2
├── result/
│   ├── validator.py
│   └── schema.py
├── privacy/
│   ├── consent.py              # ConsentGrant / AuthorizationContext
│   └── egress.py               # EgressGate / one-shot approval
├── transport/
│   ├── contracts.py            # PreparedOutbound / exact envelope
│   ├── session.py              # AuthorizedSendSession
│   └── http.py                 # TLS / redirect / credential injection
├── runtime/
│   ├── context.py              # deadline / cancellation
│   └── budget.py               # atomic call and billing budgets
├── present/
├── study/
└── observability/
```

目录是目标边界，不要求一次性创建空文件。只在对应阶段实际实现模块。

---

## 14. 主要风险与应对

| 风险 | 应对 |
|---|---|
| “OpenAI-compatible” 兼容程度不一致 | profile 能力白名单 + contract test；未知字段不透传 |
| 模型名、价格、限流变化 | model/profile 分离；实现时重新核验；记录 verified date |
| 同一截图被重试或 fallback 多次上传 | 单一调用预算；默认无跨 Provider fallback；观测实际调用数 |
| 模型自信错答 | 题面摘要、简明解析、正确拒答 eval；自报 confidence 不冒充准确率 |
| 全屏泄露敏感内容 | Phase 1 remote/unknown 强制选区/预览并拒绝全屏；权限与 endpoint fail-closed |
| 图片 prompt injection | 公共提示隔离图像指令；严格 Schema；输出清洗；安全评测样例 |
| 多 Provider 导致配置/密钥混乱 | 独立 credential reference；profile 显示真实 host；不复用密钥 |
| OCR 路丢失公式和布局 | 结构化 QuestionDocument；质量门控；Phase 2 专项 eval |
| UI 主线程与后台任务冲突 | pipeline 只产出事件/结果；Presenter 通过主线程 dispatcher 更新 |
| 规划被误写成现状 | README 与 Spec 都显式标 Current/Target/Planned；验收后才改状态 |

---

## 15. 待确认决策

| ID | 决策 | 当前建议 |
|---|---|---|
| O1 | 第一阶段第二个原生 Adapter | 只选一个不同协议族；按账号可用性、地域、成本和 eval 决定 |
| O2 | Phase 1 后是否通过独立 ADR 允许 remote full-screen | Phase 1 已定为禁止；未来只能基于新威胁模型、逐次 scope/payload 授权和专项安全验收决定 |
| O3 | profile 配置文件位置/格式 | TOML + Keychain/env credential reference |
| O4 | 首轮准确率门槛 | 先构建代表性 eval 基线，再按题型设门槛 |
| O5 | 第一阶段是否加入本地 Ollama | 可作为实验 profile，不阻塞云端双 Provider 验收 |
| O6 | Phase 2 首个 OCR | 优先本地方案；依据中文、公式、布局评测选择 |

---

### 一句话总结

v3 的重点不是“把 GLM 换成更多模型名”，而是建立一套不会泄露隐私、不会静默换云、不会把坏 JSON 当答案、且能用统一评测证明支持程度的双通道模型架构。第一阶段先把多模态直连做正确，并用至少两个不同协议族验证抽象；OCR + 文本模型在第二阶段沿同一领域契约接入。
