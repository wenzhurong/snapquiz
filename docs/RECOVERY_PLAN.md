# snapquiz 恢复与推进计划

> **状态**：Active，取代 `IMPLEMENTATION_PLAN.md` 作为执行依据。
> **基线**：`main@341374b` + 未提交的 W10 工作区。
> **评估日期**：2026-09-14。

**目标**：让 `snapquiz` 在一周内重新成为一个能按下热键、截一张题图、拿到答案的工具；
同时保留 v3 中真正有价值的安全不变量，删除为错误威胁模型服务的 5.4 万行基础设施。

**方法**：反转门禁顺序。当前 spec 把"第一次真实 API 调用"放在 M6、把"真实截图"放在 M7、
把"评测集"放在 M9 之后；本计划把这三件事分别放在 Task 3、Task 4、Task 7。

---

## 0. 全局约束（每个 Task 隐含包含）

这些约束直接来自对前 8 周的复盘，违反其中任何一条都应该让 Task 不通过评审。

1. **验收判据必须在代码之外。** 每个 Task 的 gate 是"你能用它做到 X"，不是"测试全绿"或
   "P0/P1 = 0"。后者可以靠写更多代码满足，这正是项目走到 7.6 万行不可达代码的机制。
2. **不新增门禁。** 不写新的 `PRODUCTION_*_AVAILABLE = False`，不写新的 fail-closed 占位实现。
   一个能力要么本 Task 交付可用，要么不写。
3. **不新增账本 / 租约 / 归属证明层。** `ledger` / `lease` / `permit` / `attestation` /
   `owner claim` 这些词在新代码里出现即视为超范围。
4. **同一事实只校验一次。** v3 里存在同一个 `PreparedOutbound` 被 prepare 两次、
   digest 被独立复核三次的模式。新代码里，一个不变量在一个地方断言。
5. **不裸用"继续推进"派发。** 每次会话必须带上本文件里某个 Task 的编号与它的验收句。
6. **Python ≥ 3.10**（`pyproject.toml` 现有下限），macOS 为唯一目标平台。
7. **密钥只从 `.env` 或 Keychain 读，永不进 git、永不进日志、永不进异常消息。**

---

## 1. 现状清点（精确行数，已逐文件核对）

`snapquiz/` 共 **76,457 行** / 87 模块。从唯一入口 `snapquiz.app:main` 可达 **80 行（0.1%）**，
其功能是打印"已禁用"并返回退出码 3。

| 分类 | 行数 | 文件数 | 处置 |
|---|---:|---:|---|
| **A. 可原样存活的纯核** | 2,651 | 15 | 直接复用，删掉其余一切后仍可 import |
| **B. 需重写（不是瘦身）** | 16,588 | 12 | 从中抄出纯函数，重写为 ≈1,200 行 |
| **C. 暂缓（多 Provider）** | 3,643 | 4 | 留在 tag 上，Phase C 再回收 |
| **D. 移除** | 53,575 | 56 | 打 tag 后从主干删除 |
| | | | + `native/` 4,448 行 C |

> ### ⚠ 关键结构事实（已用导入图验证，直接决定 Task 2 的做法）
>
> **v3 的各层无法按文件切分。** `domain/plan.py` 的 `ExecutionPlan` →
> `routing/planner.py` 的 `PlannedExecution` 这条对象链贯穿了 domain 之上的**每一个**模块：
> `egress` / `consent` / `session` / `credentials` / `context` / `multimodal` / `contracts` /
> `capture/validation` / `openai_chat_compatible` / `adapters/base` 全部直接 import 它。
>
> 所以"保留文件但瘦身"是做不到的 —— 让这些文件长到 2,000 行的**正是**这条
> PlannedExecution/Registry 穿线本身。减掉穿线，文件就不剩什么了。
>
> 正确做法：**从纯核（A，2,651 行）向上重写中间层（约 1,200 行新代码），
> 从 B 类文件里抄出自包含的纯函数。** 不要试图 `git rm` 完 D+C 然后让 B 编译通过 ——
> 那会在第一条 `git rm` 之后立刻 ImportError。

### A. 可原样存活的纯核（2,651 行 / 15 文件）

以下 15 个文件构成一个**自闭包**：删光仓库里其余所有 Python，它们仍然能 import、能测试。
这是 8 周工作里真正的可回收资产。

| 文件 | 行 | 为什么留 |
|---|---:|---|
| `result/validator.py` | 186 | 严格结果校验，非强制转换，拒绝模型自称 calibrated。**直接解决原审计第 4 条**（`{}` 被判成功）。写得很好，一行不改。 |
| `domain/digest.py` | 168 | canonical JSON + 固定 schema tag，有 golden vectors |
| `domain/solve.py` | 292 | `SolveResult` / `SolveStatus` / `ConfidenceKind` |
| `domain/errors.py` | 130 | typed error，不携带 Provider 原文 |
| `domain/capture.py` | 330 | `CaptureScope` / `CaptureArtifact` |
| `domain/adapter.py` | 457 | `TransportResponse` / `AnswerCandidateResult`，2 MiB 响应上限 |
| `domain/intent.py` | 170 | `SolveIntent` |
| `domain/_validation.py` | 325 | 共享校验 helper |
| `domain/policy.py` | 91 | |
| `adapters/prompt.py` | 59 | 内容寻址的 prompt 策略，含 prompt-injection 隔离语句 |
| `capture/topology.py` | 243 | 显示器几何快照，真实选区要用 |
| `core/busyguard.py` | 50 | 单槽并发护栏，成本护栏，MVP-0 原件 |
| `llm/prompt.py` `llm/parse.py` `llm/base.py` | 155 | MVP-0 原件，Task 2 要用 |

**差一点就进这个闭包的两个**（各只差一条 import，Task 2 顺手修）：

- `domain/outbound.py` (368) —— `PreparedOutbound` + envelope digest。只从 `plan.py` 取 4 个名字：
  `CredentialInjectionSlot` / `ExecutionPlan` / `OutboundDataKind` / `QueryPolicyKind`。
  前三个是轻量枚举/小类，把 `ExecutionPlan` 那处绑定换成 Task 2 的简化配置对象即可救回。
- `domain/__init__.py` (163) —— 只是再导出列表，删掉 `capabilities` / `plan` 两段即可。

### B. 需重写，不是瘦身（16,588 行 → ≈1,200 行新代码）

这些文件**全部**直接 import `PlannedExecution` 或 `ExecutionPlan`，因此不能就地裁剪。
做法是：**新写**一个模块，从旧文件里**抄出自包含的纯函数**，旧文件整个删除。

| 旧文件 | 行 | 新目标 | 抄什么 / 不要什么 |
|---|---:|---:|---|
| `privacy/egress.py` | 2,072 | ~150 | **抄思想**：发送前预览实际出站字节 + 一次性批准。这是 v3 里唯一真正对上本产品威胁的功能。**不要**：`EgressPreviewController`、账本、原子消费、多层 digest 绑定。 |
| `privacy/consent.py` | 2,279 | ~80 | **抄思想**：一条持久化的"我同意把截图传给 open.bigmodel.cn"记录 + 撤销。**不要**：进程内 `ConsentLedger`、revision 重绑防护、unknown 维度逐项确认。 |
| `runtime/context.py` | 2,170 | ~150 | **抄思想**：单个 monotonic deadline + 调用/计费次数预算 + 取消标志。**不要**：`AtomicBudget` 账本、lease、cancellation source 归属证明。 |
| `pipelines/multimodal.py` | 2,375 | ~200 | 全新直线执行器。现版本 30+ 个私有方法在做归属线性化。 |
| `transport/credentials.py` | 3,120 | ~60 | **抄思想**：批准消费后才 resolve secret，用完清零（`_best_effort_zero` 可直接抄）。**不要**：`CredentialHandle` 状态机、staging owner、handle proof。 |
| `transport/session.py` | 1,141 | ~40 | **抄思想**：一次性发送令牌。**不要**：`SendSessionLedger`。 |
| `adapters/openai_chat_compatible.py` | 687 | ~350 | **直接抄这些纯函数**（自包含，无 plan 依赖）：`_strict_json_text` / `_strict_json_bytes` / `_unique_object` / `_validate_json_depth` / `_reject_constant` / `_strict_int` / `_strict_float` / `_map_http_error` / `_provider_error_code`。**不要**：`_validate_execution_binding` 的四重复核。 |
| `capture/validation.py` | 1,005 | ~120 | **直接抄**：`_decode_bounded_png` 的黑帧/空白帧判定与 `BLACK_LUMA_MAX` 阈值。**不要**：完整 PNG signature/chunk CRC/zlib 解码器 —— PNG 是我们自己用 `mss` 生成的，不需要防御恶意 PNG。 |
| `core/permissions.py` | 233 | ~60 | **抄**：`MacOSScreenPermissionProbe.observe` 的探测分支（对 `type(raw) is not bool` 的处理是对的）。**不要**：observation digest、`_authority` 构造守卫、`observed_at == now` 精确相等。 |
| `transport/_exact_tls.py` | 275 | ~80 | **直接抄**：`FORBIDDEN_TLS_ENVIRONMENT_KEYS` 那 7 个变量的屏蔽 + `_HOST_RE`。便宜且正确。 |
| `pipelines/contracts.py` | 537 | ~80 | `SolveRequest` / `StageInvocation` 的字段，去掉 factory 与 plan 绑定 |
| `adapters/base.py` | 46 | ~30 | 只需把 `PlannedExecution` 参数换成简化配置 |

### C. 暂缓（3,643 行，留在 tag 上）

`domain/capabilities.py` (1,393)、`domain/plan.py` (780)、`routing/planner.py` (774)、
`routing/registry.py` (696)。

多 Provider Registry / Plan 机制本身写得正确，但**只有在真的接第二个 Provider 时才有价值**。
现在只有一个 GLM，它引入的间接层让每次改动要穿过 4 个 digest 绑定。Phase C 接第二个模型时回收。

### D. 移除（53,678 行 Python + 4,448 行 C）

| 子系统 | 行数 | 替代物 | 理由 |
|---|---:|---|---|
| **resolver 子系统**（15 文件，含 `http.py` 2,346 —— 它不含任何 HTTP，是 resolver attempt 协调器） | 31,140 | `httpx`（或 `socket.getaddrinfo`） | 把 DNS 解析放进独立子进程、自定义 `SNAPQUIZ-RESOLVER/2` wire 协议、supervisor + proxy + async adapter + output cache 四层。防御目标是被污染的 libc resolver 与 DNS rebinding。本产品是单用户本地工具，调用一个固定官方域名，用自己的 key。 |
| **Darwin 身份 / native 层**（7 文件 + 5 个 `.c`） | 7,737 + 4,448 C | `keyring`（~20 行）或 `.env` | 进程身份归属转移、numeric owner、TLS owner、suspended identity。防御目标是同进程恶意插件与进程身份伪造。项目没有插件系统。 |
| `runtime/attempt.py` | 6,917 | 不需要 | 单文件 8 个类，为 resolver 子进程服务的 permit/gate/stop-authority 机制 |
| `transport/_production_readiness.py` | 2,673 | 不需要 | 关于一组恒为 `False` 的门禁的元记账 |
| `_exact_transport.py` + `_exact_http1.py` | 2,261 | `httpx`（~40 行） | 手写 HTTP/1.1 |
| `capture/policy.py` | 1,081 | Task 4 的 ~40 行 | `CaptureAuthorizationLedger` 机制 |
| `runtime/authority.py` + `clock.py` | 1,110 | 折进瘦身后的 context（~40 行） | Registry 代际租约 |
| legacy 冻结桩（`app.py` `core/legacy.py` `core/orchestrator.py` `llm/glm.py` `capture/screen.py` `legacy_config.py` `config/*`） | 759 | Task 2 重写 | 现在全部 raise |

对应测试：`tests/test_w09_*`（39 个文件）、`tests/test_w10_*`（7 个）、`tests/w09_helpers.py`、
`tests/w10_helpers.py`、`tests/fixtures/*.c`、`tests/fixtures/resolver_*.py`、
`scripts/build_w09_native.py` 一并移除。删除后离线套件从 1,341 个用例 / 568 秒降到约 350 个 / 20 秒以内。

---

## 1.5 各阶段成品形态（实体产出）

| | 阶段 A 结束 | 阶段 B 结束 | 阶段 C 结束 |
|---|---|---|---|
| **形态** | venv + 终端命令 | 常驻后台 + 浮层窗口 | `SnapQuiz.app` |
| **可双击** | ❌ | ❌ | ✅ |
| **启动方式** | `source .venv/bin/activate && snapquiz` | 同左，但可脱离终端焦点 | 双击 / 登录自启 |
| **屏幕录制权限授给** | **终端.app** | 终端.app | **SnapQuiz 自己** |
| **数据资产** | 两个 json 配置 | **SQLite 错题本 + 准确率报告** | 同左 + Keychain |
| **能给别人用** | ❌ 对方要装 Python | ❌ | ✅（签名后） |
| **日常摩擦** | 开终端 → 激活 venv → 跑 | 开终端跑一次，之后按热键 | 按热键 |

### 阶段 A 成品：一个能用的终端工具

**没有可双击的东西。** 产出是一个 Python 包和一个 console script。

完整使用流程：

```
$ cd ~/Desktop/robot/snapquiz && source .venv/bin/activate
$ snapquiz
snapquiz 就绪。按 Enter 解题，Ctrl-C 退出。
⏎
  → 屏幕变暗，出现十字准星（macOS 原生选区）
  → 拖框选中题目
  → 预览：即将上传 1 张 PNG，812×430，47 KB，目标 open.bigmodel.cn
     发送？[y/N] y
  → 答案:B
     置信度:82%
     解析:……
  （同时弹一条 macOS 通知）
```

落到磁盘上的东西：`~/.snapquiz/consent.json`（一次性同意记录）、
`~/.snapquiz/region.json`（记住的选区）、`.env`（**明文 API key**，已 gitignore）。

⚠️ **权限归属问题从这里开始**：因为 snapquiz 不是独立 app bundle，macOS 把截屏行为
归属给**终端.app**。所以"屏幕录制"权限要勾给终端，不是勾给 snapquiz。
这是阶段 C 打包的直接动因，不是可有可无的美化。

限制：终端窗口必须开着（stdin 触发要读 Enter）；换电脑要重装整套 Python 环境；
给不了别人用。

### 阶段 B 成品：第一次有真正属于你的资产

形态仍是 Python 源码，但产出物变了性质：

- **`~/.snapquiz/snapquiz.db`** —— SQLite 错题本。里面是你做过的题、你答错的题、
  模型给的解析。这是换电脑能带走、越用越值钱的东西。前面所有阶段的产出都是代码，
  只有它是**你的数据**。
- **`evals/report.md`** —— 一个能回答"这工具对我到底有没有用"的数字：
  在你的题型上准确率 X%、误答率 Y%、平均延迟 Z 秒。做了 8 周的项目至今回答不了这个问题。

交互变成：终端跑一次后可以切走 → 任意 app 里按 `Cmd+Shift+Space` → 浮层弹出，
**先只显示识别到的题面** → 你自己想 → 点「看答案」展开解析 → 点「我错了」进错题本。
`snapquiz review` 复习。

这一步是从"问答工具"变成"学习系统"。但仍然没有 .app，仍然要开终端启动。

### 阶段 C 成品：唯一有实体的阶段

打包有三个档次，成本差别很大，**不要默认走最贵那档**：

| 档次 | 做法 | 产出 | 成本 | 谁能用 |
|---|---|---|---|---|
| **C3-a** | `.command` 文件 / launchd plist | 双击启动、登录自启 | 0，约 10 行 | 只有你 |
| **C3-b** | `py2app` 打包（不签名） | `SnapQuiz.app`，有图标，可拖进 Applications | 0，半天 | 你 + 愿意右键→打开的人 |
| **C3-c** | Apple Developer + `codesign` + `notarytool` | 可分发的 `.app` / `.dmg` | **$99/年** + 1–2 天 | 任何人，双击即用 |

**关键：C3-b 就已经解决权限归属问题。** 一旦有了独立 app bundle，
"屏幕录制"权限就授给 SnapQuiz 自己，终端不再需要这个权限，也不再需要开着终端。

所以如果目标是**自用**，C3-b（免费、半天）就是终点，不需要 $99 的开发者账号。
C3-c 只在要把它发给别人时才有意义 —— **也正是到那一步，
`v3-transport-research` tag 里的传输加固才第一次有讨论价值**，因为那时软件跑在别人机器上，
威胁模型才真的变了。

---

## 阶段 A：恢复可用（目标 5 个工作日）

### Task 1 — 封存与止血

**文件**：`docs/RECOVERY_PLAN.md`（本文）、`README.md`、`docs/ARCHITECTURE.md`、`docs/IMPLEMENTATION_PLAN.md`

1. 先把未提交的 W10 工作原样提交，不要让 2 万行悬在工作区：
   ```bash
   git add -A && git commit -m "feat: W10 direct_multimodal local/offline composition"
   ```
2. 打不可变 tag，这是 D 类代码的唯一恢复点：
   ```bash
   git tag -a v3-transport-research -m "W04-W10 离线安全链完整状态；resolver/darwin/native 子系统封存于此"
   git push origin v3-transport-research
   ```
3. ~~决定 README 的边界声明。~~ **已决（2026-09-14）：删除。**
   工作区那处挂了 6 周的未提交改动（移除 `⛔ 不适用：受监考的考试……` 一条）保持不变，
   并已顺手清掉它留下的多余空行。这是纯文档改动，不改变任何代码行为 ——
   项目里没有、本计划也不新增任何"规避监考 / 隐藏窗口 / 反检测"相关实现。
4. 修正 README 现状段：当前它教人 `pip install -e . && snapquiz`，照做只会拿到退出码 3。
   在"运行"一节顶部加一行真实状态，等 Task 3 完成后再改回可用说明。
5. `ARCHITECTURE.md` / `IMPLEMENTATION_PLAN.md` 顶部各加一行指向本文件，说明 M5–M9 的
   门禁顺序已被取代。不要删除它们 —— 里面的威胁分析（§14）与结果契约（§4.6）仍然有效。

**验收**：`git tag -l` 能看到 `v3-transport-research`；`git status` 干净；README 不再声称一个不存在的运行方式。

---

### Task 2 — 重建可执行闭环

**文件**
- 重写：`snapquiz/app.py`、`snapquiz/core/orchestrator.py`、`snapquiz/capture/screen.py`、`snapquiz/core/permissions.py`
- 新建：`snapquiz/config.py`（合并 `legacy_config.py`）、`snapquiz/transport/client.py`
- 删除：D 类全部文件与对应测试
- 修改：`pyproject.toml`

**2.1 保留白名单，删掉其余全部。**

因为上面那条结构事实，不能"删 D 留 B"——那会在第一条 `git rm` 之后立刻 ImportError。
做法是反过来：**列出白名单，其余一次性删光。** tag 已经存了全部历史，不要分批。

先把要抄的纯函数拷到一个临时文件，再删：

```bash
mkdir -p /tmp/snapquiz-salvage
cp snapquiz/adapters/openai_chat_compatible.py snapquiz/capture/validation.py \
   snapquiz/transport/_exact_tls.py snapquiz/core/permissions.py \
   snapquiz/transport/credentials.py /tmp/snapquiz-salvage/
```

白名单（**27 个文件 / 3,251 行**，含各 `__init__.py`；已用导入图实跑核对）：

```
snapquiz/__init__.py
snapquiz/domain/{__init__,_validation,digest,errors,solve,capture,adapter,intent,policy,outbound}.py
snapquiz/result/{__init__,validator}.py
snapquiz/adapters/{__init__,prompt}.py
snapquiz/capture/{__init__,topology}.py
snapquiz/core/{__init__,busyguard}.py
snapquiz/llm/{__init__,base,parse,prompt}.py
snapquiz/hotkey/{__init__,stdin_trigger,global_hotkey}.py
snapquiz/present/__init__.py
```

其余 `snapquiz/**/*.py` 全部 `git rm`，外加：

```bash
git rm -r snapquiz/transport/native snapquiz/routing snapquiz/config snapquiz/runtime snapquiz/pipelines snapquiz/privacy
git rm tests/test_w09_*.py tests/test_w10_*.py tests/test_w08_*.py tests/test_w07_*.py \
       tests/w0*_helpers.py tests/fixtures/*.c tests/fixtures/resolver_*.py \
       tests/test_m0_fail_closed.py tests/test_registry*.py tests/test_planner_consent.py \
       tests/test_capture_policy.py tests/test_domain_plan_outbound.py \
       scripts/build_w09_native.py
```

删完后**恰好 5 处**编译修复（已实跑核对，不多不少）：

| 文件 | 悬空 import | 怎么修 |
|---|---|---|
| `domain/__init__.py` | `domain.capabilities`、`domain.plan` | 删掉这两段 import 与对应 `__all__` 条目 |
| `domain/outbound.py:17` | `domain.plan` 的 4 个名字 | `CredentialInjectionSlot` / `OutboundDataKind` / `QueryPolicyKind` 是轻量枚举，直接搬进 `outbound.py`；`ExecutionPlan` 那处绑定改成接受 2.4 的 `Config` |
| `adapters/__init__.py` | `adapters.base` | `base.py` 只因 `PlannedExecution` 一个参数而出局；把该参数换成 `Config` 后把 `base.py` 一起加回白名单 |
| `hotkey/stdin_trigger.py` | `core.legacy` | 本来就要在 2.6 恢复成 `93a7b2b` 的原件 |
| `hotkey/global_hotkey.py` | `core.legacy` | 同上 |

**确认白名单自洽**（这一步必须真跑，不要跳过）：
```bash
python3 -c "import snapquiz.domain, snapquiz.result.validator, snapquiz.adapters.prompt; print('core ok')"
python3 -m unittest discover -s tests   # 应当在 20 秒内跑完
```

**2.2 权限三态（~60 行）。** 保留 `ScreenPermissionState` 三态枚举与 `MacOSScreenPermissionProbe.observe()`
的探测分支逻辑（它对 `type(raw_state) is not bool` 的处理是对的），去掉 digest / `_authority` /
`observed_at == now`。恢复 `request_screen_recording()` 的真实实现（现在恒返回 `False`）：

```python
def request_screen_recording() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from Quartz import CGRequestScreenCaptureAccess
        return bool(CGRequestScreenCaptureAccess())
    except Exception:
        return False
```

**2.3 截屏（~40 行）。** 恢复 `93a7b2b` 的 `capture_png_bytes`，但**保留冻结版的强约束**：
`region is None` 直接 `raise ValueError("必须提供明确选区")`，不回退全屏。这是原审计第 2 条。
接上瘦身后的 `capture/validation.py` 做尺寸 / 空白 / 黑帧检查。

**2.4 配置（~50 行）。** 以冻结版 `legacy_config.py` 为基础 —— 它已经做对了三件事：
`base_url` 必须等于官方端点、`model` 必须是冻结值、`SNAPQUIZ_REGION` 必填。
把 `Config` 里的 `api_key: str` 改成不存明文：存 `api_key_ref`，真正取值在 2.5 里发生。

**2.5 传输（~80 行）。** 这是替代 4.4 万行的那 80 行。**用 `httpx` 而不是 `openai` SDK**，
因为只有直接 POST 字节才能保证"预览到的就是发出去的"——这是 v3 唯一值得保留的强不变量：

```python
# snapquiz/transport/client.py
import httpx
from snapquiz.domain.outbound import PreparedOutbound

def send_once(
    outbound: PreparedOutbound, *, api_key: str, timeout: float, provider_profile_id: str
) -> bytes:
    """发送 Adapter 已经准备好的确切字节。无自动重试，无重定向。"""
    headers = {
        h.lowercase_name: h.normalized_value for h in outbound.non_secret_headers
    }
    headers["content-type"] = outbound.content_type
    headers["authorization"] = f"Bearer {api_key}"
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,          # 3xx fail-closed
        verify=True,
        transport=httpx.HTTPTransport(retries=0),
    ) as c:
        r = c.request(
            outbound.http_method, outbound.canonical_url,
            content=outbound.body, headers=headers,
        )
    if r.status_code != 200:
        _map_http_error(r.status_code, provider_profile_id)   # 复用 adapters 里的 34 码映射表
    if len(r.content) > MAX_PROVIDER_RESPONSE_BYTES:
        raise InvalidOutputError(stage="transport", provider_profile_id=provider_profile_id)
    return r.content
```

字段名已按 `domain/outbound.py` 核对：是 `outbound.body` / `outbound.canonical_url` /
`h.lowercase_name` / `h.normalized_value`，不是 `body_bytes` / `url` / `h.name` / `h.value`。
错误映射函数在 `adapters/openai_chat_compatible.py:348`，名为 `_map_http_error`，
它自己 `raise`，不返回异常对象 —— 把它提升为公开函数 `map_http_error` 再用。
在建立 client 前调用瘦身后的 `_exact_tls` 环境变量检查（`SSLKEYLOGFILE` 等存在即拒绝）。
`pyproject.toml`：加 `httpx>=0.27`，**删掉 `openai`**。

**2.6 编排（~120 行）。** 恢复 `93a7b2b` 的 `Orchestrator` 依赖注入形状（它本来就对），
串成：`权限三态 → 截图 → validation → Adapter.prepare → send_once → Adapter.decode →
result/validator.validate_solve_result → present`。`present/notify.py` 恢复 MVP-0 原件。

**验收**（必须是这句，不是测试数）：
> 在终端跑 `snapquiz`，按 Enter，屏幕上 `SNAPQUIZ_REGION` 指定的区域里那道题，
> 终端里出现了答案和解析。

---

### Task 3 — 真实 API 打通

当前 spec 把这一步锁在 M6/W11 并要求"另行明确授权"。**这个门禁应该拆掉**：
GLM-4.6V-Flash 是免费档，图是仓库里的合成题图，调用一次的风险约等于零；
而在没跑通真实 API 之前，前面所有离线证据都无法证明请求形状是对的。

1. `cp .env.example .env`，填入智谱 key。
2. 准备一张固定合成题图 `tests/fixtures/sample_question.png`（自己画一道简单选择题即可）。
3. 加一个只在显式传参时才跑的 smoke：
   ```bash
   python -m snapquiz.smoke --image tests/fixtures/sample_question.png
   ```
   它走完整链路但用文件输入代替截屏，`max_retries=0`。
4. 记录非内容证据：HTTP 状态、延迟、token 用量、响应 schema 是否通过 `validate_solve_result`。

**验收**：
> 对那张合成题图，真实 GLM 返回了一个通过严格 Validator 的 `SolveResult`，答案是对的。

如果这一步暴露了请求形状问题（很可能，因为从未真实验证过），**在这里修，不要回头改 spec**。

---

### Task 4 — 选区与发送前预览

这是 v3 里唯一真正对上本产品威胁的功能，也是原审计第 2 条的完整答案。
但不需要 NSPanel，也不需要 4,400 行。

**4.1 选区用系统自带的。** macOS 的 `screencapture -i -s` 就是一个免费的拖框选择器：
```python
def pick_region_png(path: str) -> bool:
    r = subprocess.run(["screencapture", "-i", "-s", "-x", path], timeout=60)
    return r.returncode == 0 and os.path.exists(path)
```
`-x` 静音，用户按 Esc 则文件不存在 → 视为取消，零网络。
把选中的区域存进 `~/.snapquiz/region.json` 供后续热键复用（README 里承诺的"选区记忆"）。

**4.2 预览 + 一次性批准（~150 行）。** 从 `privacy/egress.py` 提炼：
在 `send_once` 之前，把**实际要发的字节**里的图片解码出来，用 `qlmanage -p` 或
Preview 打开给用户看，终端问 `发送这张图到 open.bigmodel.cn？[y/N]`。
否 → 零网络、零 secret resolve。是 → 消费一次性令牌，然后才 resolve API key。

关键不变量（保留 v3 的，丢掉其余）：**secret 在批准之前 resolve 次数必须为 0**，
且预览的图与发出的 body 来自同一个 `PreparedOutbound` 对象，不重新 prepare。

**4.3 同意记录（~80 行）。** 首次运行时问一次"是否接受截图上传云端"，
写进 `~/.snapquiz/consent.json`（含时间、endpoint、可撤销）。之后每次只做 4.2 的逐次预览。

**验收**：
> 按热键 → 拖框选题 → 看到即将上传的那张图 → 按 y → 拿到答案；按 n 则什么都没发出去。

---

### Task 5 — 阶段 A 收口

- 跑一遍剩余测试套件，确认 20 秒内跑完、全绿。
- 更新 README 的"运行"与"状态"两节为真实可用状态，恢复"45 个单测"那句为真实数字。
- `git tag v0.1.0-usable`。

**验收**：
> 一台干净的 mac 上按 README 走一遍，能解题。

---

## 阶段 B：让它真的有用（1–2 周）

原审计的第 3、4 条，至今零投入。这是"能跑"和"有用"的差距。

### Task 6 — 评测集（优先级最高）

**没有这个，你无法回答"这玩意儿到底答得对不对"。** 项目做了 8 周，这个问题至今无法回答。

- `evals/` 下放 30–50 道代表性题：选择、填空、公式、几何图、图表、中英混排、模糊截图。
- 每题一个 `.png` + 一个 `expected.json`（答案 + 是否应当拒答）。
- `python -m snapquiz.eval` 跑全集，输出：准确率、拒答率、误答率（答错且高置信）、
  平均延迟、平均 token。
- **误答率是关键指标** —— 原审计第 6 条说的"模型自信错答"是本产品的头号真实风险。

**验收**：
> 你能说出一句"snapquiz 在我的题型上准确率是 X%，在看不清的题上有 Y% 会硬猜"。

### Task 7 — 错题本与去重缓存

- SQLite：`~/.snapquiz/snapquiz.db`，表 `attempts(id, ts, image_sha256, question_summary,
  answer, rationale, confidence, user_marked_wrong)`。
- 图片 sha256 命中则直接返回缓存，不发网络（成本 + 速度）。
- `snapquiz review` 列出标记为错的题。

**验收**：
> 同一道题按两次，第二次没有产生网络调用；`snapquiz review` 能列出你标错的题。

### Task 8 — 浮层与"先自答"

- NSPanel（pyobjc-Cocoa 已在依赖里）：先只显示"已识别题面"，点一下才展开答案+解析。
- 这是 README 里的核心学习主张，也是与"直接给答案"的产品差异所在。

**验收**：
> 按热键后你先看到题面摘要，自己想完再点开答案。

### Task 9 — Carbon 零权限热键

当前 `hotkey/global_hotkey.py` 用 pynput，需要"辅助功能"权限。
`pyobjc-framework-Carbon` 已在依赖里，`RegisterEventHotKey` 不需要该权限。
这是 README 架构表里承诺但从未实现的一项。

**验收**：
> 在没有授予"辅助功能"权限的机器上，全局热键仍然工作。

---

## 阶段 C：按需（不承诺时间）

- **C1 第二个 Provider**：这时才从 `v3-transport-research` tag 上把 C 类 4 个文件
  （`capabilities.py` / `plan.py` / `routing/`）拣回来。它们是为这一刻写的。
- **C2 Keychain**：`keyring` 库，约 20 行，替代 `.env`。不需要 `_darwin_keychain_source.py` 的 1,409 行。
- **C3 签名 / 公证 .app**：只有在要分发给别人时才有意义。
  **也只有到这一步，`v3-transport-research` 里的传输加固才第一次有讨论价值** ——
  因为那时软件跑在别人的机器上，威胁模型才真的变了。

---

## 3. 工作方式（最重要的一节）

前 8 周的成本是：191 个 codex 会话、1.04 GB 日志、**14.74 亿 token**、21,146 次工具调用。
其中 320 条用户消息里有 141 条是裸的"继续推进"。

产出 7.6 万行代码，可达 80 行。

机制是这样的：spec 把"冻结能跑的 MVP-0"设为 M0 前置、把"第一次真实 API"推到 M6，
于是每个工作包的 exit gate 只能是"离线证据齐备 + P0/P1 = 0"。
**这个判据永远可以靠写更多代码和更多测试来满足，而且与产品能不能用完全解耦。**
配上不允许收缩范围的自主目标包装器，系统没有自然停止点。

所以：

| 不要 | 要 |
|---|---|
| `继续推进直到完成 W09` | `执行 Task 2。验收句是"按 Enter 能拿到答案"。做到为止，其他都不要动。` |
| exit gate = "P0/P1 = 0" | exit gate = 一句用户能自己验证的话 |
| 一次会话跨多个 Task | 一次会话一个 Task，做完停下来给我看 |
| 发现问题就加一层防御 | 发现问题就记进本文件的"已知问题"，下个 Task 处理 |

按你之前定下的节奏：**批量派发、每批一次评审、小改动自己做**。
阶段 A 的 5 个 Task 适合一次派一个；阶段 B 的 Task 6–9 互相独立，可以一次派一批。

---

## 4. 已知问题（滚动记录）

- `README.md` 的边界声明改动未决（Task 1.3）。
- **v3 各层不可按文件切分**（见 §1 的结构事实框）。任何"先删一半再让另一半编译过"的
  做法都会立刻 ImportError。白名单 27 文件已实跑验证，悬空 import 恰好 5 处。
- `PermissionGate.require_granted` 要求 `observation.observed_at == now` 精确相等，
  瘦身时注意这条会让调用方必须共享同一个 `datetime` 实例。
- `transport/http.py` 文件名与内容不符（不含 HTTP），删除时不要被文件名误导。
- 离线套件 568 秒中的大部分来自 resolver 生命周期测试（单模块 43 用例 37 秒）与
  测试期现场编译 C；D 类删除后这部分一并消失。
