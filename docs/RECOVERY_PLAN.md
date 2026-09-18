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

## ⚠ 2026-09-18：阶段 B 已被 v2 重排

用户明确了项目的目标形态，原阶段 B 的四个 Task 不再适用：

- **双端**：至少同时支持 macOS 与 Windows
- **全屏自动识别**：除指定选区外，能整屏截图并自动找出可能的问题
- **应用内设置页**：热键、截屏/选区模式等都在 app 里改
- **双答案模式**：实时（按键即弹答案）与延时（按键只计算存档，做完整组后打开
  app 统一复习）

已定决策见 [`SPEC_B0_PLATFORM.md`](./SPEC_B0_PLATFORM.md) §1。

新的路线：

| 阶段 | 内容 | 验收句 |
|---|---|---|
| **B0** | **平台层抽象（前置，spec 已就绪）** | 核心代码 grep 不到 osascript/Quartz/screencapture |
| B1 | GUI 骨架 + 设置页（PySide6） | 在 app 里改热键，改完立刻生效，不碰任何文件 |
| B2 | SQLite + 练习组 + 截图归档 | 做完一组 10 题，能在 app 里翻到这一组全部记录 |
| B3 | 延时模式（队列 + 会话级批准 + 常驻指示器） | 按 10 次热键做完一套，打开 app 看到 10 个答案，中间没被打断 |
| B4 | 全屏自动识别 + 多问题 + 评测集 | 能说出全屏模式比选区模式准确率低多少 |
| B5 | Windows 端 | 在 Windows 上按热键能解题 |

**为什么 B0 必须最先做**：现有 5,276 行里 **4,073 行平台无关、1,706 行 macOS 锁定**，
而那 1,706 行恰好集中在 B1–B4 将要大量新增代码的那一层（9 个文件，全是 UI/IO 边缘）。
不先立接口，后面每个功能都要写两遍，而且第二遍是在第一遍已经被当成"完成"之后才写。

**原阶段 B 四个 Task 的去向**：Task 6 评测集 → B4；Task 7 错题本 → B2（从可选升为
延时模式的地基）；Task 8 浮层 → B1/B3 的 UI；Task 9 零权限热键 → B0-2
（且有了新线索，见 spec §3）。

---

## 阶段 B（原始版本，已被上面取代，保留作对照）

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

## 3.5 执行记录

### Task 1 — 完成（2026-09-15）

- `0df1819` 提交 W10 全部未落盘工作；tag `v3-transport-research` 已推送到 origin。
- README 边界声明按用户决定删除；状态段改为诚实描述。
- ARCHITECTURE / IMPLEMENTATION_PLAN 加取代声明。

### Task 2 — 完成（2026-09-15）

**验收句已满足**：真实截屏 900×700 → 117 KB PNG → 预览确认 → 发送 → 严格校验 →
终端打印「题面 / 答案 B / 模型自评把握:较高(未校准) / 解析」。

规模：删除 131 文件 / 135,878 行；新写 **1,869 行**（14 个文件）。
测试从 1,341 个 / 568 秒变成 **137 个 / 0.13 秒**。

#### ⚠ 三处计划偏差（重要，影响对"可回收资产"的判断）

§1 把 `domain/outbound.py`、`domain/adapter.py`、`domain/solve.py` 归为「A. 可原样存活」，
**这个判断偏乐观**。导入图显示它们自闭包没错，但 PlannedExecution 的穿线还长在
**类的字段列表里**：

| 类 | 被迫移除的字段 | 后果 |
|---|---|---|
| `PreparedOutbound` | plan_id / plan_digest / stage_id / operation_id / source_ids / source_digests | 整类重写为 `OutboundRequest` |
| `TransportResponse` | plan_id / stage_id / operation_id | 重写 |
| `AnswerCandidateResult` | plan_id / plan_digest / stage_id / operation_id / invocation_digest | 重写 |
| `StageProvenance` | binding_id / provider_profile_digest / capabilities_ref / capabilities_digest / component_id / component_version | 重写 |
| `SolveProvenance` | plan_id | 重写 |

保留下来的是真正做事的那条相关性：**请求 envelope digest ↔ 响应体 digest ↔ 候选结果**。
它足以拒绝「用另一次请求的响应冒充这次的结果」，而且不需要任何 plan 记账。

**给下一个阶段的教训**：判断 v3 代码能否复用，看导入图不够，要看类的字段。
真正没有被穿线污染的只有 `digest.py` / `errors.py` / `_validation.py` / `policy.py` /
`intent.py` / `capture.py` / `result/validator.py` 的 `validate_solve_result` /
`adapters/prompt.py` / `capture/topology.py` / `core/busyguard.py` / `llm/*`。

#### 计划外新增

- `snapquiz/adapters/glm_errors.py`（274 行）：从 v3 抄出的 34 个 GLM 业务错误码矩阵
  + 严格 JSON 解码。这是 v3 最值钱的一块，单独成模块以便复用。
- `snapquiz/adapters/glm.py`（213 行）：具体 Adapter，线格对着
  `tests/fixtures/glm_request.json` golden 核对。
- `snapquiz/transport/tls.py`（34 行）：7 个 TLS 环境变量屏蔽。

#### 验收过程中发现并修掉的真实 bug

`--trigger stdin` 下，发送确认提示与 stdin 触发循环**抢同一个输入流** ——
BusyGuard 把编排丢进后台线程，后台线程的 `input()` 和主线程触发循环的 `input()`
互相吃对方的输入，表现为「刚按 Enter 就说上一题还在处理中」然后确认被当成取消。

修法：两种触发方式用不同执行模型。`stdin` 串行同步执行（确认独占 stdin）；
`hotkey` 保留 BusyGuard（连击护栏是它存在的理由），确认改走 osascript 系统对话框。
**这个 bug 靠单测发现不了，只有跑真实 CLI 才会暴露** —— 这正是「验收判据必须在代码之外」的意义。

### Task 3 — 完成（2026-09-15）

**验收句已满足**：对 `tests/fixtures/sample_question.png` 打真实 GLM，
拿到通过严格 Validator 的 `SolveResult`，答案正确。

```
HTTP 200 | 延迟 4277 ms | prompt 1389 + completion 136 = 1525 tokens
答案:C. 29   正确答案 C → ✅ 答对
```

#### 这一步暴露了三件离线永远测不出来的事

**1. 模型不听 prompt，照样加 Markdown 围栏。**
system prompt 明写 "no Markdown, code fence, commentary"，模型仍然返回：

    ```json
    { "schema_version": "snapquiz.solve-result.v2", ... }
    ```

第一次真实调用就因此 `InvalidOutputError` 失败。讽刺的是 MVP-0 的
`llm/parse.py` 本来就处理围栏（`_FENCE_RE`），是 v3 的严格 Adapter 把这份宽容丢了。

修法：`_unwrap_code_fence` 只接受**整段内容恰好是一个围栏**，剥掉后里面的 JSON
仍走完整严格解析、结果仍过九字段精确校验。**没有**退回 MVP-0 那种
「在任意文本里捞第一个 JSON 对象」——围栏外只要有一个字的解释文字就拒绝。

**2. `glm-4.5-air` 不是多模态模型，本产品用不了。**
`1210 messages.content.type 参数非法，取值范围 ['text']`。截图工具必须用视觉模型。

**3. 「v」系列是推理模型，token 预算要同时覆盖思维链。**
`glm-4.6v` / `glm-4.5v` / `glm-4.6v-flash` 把思维链放在 `reasoning_content`，
答案放在 `content`。`max_tokens=50` 时 `reasoning_tokens=49`、`content=''`、
`finish_reason="length"` —— 看起来像"模型返回空"，其实是预算配置问题。
已为它单开 `OutputBudgetExhausted`，不和"模型乱答"混为一谈。

#### 实测模型矩阵（2026-09-15，同一张图，单次调用）

| 模型 | 结果 | 延迟 | completion tokens | 备注 |
|---|---|---:|---:|---|
| **`glm-4v-flash`** | ✅ 答对 | 4.3 s | 136 | **当前默认**；非推理，快且稳 |
| `glm-4.6v` | ✅ 答对 | 13.5 s | 330 | 推理模型，慢 3 倍 |
| `glm-4.6v-flash` | ❌ `1305` | — | — | 3 次里 2 次「访问量过大」 |
| `glm-4.5v` | ⚠️ 未过完整链路 | — | — | 推理模型，仅裸 API 验证过 |
| `glm-4.5-air` | ❌ `1210` | — | — | 纯文本，拒收图片 |

默认模型因此从 `glm-4.6v-flash` 改为 `glm-4v-flash`。

#### 顺带验证到的

- **错误映射对真实服务端成立**：`glm-4.6v-flash` 的 `1305` 被正确映射成
  `ProviderUnavailableError`（retryable=True），不是靠 fixture 推测的。
- 模型返回 `confidence: 1`（int 不是 float），Validator 接受 —— 已补测试钉死。
- 请求线格（model / messages / max_tokens 三个顶层键，`[image_url, text]` 两段）
  **被真实服务端接受**，golden fixture 这一点是对的。

### 接入第二个 Provider（2026-09-15，计划外，用户要求）

原计划把多 Provider 放在阶段 C。提前做是因为它现在**确实便宜**：
Adapter 已经是纯 `prepare`/`decode`，加一个 Provider 不需要碰传输、权限、
捕获、校验任何一层。

做法是一张**静态表**（`snapquiz/providers.py`，约 120 行），不是 Registry：

- 核心逻辑不含任何 Provider 分支；唯一的分支在 `map_business_error` 的两行 if 里；
- 每个 Provider 的差异（endpoint / key 变量 / 模型白名单 / 必需 header /
  错误方案 / token 预算 / 超时）全部是 `ProviderProfile` 的字段；
- 新增 Provider = 加一条表项，不动其他文件。

对比：v3 的 Registry/Plan 机制做同一件事用了 **3,643 行**，代价是一条贯穿
每一层的 PlannedExecution 穿线。

#### opencode / mimo-v2.5 实测到的四件事

1. **Go 路由强制要 `x-opencode-session` header**，缺了返回 `MissingSessionID`。
   它不是密钥，所以作为 non-secret header 进 envelope digest —— 换个 session
   就是另一次请求，预览时也看得见。
2. **opencode 对「模型名写错」也返回 HTTP 401**，和无效 key 一样。只看状态码会
   把配置错误误报成密钥失效，必须看 `error.type`（`AuthError` vs `ModelError`）。
   这正是 `error_scheme` 必须**必填**的原因：给它默认值会让调用方漏传时静默退化。
3. **`mimo-v2.5` 是推理模型**，输出在 `message.reasoning`，`content` 是 `None`
   直到推理结束。`max_tokens=1024` 时 `finish_reason="length"`、拿不到任何答案。
   为 GLM 加的 `OutputBudgetExhausted` 原封不动地正确诊断了它 —— 一个好抽象的迹象。
4. **它慢一个数量级**：8192 预算下 141 秒 / 1172 tokens（裸 API），完整链路 86 秒。
   按热键等一分半钟不实用。留着是为了证明抽象成立与将来对比评测。

`mimo-v2.5-pro` 是纯文本的：404「No endpoints found that support image」。

### 模型选型与计费核查（2026-09-15）

#### 智谱资源包：客户端无从选择

用户问「是不是后台选错了资源包，用了通用包而不是 glm-4.6v 专用包」。核查结论：

**请求里根本没有资源包选择项。** 我们发给智谱的全部内容是：

```
POST https://open.bigmodel.cn/api/paas/v4/chat/completions
headers: accept: application/json + authorization
body 顶层键: ["max_tokens", "messages", "model"]
```

没有任何参数或 header 能指定用哪个包。智谱官方文档的规则是
「优先扣除**满足模型适用场景**的资源包余额，再扣除现金账户余额；存在多个相同适用
场景的资源包时，优先扣除最快过期的」。也就是说包的匹配完全由**模型名**决定，
在服务端完成。智谱也没有公开的余额/资源包查询 API（试过 `/usage`、
`/account/balance`、`/resource_packages`，全 404），只能在控制台账单页看。

**唯一受我们控制、且真的会影响匹配的是模型名。** 这里有一个需要说明的窗口：
本轮重建过程中默认模型一度是 `glm-4v-flash`（当时 `glm-4.6v-flash` 间歇 1305，
选了实测最稳的），那段时间的调用不会匹配 `glm-4.6v` 专用包。涉及约十几次调用、
每次 1.1k–1.8k tokens。现已按用户要求固定为 `glm-4.6v`。

#### opencode 模型选型：flash 系完胜 mimo

`mimo-v2.5` 中位 24.5 秒、1513 completion tokens，比同平台的 flash 系慢 5 倍。
改默认为 `glm-5.3-flash`（4.6 秒 / 122 tokens / 3-3 正确）。详见 README 实测表。

#### 一个把我自己骗过去的坑

第一轮扫描 12 个模型时全部返回 `403 error code: 1010`，我差点得出
「opencode 没有模型支持图片」的结论。两个原因叠加：

1. 我手工编的 32×32 测试 PNG **是坏的**（IDAT CRC 错、缺 IEND chunk）；
2. 更要命的是探测脚本用了 `urllib`，而 **opencode 的 CDN 直接拦
   `Python-urllib` 和空 User-Agent**（Cloudflare 1010）。curl 和 httpx 都放行。

也就是说那一轮 403 跟模型能力毫无关系。教训：拿到「所有目标一致失败」这种
结果时，先怀疑自己的探针，别急着下结论——尤其当已知可用的那个也一起失败时。
本项目用 httpx，不受影响。

### Task 4 — 完成（2026-09-15）

**验收句已满足**：拖框选题 → Quick Look 看到即将上传的那张图 → 按 y 拿到答案；
按 n 则零网络（用 httpx tripwire 实测 0 次调用）、零密钥读取、预览临时文件立刻删除。

三个模块，共约 330 行：

| 模块 | 行 | 做什么 |
|---|---:|---|
| `capture/select.py` | 77 | `screencapture -i -s` 拖框；Esc → `SelectionCancelled` |
| `privacy/preview.py` | 174 | **从出站字节里**解出图片 → Quick Look + 文字描述 |
| `privacy/consent.py` | 105 | 一次性数据政策同意，按 provider+endpoint 限定 |

对比 v3：`privacy/egress.py` 2,072 行 + `privacy/consent.py` 2,279 行 = 4,351 行。

#### 关键不变量：预览的图从 `OutboundRequest.body` 里解出来

不是用调用方手上那份原始 PNG。否则「预览的」和「发出的」只是碰巧相同，
而不是同一份东西 —— 一旦中间哪一步动了 body，预览就会骗人。有测试钉死
（换 provider/模型后预览内容必须跟着变）。

#### 选区坐标拿不到，所以「选区记忆」降级了

`screencapture` 只给图不给位置。所以：交互模式每次现拖（无记忆），
固定模式靠 `SNAPQUIZ_REGION`。坐标级记忆需要自己写选择器（NSPanel + 多显示器
+ Retina + 旋转的坐标变换），留到阶段 B。原计划里写的
「把选中的区域存进 region.json」**做不到**，这里如实降级。

#### 用户实测发现的第三个坑：默认路径根本没被测到

用户按 README 跑完说「能正常读题且答对,但选区似乎是自动的,不是我手动拖的」。
查下来是我连着犯了两个错：

1. Task 2/3 做冒烟时我把 `SNAPQUIZ_REGION=100,100,900,700` **写进了 `.env`**；
2. 我让用户 `unset SNAPQUIZ_REGION && snapquiz` —— 而 **`unset` 根本没用**，
   `load_dotenv()` 会把 `.env` 里的值重新读回进程环境。

于是 `cfg.region` 非空 → 走固定选区 → 不弹准星。用户拿到的是 (100,100) 处
900×700 的固定裁剪，恰好框住了题目，所以答案是对的，但交互完全不是设计的那样。

**更值得记的是我为什么没测出来**：我的验收脚本显式传了 `--select`，
所以它验证的是「加了 flag 的路径」，而用户走的是「什么都不加」的默认路径。
**验收用的调用方式必须和用户实际用的一致**，否则测的是另一个程序。

修法：`.env` 与 `.env.example` 里的选区默认注释掉（默认即拖框）；
把模式判定抽成 `choose_interactive()` 并补 6 个用例，其中一个专门钉死
「不带任何参数时 capture_fn 必须是拖框那个」；启动横幅在固定选区模式下
明确打印「**不会弹准星**」并告诉你怎么切、以及 unset 为什么无效。

#### 两个我自己制造的坑

1. **Cocoa 的 `samplesPerPixel` 不能当步长。** 实测 `samplesPerPixel=3` 但
   `bitsPerPixel=32` —— 每像素 4 字节，第 4 字节是值为 `0xFF` 的填充。
   按 3 字节步进会读到错位的填充字节，**全黑图被判成有内容**。
   要用 `bitsPerPixel // 8`。写完第一版时四个负向用例全部静默通过，
   是逐个手验才发现的。

2. **验收脚本把 `builtins.input` 无条件 patch 成返回 "y"**，导致 stdin 触发
   循环永远读不到 EOF，在真实 API 上死循环，**烧掉 40 次调用（约 7 万 tokens）**
   才被发现并 kill。教训：给真实外部调用做端到端脚本时，桩必须是**有限序列**，
   耗尽即抛 EOF，并对调用次数加断言上限。修正版加了
   `assert len(captures) <= 2, "疑似死循环"`。

### Task 5 — 阶段 A 收口（2026-09-15）

**验收句已满足**：在一份全新 `git clone` + 全新 venv 里，严格照 README 走一遍，
能解题。

```
git clone … && python3 -m venv .venv && ./.venv/bin/pip install -e .
未配 key            → 「缺少 GLM_API_KEY」+ 退出码 2
scripts/grant_check → ✅ 已授予屏幕录制权限
unittest discover   → 189 tests, OK
配好 .env 后真实解题 → HTTP 200 / 11.6 s / 答案 C. 29 ✅
```

#### 干净 clone 验收抓到的最后一个 bug

`scripts/grant_check.py` 从 Task 2 重写 `permissions.py` 起就是坏的 ——
它还在 `import has_screen_recording`，而那个函数已经被删掉了。
**它是 README 的首次运行步骤**，任何新用户第一步就会撞上。

没被发现的原因很直白：单测只覆盖 `snapquiz/`，**从没碰过 `scripts/`**。
现在补了一条「README 里让用户跑的每个脚本都必须能 import 且有 `main()`」，
外加 grant_check 三态返回码的用例。

这也是「验收判据必须在代码之外」的又一个实例：本地 187 个测试全绿，
但换个目录、换个 venv 就崩 —— 只有真的按用户的路径走一遍才看得见。

---

## 阶段 A 完成总结

| | 起点（2026-09-14） | 现在 |
|---|---|---|
| 源码 | 76,457 行 | **5276 行** |
| 从 CLI 入口可达 | 80 行（0.1%） | 全部 |
| 测试 | 1,341 个 / 568 秒 | **189 个 / 0.24 秒** |
| 能不能解题 | ❌ 退出码 3 | ✅ |
| Provider | 0 个可用 | 2 个真实打通 |

五个 Task 全部验收通过，每一条验收句都是用户能自己复现的行为，
没有一条是「测试全绿」或「P0/P1 = 0」。

**保留下来的安全不变量**（都有测试）：端点与模型钉死白名单 · 必须显式选区
且无全屏回退 · 非 granted 权限阻断 · 批准前零密钥解析零网络 ·
发出字节等于预览字节 · 预览图从出站 body 解出 · 无自动重试 · 不跟随 3xx ·
Provider 原文不进异常 · 模型自评不以百分比展示。

**阶段 A 交付物形态**：venv + 终端命令，没有可双击的东西，
屏幕录制权限记在终端名下。这些在 §1.5 就写清楚了，没有变。

### 打包（2026-09-16，计划外提前）

`python scripts/build_app.py` → `dist/SnapQuiz.app`（44 MB，未签名）。

打包不只是跑 py2app —— **双击启动的 .app 没有终端**，stdin 触发、终端确认、
`print` 输出全部失效。补齐的 GUI 路径：`is_gui_launch()` 检测无 tty 自动切到
「热键 + 系统对话框」；结果与错误走对话框；同意书也有对话框版；热键监听在后台
线程、主线程停在「运行中」对话框上作为唯一退出口。

两个坑：py2app 0.28 不支持 `install_requires`，而 setuptools 会把 pyproject 的
`dependencies` 映射成它（`scripts/build_app.py` 在构建期把 pyproject 临时挪开，
try/finally 保证还原）；双击时 CWD 是 `/`，读不到仓库里的 `.env`（改成
`~/.snapquiz/.env` 打底 + 就近 `.env` 覆盖两层加载）。

### Task 9 — Carbon 零权限热键（实现完成，**等人工验证**）

`snapquiz/hotkey/carbon_hotkey.py`。目标：摆脱 pynput 需要的**辅助功能**权限 ——
那个权限等于允许程序读取所有按键并控制电脑，为一个截图工具开这口子不划算。

已确认的部分：

- pyobjc **只暴露了一半**：`RegisterEventHotKey` / `UnregisterEventHotKey` /
  `EventHotKeyID` 有，`InstallEventHandler` / `GetApplicationEventTarget` /
  `GetEventParameter` 没有。只注册不装 handler 收不到事件，所以改用 `ctypes`
  直接调 Carbon.framework —— 那五个函数都在。
- `InstallEventHandler` 与 `RegisterEventHotKey` 都返回 OSStatus 0，
  **全程没有触发辅助功能权限请求**。这一点是这个 Task 的核心价值所在。

**无法自动验证的部分，以及为什么**：

注册成功证明不了热键可用 —— 实测会 OSStatus 0 却收不到任何事件。我试了四种
形态：终端 Python、加 `NSApplication`、`nextEventMatchingMask` 手动泵、
真正的 `NSApp.run()`，再加上从 .app bundle 里跑，全都收不到。

于是我做了一个决定性实验：用 `CGEventPost` 合成 **Cmd+Shift+3**（系统自己的
截图热键），桌面上**没有出现截图**。也就是说 **macOS 的热键分发层完全忽略合成
按键** —— 我的测试装置从原理上就验证不了这件事，只有真人按键能。

（注意这不影响结论方向：合成按键 pynput 是看得见的（CGEventTap 层级更低），
但热键分发在更上层。所以「pynput 收得到、Carbon 收不到」不能说明 Carbon 坏了。）

因此：**默认仍是 pynput**，Carbon 作为待验证实现并存。
`snapquiz --hotkey-selftest` 让用户按一次键，两种事件泵各试一轮，一次就能知道
哪种（如果有）可用。验证通过再切默认。

这条与 [[acceptance-criteria-must-be-user-observable]] 一致：验收判据在代码之外，
而这一次连「代码之外」都只能是人的手指。

---

## 4. 已知问题（滚动记录）

- `-y/--yes` 会同时跳过数据政策同意与逐次发送确认，隐私护栏只剩「必须显式选区」一条。
- `hotkey` 模式的确认对话框已能弹图（Quick Look），但 osascript 对话框本身仍是纯文字。
- 坐标级选区记忆未实现（见 Task 4 记录）。
- macOS 原生拖框那一步只做过桩测试，真实拖拽需要人手验证一次。
- `glm-4.5v` 只做过裸 API 验证，没跑过完整链路。
- 智谱到底扣了哪个资源包，只能在控制台账单页确认；API 侧无从查询也无从指定。
- opencode 的响应里没有 `request_id`，冒烟显示 `None`；只影响对账。
- `mimo-v2.5` 的 86 秒延迟没有做过多次采样，可能波动很大。
- 推理模型在完整九字段 prompt 下的 token 消耗未系统测量；`MAX_OUTPUT_TOKENS=1024`
  对这道简单题够用（330），复杂题是否够未知。
- **v3 各层不可按文件切分**（见 §1 的结构事实框）。任何"先删一半再让另一半编译过"的
  做法都会立刻 ImportError。白名单 27 文件已实跑验证，悬空 import 恰好 5 处。
- `PermissionGate.require_granted` 要求 `observation.observed_at == now` 精确相等，
  瘦身时注意这条会让调用方必须共享同一个 `datetime` 实例。
- `transport/http.py` 文件名与内容不符（不含 HTTP），删除时不要被文件名误导。
- 离线套件 568 秒中的大部分来自 resolver 生命周期测试（单模块 43 用例 37 秒）与
  测试期现场编译 C；D 类删除后这部分一并消失。
