# snapquiz

个人学习刷题助手 —— 热键一按,读取屏幕上的题目,调用 LLM 给出**答案 + 解析 + 相关知识点**,辅助自学、自测与错题复习。

> **状态(2026-09-15):✅ 阶段 A 完成 + 已可打包成 .app**。
> 拖框选区 → 预览实际出站图片 → 逐次确认 → 两个 Provider 均真实打通;
> `python scripts/build_app.py` 产出可双击的 `SnapQuiz.app`。
> 尚未做评测集、错题本与浮层(阶段 B)。
> v3 时期的 7.6 万行离线安全链已封存于 tag `v3-transport-research`;
> 重建过程与后续计划见 [docs/RECOVERY_PLAN.md](docs/RECOVERY_PLAN.md)。

## 这是什么

一个运行在 macOS 上的**个人学习工具**:

```
热键触发 → 截取屏幕题目区域 → 直接把截图发给视觉大模型(GLM-4.6V-Flash) → 生成「答案 + 解析」→ 浮层呈现 + 错题本
```

目标是帮助**自学与复习**,而不是替你思考——支持「先自己作答、再看 AI 解析」的模式,并沉淀错题本。

## 定位与边界

- ✅ **适用**:个人自学 / 自测练习 / 无障碍辅助 / 休闲趣味竞答

## 当前架构

| 环节 | 现状 |
|---|---|
| **触发** | 终端按 Enter,或全局热键 `Cmd+Shift+Space`(pynput,需辅助功能权限) |
| **选区** | macOS 原生 `screencapture -i -s` 拖框;或 `SNAPQUIZ_REGION` 固定选区。**无全屏选项** |
| **作答** | 两个 Provider:智谱 `glm-4.6v`、opencode `glm-5.3-flash`。纯 Adapter + 静态 profile 表,新增 Provider 只加一条表项 |
| **出站** | 发送前预览**实际出站字节**里的图;批准后才解析密钥、才联网 |
| **结果** | 严格九字段校验;模型自评不以百分比展示 |
| **呈现** | 终端 / 系统对话框 + 通知 |
| **学习** | ⏳ SQLite 错题本、去重缓存、「先自答」浮层 —— 阶段 B |

## 现实预期

- 视觉模型可覆盖**文本 / 公式 / 图表 / 几何 / 看图题**(VLM 正常误差,非 100%)。
- 主要风险是 **VLM 自信错答**:靠展示解析+置信、「先自答」核对、信息不足即拒答来缓解。
- 单题成本:GLM-4.6V-Flash 免费档;隐私上需接受**截图上传云端**(否则走本地 VLM)。

## 路线图

**阶段 A 已完成**(tag `v0.1.0-usable`):可用闭环 + 两个 Provider + 拖框选区 + 出站预览 + 可双击的 .app。

**阶段 B**(接下来):评测集 → 错题本与去重缓存 → 「先自答」浮层 → Carbon 零权限热键。

**阶段 C**(按需):Keychain 存密钥、签名公证(仅在要分发给别人时)。

逐项任务与验收句见 [docs/RECOVERY_PLAN.md](docs/RECOVERY_PLAN.md)。

## 运行

```bash
cd snapquiz
python3 -m venv .venv && source .venv/bin/activate
pip install -e .                 # 基础依赖(httpx / mss / pyobjc ...)
pip install -e ".[hotkey]"       # 可选:真·全局热键(pynput,需辅助功能权限)

cp .env.example .env             # 然后编辑 .env,填入 API key
python scripts/grant_check.py    # 首次:按提示授予「屏幕录制」权限后重启终端

snapquiz                         # 按 Enter → 拖框选题 → 看图确认 → 出答案
snapquiz --trigger hotkey        # 全局热键(默认 Cmd+Shift+Space,需 [hotkey] 依赖 + 辅助功能权限)
```

**一次交互长这样:**

```
按 Enter 触发一次答题(Ctrl+C / Ctrl+D 退出)...
⏎
  → 屏幕变暗,出现十字准星(macOS 原生选区,Esc 取消)
  → 拖框选中题目
  → Quick Look 弹出**即将上传的那张图**,终端同时打印:
       即将上传一张 66 KB 的 image/png 截图
         目标   https://open.bigmodel.cn/api/paas/v4/chat/completions
         模型   glm-4.6v
         总大小 89 KB(envelope 35f3cc9b54cf)
     发送?[y/N] y
  → 答案:C. 29
     模型自评把握:较高(未校准,仅供参考)
     解析:……
```

答 `n` 则**零网络、零密钥读取**,预览临时文件立刻删除。`-y` 可跳过确认(不推荐)。

### 选区两种模式

| | 何时生效 | 行为 |
|---|---|---|
| **拖框**(默认) | 没配 `SNAPQUIZ_REGION` | 每次弹十字准星,Esc 取消 |
| **固定** | 配了 `SNAPQUIZ_REGION` | 直接截那一块,**不弹准星** |

`--select` / `--region` 可强制其一。**两种都不存在「全屏」这个选项。**

> ⚠️ **一个容易踩的坑**:`SNAPQUIZ_REGION` 一旦写进 `.env`,在 shell 里
> `unset SNAPQUIZ_REGION` 是**没用的** —— `load_dotenv()` 会把它重新读回来,
> 于是你以为在拖框、实际却是固定选区。想临时拖框请用 `snapquiz --select`,
> 想永久拖框就把它在 `.env` 里注释掉。启动横幅会明确告诉你当前是哪种模式。

首次运行会一次性征求数据政策同意(截图会传给谁),记录在 `~/.snapquiz/consent.json`,
`snapquiz --revoke-consent` 撤销。这跟每次发送前的确认是**两层**:
同意的是「政策」,批准的是「这一张图」。

> ⚠️ **权限归属(终端版)**:从终端跑时 snapquiz 不是独立 app bundle,
> macOS 把截屏行为归属给**调用它的终端**,所以「屏幕录制」要勾给终端.app。
> 用下面的 `SnapQuiz.app` 就没有这个问题 —— 权限记在它自己名下。

环境变量(见 `.env.example`):

| 变量 | 必填 | 说明 |
|---|---|---|
| `SNAPQUIZ_REGION` | | `left,top,width,height`。**不设 = 每次拖框**(推荐);设了就固定截那块。**没有全屏选项** |
| `SNAPQUIZ_PROVIDER` | | `zhipu`(默认) 或 `opencode_go` |
| `GLM_API_KEY` | ✅* | 智谱 key(provider=zhipu 时必填) |
| `OPENCODE_API_KEY` | ✅* | opencode key(provider=opencode_go 时必填) |
| `SNAPQUIZ_MODEL` | | 不填则用当前 provider 的默认模型;跨 provider 的模型名会被拒绝 |
| `SNAPQUIZ_HOTKEY` | | 默认 `cmd+shift+space` |
| `SNAPQUIZ_TIMEOUT` | | 不填则用 provider 默认值(zhipu 30s / opencode_go 240s) |

### 实测模型矩阵(2026-09-15,同一张合成题图,单次调用)

走本项目完整九字段 prompt,各跑 3 次取中位数。

| Provider | 模型 | 结果 | 中位延迟 | completion tokens |
|---|---|---|---:|---:|
| zhipu | **`glm-4.6v`**(默认) | ✅ 3/3 | 7.6 s | 374 |
| zhipu | `glm-4v-flash` | ✅ | 4.3 s | 136 |
| zhipu | `glm-4.6v-flash` | ❌ `1305` 访问量过大 | — | — |
| opencode_go | **`glm-5.3-flash`**(默认) | ✅ 3/3 | **4.6 s** | **122** |
| opencode_go | `deepseek-v4-flash-vision-exp` | ✅ 3/3 | **3.4 s** | 176 |
| opencode_go | `qwen3.8-flash` | ✅ 3/3 | 5.5 s | 201 |
| opencode_go | `mimo-v2.5` | ✅ 3/3 | 24.5 s | 1513 |

opencode Go 是订阅制,响应里 `cost` 恒为 `0` —— token 数不计费,所以"性价比"的判据
是**延迟与稳定性**。选 `glm-5.3-flash` 而不是更快的 deepseek:后者名字里的 `-exp`
表示实验端点,随时可能消失或改行为,为日常工具省那 1.2 秒不值得。要更快就显式设
`SNAPQUIZ_MODEL=deepseek-v4-flash-vision-exp`。

**用不了的模型**(本工具发的是截图):`glm-4.5-air` → `1210` 纯文本;
`mimo-v2.5-pro` → 404「No endpoints found that support image」;
`mimo-v2-omni` → 400;`gpt-5.6-luna` → 500。

> ⚠️ opencode 的 CDN 会拦 `Python-urllib` 与空 User-Agent(Cloudflare `1010`/403)。
> 本项目用 httpx,不受影响;换传输层时要注意。

> 触发方式说明:`stdin` 串行执行,确认提示直接在终端问;`hotkey` 用 pynput 实现
> 真·全局热键(需辅助功能权限),确认走系统对话框。架构目标里「零权限 Carbon 热键」
> 留待阶段 B Task 9。

## 打包成 SnapQuiz.app(可双击)

```bash
pip install -e ".[app]"
python scripts/build_app.py       # 产物:dist/SnapQuiz.app
```

拖进「应用程序」后双击即可。**未签名**,第一次可能要右键 →「打开」才放行。

打包版和终端版的区别:

| | 终端 | SnapQuiz.app |
|---|---|---|
| 启动 | `source .venv/bin/activate && snapquiz` | 双击 |
| 触发 | 按 Enter(或 `--trigger hotkey`) | 全局热键 `Cmd+Shift+Space` |
| 确认/结果 | 终端问答 + Quick Look | 系统对话框 + Quick Look |
| **屏幕录制权限** | 记在**终端**名下 | 记在 **SnapQuiz** 名下 |
| 配置位置 | 项目目录的 `.env` | **`~/.snapquiz/.env`** |
| 退出 | Ctrl-C | 「运行中」对话框上的「退出」 |

> ⚠️ **配置位置**:双击启动时工作目录是 `/`,**读不到仓库里的 `.env`**。
> 必须把 key 放进 `~/.snapquiz/.env`:
>
> ```bash
> mkdir -p ~/.snapquiz && chmod 700 ~/.snapquiz
> cp .env ~/.snapquiz/.env && chmod 600 ~/.snapquiz/.env
> ```
>
> 从终端跑时两份都会读,就近那份优先。

.app 还需要**辅助功能**权限(全局热键用的是 pynput)。换成零权限的 Carbon 热键
是阶段 B 的 Task 9。

签名 + 公证需要 Apple Developer 账号($99/年),只在要发给别人时才需要 ——
自己用到这一步就够了。

## 开发 / 测试

```bash
python3 -m unittest discover -s tests    # 195 个离线单测,约 0.3 秒
```

覆盖:Provider 档案与模型白名单、端点钉死、权限三态 fail-closed、
截图质量(黑帧/空白帧)、选区模式判定、拖框取消语义、
**预览必须从实际出站字节里解出**、一次性同意的作用域、
GLM 34 个业务错误码与 opencode typed error、严格 JSON 解码与围栏剥离、
出站字节不可变性与密钥隔离、编排顺序(取消则零网络零密钥)、
结果严格校验、呈现格式、README 里让用户跑的脚本能不能跑。

另有 `python -m snapquiz.smoke` 对固定合成题图打一次**真实** GLM(单次,无重试),
用来验证请求形状确实被服务端接受 —— 离线 golden 证明不了这件事。

真实 TCC 权限弹窗、全局热键监听仍需在 macOS 上实跑验证。

## 许可

待定(TBD)。
