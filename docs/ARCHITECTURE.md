# snapquiz 架构与策略(v2 · GLM-4.6V-Flash 视觉版)

> **一句话**:macOS 个人自学答题助手。按一次全局热键 → 截屏 → **把截图直接发给视觉大模型(GLM-4.6V-Flash,免费)** → 得到「答案 + 解析」→ 浮层呈现 + 沉淀错题本。
> **定位**:仅限个人自学 / 自测 / 无障碍,**不含任何反监考、隐身、绕过检测的特性**。

---

## 0. 版本说明:为什么是这套(相对 v1 的关键转变)

v1 曾评估「DeepSeek + OCR(纯文本)」:因为 **DeepSeek 的 API 只收文本**(其视觉能力只在网页版、未开放 API),题目必须先被 OCR 转成文本,导致:

- 必须自建脆弱的 `OCR → 公式OCR → 分诊` 前端;
- 图 / 几何 / 电路 / 坐标读数 / "哪张图显示…" 等题型是**结构性硬天花板**,纯文本管线无解。

**v2 改用能直接读图的视觉 API,一次调用就把整条 OCR 前端塌缩掉,并铲平了图形题天花板。** 选 **GLM-4.6V-Flash** 的理由:视觉 + **官方免费** + OpenAI 兼容 + 128K 上下文 + 国内直连。

> 注:GLM-4.6V-Flash 免费一说以智谱官方文档为准,接入前请复核当前条款与限流。

---

## 1. 已定的关键决策与约束

| 项 | 决定 |
|---|---|
| LLM 主力 | **GLM-4.6V-Flash**(视觉),经 `openai` SDK 调用 |
| base_url | `https://open.bigmodel.cn/api/paas/v4` |
| 模型代号 | `glm-4.6v-flash`(接入前于官方模型页复核确切字符串) |
| 图片传法 | OpenAI 标准 `image_url`(base64 data URL) |
| 触发 | 全局热键,**一次按键 = 一次查询** |
| 平台 / 语言 | macOS / Python(MVP) |
| 用途 | 个人自学,无反监考特性 |
| Provider 抽象 | **保留**:后续可切 GLM-4.6V(质量档)、Qwen-VL、Gemini/Claude/GPT,或本地 VLM(隐私路),或 DeepSeek(纯文本快路) |

---

## 2. 整体架构(简化后)

### 2.1 组件图

```
按热键 (Cmd+Shift+Space)
   │  Carbon RegisterEventHotKey 回调(主线程 RunLoop)—— 零 TCC 权限
   ▼
单槽 busy-guard  ← 正忙则丢弃重复/长按,杜绝并发截图与重复调用
   ▼
截屏 (mss,内存 BGRA 不落盘,处理 Retina 缩放)  ← 需 Screen Recording 权限
   ▼
VlmClient (openai SDK → GLM-4.6V-Flash)
   · 把截图作为 image_url(base64)+ 固定 system 提示一起发送
   · 结构化产出 {answer, rationale, confidence}
   · 超时 / 重试 / 成本&限流护栏
   ▼
Presenter (NSPanel 浮层:先自答 → 点击看 答案+解析+置信提示)
   ▼
StudyStore (SQLite:题库 / 错题本 / 去重缓存)
```

### 2.2 一次热键的数据流

1. **触发**:按 `Cmd+Shift+Space`,Carbon 回调在主线程被调用。
2. **去重再入保护**:回调不内联执行,而是投递到 `maxsize=1` 单槽队列;worker 忙则丢弃后续按键。
3. **截屏**:`mss` 抓取记忆的区域(或首次拖框选区),返回内存 BGRA,不落盘;处理 backing scale factor 避免 Retina 裁错。
4. **调用 VLM**:`VlmClient` 把截图编码为 base64 data URL,连同 system 提示(「你在帮助用户自学做题,给出答案、解析、置信度;信息不足就直说」)发给 GLM-4.6V-Flash。
5. **结构化解析**:优先用 function-calling / JSON 指令拿到 `{answer, rationale, confidence}`;容错解析 + 一次重试。
6. **呈现**:`Presenter` 浮层默认「先自答」——先显示模型复述的题目 + 「点击查看答案」,点开才展示答案+解析+置信提示。
7. **落库**:写入本地 SQLite(题目截图哈希、答案、时间、是否加入错题本)。
8. **重新武装**:清除 busy 标志,准备下一次热键。

---

## 3. 各组件选型与理由

- **全局热键 —— Carbon `RegisterEventHotKey`**(pyobjc,或签名 Swift 小 helper):唯一**不需要辅助功能(Accessibility)权限**的全局热键 API;既然截屏已必须申请 Screen Recording,这样全程**只需一个权限**,UX 摩擦最低。不能绑纯修饰键、可能与他 app 冲突且无可靠占用报错 → 默认带修饰键组合并**允许改键**。
- **截屏 —— `mss`**:纯 ctypes、极快、内存 BGRA 直喂后续,免磁盘往返;必须处理 Retina 缩放。备选 `screencapture -i` 用于交互式拖框选区。
- **VLM 客户端 —— `openai` SDK 指向 GLM**:藏在 `VlmProvider` 抽象后。**结构化输出**:GLM 支持 function-calling,用它拿 `{answer, rationale, confidence}` 最稳;或在 prompt 里要求 JSON + 容错解析 + 一次重试(不要假设支持 OpenAI 的严格 `json_schema`)。
- **呈现 —— NSPanel 浮层**:「先自答 → 看解析」契合自学、抑制机械抄答,并给用户核对模型是否读对题的机会。
- **学习特性 —— SQLite**:题库 / 错题本 / 去重缓存(相同截图哈希直接命中历史,既省调用又利复习)。

---

## 4. 能力与限制(视觉版)

| 题型 | 可行性 | 说明 |
|---|---|---|
| 纯文本 选择/判断/填空 | ✅ | 视觉模型直接读整图含选项结构 |
| 含公式的数理题 | ✅(VLM 正常误差) | 不再需要单独公式 OCR |
| 图 / 几何 / 电路 / 坐标读数 / 看图选择 | ✅(VLM 正常误差) | **v1 的硬天花板在此消除** |
| 表格题 | ✅ | 模型直接看版式 |

**仍要认真对待的限制(护栏而非能力):**

1. **VLM 自信错答(幻觉)**——最主要风险。答错和答对长得一样。护栏:浮层展示**解析 + 置信度**、「先自答」让用户核对、system 提示要求**信息不足就明说不作答**。
2. **小字号 / 低清 / 强压缩截图**会降准。护栏:保证捕获分辨率,必要时提示重截。
3. **隐私 —— 截图会上传云端**。个人刷题通常可接受;若需完全本地不出网,走**本地 VLM**(Apple Silicon 上 MLX/Ollama 跑 Qwen2.5-VL / MiniCPM-V),更重更慢、准确率略低,作为隐私优先备选(provider 抽象已预留)。

> v1 里「图形题明确拒答」的策略在 v2 **不再需要**。

---

## 5. 待你拍板的决策(精简)

| # | 决策 | 推荐 |
|---|---|---|
| D1 | 答案呈现 | **先自答 → 点击看解析**(附置信提示) |
| D2 | 选区 UX | 首次拖框 + **记住上次区域** + 「重选」快捷键 |
| D3 | 热键可改 | **可改**,默认 `Cmd+Shift+Space` |
| D4 | 打包形态 | MVP 先跑 `python` 脚本;成品做**签名+公证 .app**(TCC 授权绑代码身份,更稳) |
| D5 | 隐私 | 默认**接受截图上云**(用免费 GLM);若不接受 → 走本地 VLM 路线 |
| D6 | 题型 / 语种 | **需你告知**:主要题型与语种(纯中文 / 中英混 / 多语),便于调 prompt 与备选模型 |

---

## 6. 目录结构与依赖

```
snapquiz/
├── pyproject.toml
├── .env.example                 # GLM_API_KEY=...(真实 .env 入 .gitignore)
├── snapquiz/
│   ├── app.py                   # 入口:装配 RunLoop + 组件,启动热键
│   ├── config.py                # 读 .env / 用户设置(热键、区域、provider、开关)
│   ├── hotkey/carbon_hotkey.py  # RegisterEventHotKey 封装(零 TCC)
│   ├── capture/screen.py        # mss 抓帧 + Retina 缩放 + 区域记忆
│   ├── llm/
│   │   ├── base.py              # VlmProvider 接口
│   │   ├── glm.py               # GLM-4.6V-Flash(openai SDK)实现
│   │   ├── prompt.py            # system 提示 + 结构化产出约定
│   │   └── guardrails.py        # 超时/重试/成本&限流/幻觉门控
│   ├── present/panel.py         # NSPanel 浮层 + 先自答再看解析
│   ├── study/
│   │   ├── store.py             # SQLite 封装
│   │   ├── models.py            # Question / Attempt / WrongItem
│   │   └── wrongbook.py         # 错题本
│   └── core/
│       ├── orchestrator.py      # 单槽 worker + busy-guard,串起全流程
│       └── permissions.py       # Screen Recording 自检 fail-closed
├── tests/
└── scripts/grant_check.py       # 权限预检小工具

# 可选(非 MVP 必需):
#   llm/local_vlm.py             # 本地 VLM(隐私路)
#   ocr/                         # 纯文本快路/离线兜底,若确有需要再加
```

**关键依赖**:`pyobjc-framework-Carbon`/`-Cocoa`(热键+RunLoop)、`mss`(截屏)、`openai`(指向 GLM)、`python-dotenv`(密钥)、标准库 `sqlite3`(存储)、`pyobjc`(`CGPreflightScreenCaptureAccess` 权限自检)。

---

## 7. 错误处理 / 成本 / 健壮性

- **密钥**:只存 `.env`(`GLM_API_KEY`),`.env` 入 `.gitignore`,仓库只留 `.env.example`;不硬编码、不打日志。成品 .app 迁 Keychain。
- **权限 fail-closed**:启动与每次截屏前用 `CGPreflightScreenCaptureAccess()` 预检;未授权则弹明确引导,**绝不静默拿黑帧硬发**。选 Carbon 热键 → 无需 Accessibility,规避 pynput 的静默失败。
- **重试/超时**:LLM 调用设硬超时 + 对网络/5xx 指数退避重试(2–3 次),4xx 不重试直接报错。
- **成本 & 限流护栏**:单槽 busy-guard 本身杜绝连击重复计费;截图哈希**去重缓存**命中历史直接返回;免费档有 RPM/并发限流(单用户热键场景足够),命中限流时排队并提示;可选每日调用上限。
- **幻觉护栏**:展示解析 + 置信度、「先自答」核对点、system 提示要求信息不足时明说不作答。

---

## 8. 分阶段构建(GLM 视觉栈)

- **MVP-0(闭环,数天)**:Carbon 热键 + 单槽 busy-guard + `mss` 抓固定区(含 Retina)+ 发 **GLM-4.6V-Flash** + 结果用系统通知/简单浮层展示;Screen Recording fail-closed 自检;`.env` 管密钥。**验收**:对屏幕上一道题按一次热键,数秒内看到答案,连按不并发。
- **MVP-1(学习特性 + 稳健,1–2 周)**:「先自答→看解析」NSPanel 浮层(带置信);SQLite 题库/错题本/去重缓存;可改热键 + 选区记忆 + 拖框重选;成本&幻觉护栏。
- **MVP-2(打磨/分发,按需)**:签名+公证 .app,密钥迁 Keychain;可选升级——GLM-4.6V(质量档)/ Qwen-VL 备选、**本地 VLM 隐私路**、错题本复习流程(按标签/间隔重现)。

---

## 9. 主要风险与未知数

1. **VLM 自信错答**:靠置信展示 + 先自答 + 拒答提示缓解,不能根除。
2. **小字/低清截图降准**:保证捕获分辨率、必要时提示重截。
3. **隐私上云**:默认接受;隐私优先则走本地 VLM。
4. **免费档限流/条款变动**:GLM-4.6V-Flash 免费与限流以官方为准,provider 抽象保证可快速切付费档或他家。
5. **Carbon 已废弃**:`RegisterEventHotKey` 理论上未来可能移除(当前仍被 VS Code/Slack/Electron 广泛使用),暂无「非废弃 + 零权限」替代。
6. **TCC 绑代码身份**:升级 Python / 重签名 / 从 Finder 启动会使 Screen Recording 授权失效 → 成品用签名公证 .app 固定身份。
7. **待告知**:主要题型分布与语种(D6),决定 prompt 调优与是否需要备选模型。

---

### 一句话总结

v2 把系统从「和易碎 OCR 前端搏斗」变成「一次热键 → 一张截图 → 一个会看图的免费模型 → 答案+解析」。成败关键从「OCR 保真」转移到「**对 VLM 的错答保持诚实**(展示解析+置信、先自答、信息不足就拒答)」与「隐私是否接受上云」。技术栈:Carbon 零权限热键 + mss 抓屏 + GLM-4.6V-Flash(藏在可替换 provider 抽象后)+ 先自答浮层 + SQLite 错题本。
