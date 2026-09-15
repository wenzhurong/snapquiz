# snapquiz

个人学习刷题助手 —— 热键一按,读取屏幕上的题目,调用 LLM 给出**答案 + 解析 + 相关知识点**,辅助自学、自测与错题复习。

> **状态(2026-09-15):✅ 核心闭环可用,真实 API 已打通**。
> 对固定合成题图实测:`glm-4v-flash` 4.3 秒答对,过严格校验。
> 尚未接入拖框选区(Task 4)、评测集、错题本与浮层(阶段 B)。
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

## 规划架构

| 阶段 | 方案 |
|---|---|
| **热键** | Carbon `RegisterEventHotKey`(全局、**零 TCC 权限**,仅需屏幕录制)。一次按键 = 一次查询 |
| **捕获** | `mss` 抓屏(内存 BGRA、处理 Retina);首次拖框选区 + 记忆区域 |
| **作答** | **GLM-4.6V-Flash**(视觉、免费、OpenAI 兼容,`https://open.bigmodel.cn/api/paas/v4`)。截图直接作答,产出 `{answer, rationale, confidence}`。藏在可替换 provider 抽象后(可切 GLM-4.6V / Qwen-VL / 本地 VLM) |
| **呈现** | NSPanel 浮层:先自答 → 点击看 答案+解析+置信 |
| **学习** | SQLite:题库 / 错题本 / 去重缓存 |

## 现实预期

- 视觉模型可覆盖**文本 / 公式 / 图表 / 几何 / 看图题**(VLM 正常误差,非 100%)。
- 主要风险是 **VLM 自信错答**:靠展示解析+置信、「先自答」核对、信息不足即拒答来缓解。
- 单题成本:GLM-4.6V-Flash 免费档;隐私上需接受**截图上传云端**(否则走本地 VLM)。

## 路线图(MVP)

- **MVP-0** —— 数天:Carbon 热键 + `mss` 抓固定区 → 发 **GLM-4.6V-Flash** → 通知/简单浮层展示。跑通「一次热键 → 一个答案」闭环。
- **MVP-1** —— 1–2 周:「先自答→看解析」浮层 + SQLite 错题本/去重缓存 + 可改热键 + 选区记忆 + 成本&幻觉护栏。
- **MVP-2** —— 按需:签名+公证 .app + 密钥入 Keychain;可选升级(GLM-4.6V 质量档 / Qwen-VL / 本地 VLM 隐私路)。

## 运行

```bash
cd snapquiz
python3 -m venv .venv && source .venv/bin/activate
pip install -e .                 # 基础依赖(httpx / mss / pyobjc ...)
pip install -e ".[hotkey]"       # 可选:真·全局热键(pynput,需辅助功能权限)

cp .env.example .env             # 然后编辑 .env,填入智谱 GLM_API_KEY
export SNAPQUIZ_REGION=100,100,900,700    # 必填:题目所在区域(左,上,宽,高)
python scripts/grant_check.py    # 首次:按提示授予「屏幕录制」权限后重启终端

snapquiz                         # 默认 stdin 触发:聚焦终端按 Enter,解答该区域里的题
snapquiz --trigger hotkey        # 全局热键(默认 Cmd+Shift+Space,需 [hotkey] 依赖 + 辅助功能权限)
```

每次发送前会先告诉你要上传什么、多大、发到哪,确认后才解析密钥并联网;
回答 `n` 则零网络、零密钥读取。`-y` 可跳过确认(不推荐)。

> ⚠️ **权限归属**:snapquiz 目前不是独立 app bundle,macOS 把截屏行为归属给
> **调用它的终端**。所以「屏幕录制」要勾给终端.app,不是勾给 snapquiz。
> 打包成 .app 之后才会变(见 RECOVERY_PLAN 阶段 C)。

环境变量(见 `.env.example`):

| 变量 | 必填 | 说明 |
|---|---|---|
| `GLM_API_KEY` | ✅ | 智谱开放平台 API Key |
| `SNAPQUIZ_REGION` | ✅ | `left,top,width,height`。**没有全屏默认值** —— 默认全屏会把聊天、终端、通知一并上传 |
| `GLM_MODEL` | | 默认 `glm-4v-flash`(实测最快最稳)。白名单:`glm-4v-flash` / `glm-4v` / `glm-4.6v` / `glm-4.5v` / `glm-4.6v-flash`。**注意 `glm-4.5-air` 等纯文本模型用不了**,本工具发的是截图 |
| `GLM_BASE_URL` | | 只允许官方 endpoint;自定义地址会被拒绝 |
| `SNAPQUIZ_HOTKEY` | | 默认 `cmd+shift+space` |
| `SNAPQUIZ_TIMEOUT` | | 默认 30 秒 |

> 触发方式说明:`stdin` 串行执行,确认提示直接在终端问;`hotkey` 用 pynput 实现
> 真·全局热键(需辅助功能权限),确认走系统对话框。架构目标里「零权限 Carbon 热键」
> 留待阶段 B Task 9。

## 开发 / 测试

```bash
python3 -m unittest discover -s tests    # 137 个离线单测,约 0.15 秒
```

覆盖:配置与端点钉死、权限三态 fail-closed、截图质量(黑帧/空白帧)、
GLM 线格与 34 个业务错误码、严格 JSON 解码、出站字节不可变性与密钥隔离、
编排顺序(取消则零网络零密钥)、结果严格校验、呈现格式。

另有 `python -m snapquiz.smoke` 对固定合成题图打一次**真实** GLM(单次,无重试),
用来验证请求形状确实被服务端接受 —— 离线 golden 证明不了这件事。

真实 TCC 权限弹窗、全局热键监听仍需在 macOS 上实跑验证。

## 许可

待定(TBD)。
