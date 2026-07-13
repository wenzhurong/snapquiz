# snapquiz

个人学习刷题助手 —— 热键一按,读取屏幕上的题目,调用 LLM 给出**答案 + 解析 + 相关知识点**,辅助自学、自测与错题复习。

> 状态:🚧 早期阶段(可行性与架构评估完成;后端定为 **GLM-4.6V-Flash 视觉版**,进入 MVP 开发)。完整设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 这是什么

一个运行在 macOS 上的**个人学习工具**:

```
热键触发 → 截取屏幕题目区域 → 直接把截图发给视觉大模型(GLM-4.6V-Flash) → 生成「答案 + 解析」→ 浮层呈现 + 错题本
```

目标是帮助**自学与复习**,而不是替你思考——支持「先自己作答、再看 AI 解析」的模式,并沉淀错题本。

## 定位与边界

- ✅ **适用**:个人自学 / 自测练习 / 无障碍辅助 / 休闲趣味竞答
- ⛔ **不适用**:受监考的考试、认证考试、技术面试等任何被监控的评估场景。这属于学术不端,**本项目不实现任何"规避监考 / 隐藏窗口 / 反检测"相关功能**。

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

## 运行(MVP-0)

```bash
cd snapquiz
python3 -m venv .venv && source .venv/bin/activate
pip install -e .                 # 基础依赖(openai / mss / pyobjc ...)
pip install -e ".[hotkey]"       # 可选:真·全局热键(pynput,需辅助功能权限)

cp .env.example .env             # 然后编辑 .env,填入智谱 GLM_API_KEY
python scripts/grant_check.py    # 首次:按提示授予「屏幕录制」权限后重启终端

snapquiz                         # 默认 stdin 触发:聚焦终端按 Enter,解答当前屏幕上的题
snapquiz --trigger hotkey        # 全局热键(默认 Cmd+Shift+Space,需 [hotkey] 依赖 + 辅助功能权限)
```

可选环境变量(见 `.env.example`):`GLM_MODEL`、`GLM_BASE_URL`、`SNAPQUIZ_HOTKEY`、
`SNAPQUIZ_REGION`(`left,top,width,height` 截取区域,默认全屏)。

> 触发方式说明:MVP-0 默认 `stdin`(零权限)让你立刻验证核心链路;`hotkey` 用 pynput
> 实现真·全局热键但需辅助功能权限。架构目标里「零权限 Carbon 热键」留待 MVP-1。

## 开发 / 测试

```bash
python3 -m unittest discover -s tests    # 45 个纯逻辑单测,无需网络/依赖
```

纯逻辑(配置、prompt、输出解析、busy-guard、编排、格式化、热键转换)均有单测覆盖;
截屏、GLM 网络调用、macOS 权限/通知、全局热键等需在 macOS 上实跑验证。

## 许可

待定(TBD)。
