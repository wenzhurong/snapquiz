"""构造发给视觉大模型的 messages。

设计要点:
- 定位为「个人自学助手」,输出 答案 + 解析 + 置信度。
- 幻觉护栏:显式要求信息不足时明说「无法作答」,而不是硬猜。
- 要求返回 JSON(键:answer / rationale / confidence),便于结构化解析。
"""
from __future__ import annotations

from typing import List, Optional

SYSTEM_PROMPT = (
    "你是一个帮助用户自学做题的助手。用户会给你一张屏幕截图,里面是一道题目"
    "(可能是选择、判断、填空,也可能含公式、图表或图形)。请仔细看图并作答。\n"
    "严格返回一个 JSON 对象,不要有多余文字,字段如下:\n"
    '  "answer": 答案本身(选择题给选项字母如 "B";其它题型给简洁答案),\n'
    '  "rationale": 简要解析/推理过程,\n'
    '  "confidence": 0 到 1 之间的数字,表示你对该答案的把握。\n'
    "重要:如果截图不清晰、题目不完整、或这是一道必须看懂图形/图像才能作答而你无法可靠判断的题,"
    "请在 rationale 中明确说明「信息不足,无法作答」并给出较低的 confidence,不要编造答案。"
)


def build_messages(image_data_url: str, question_hint: Optional[str] = None) -> List[dict]:
    user_text = "请解答这张截图里的题目,并按要求返回 JSON。"
    if question_hint:
        user_text += f"\n补充提示:{question_hint}"

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": user_text},
                {"type": "image_url", "image_url": {"url": image_data_url}},
            ],
        },
    ]
