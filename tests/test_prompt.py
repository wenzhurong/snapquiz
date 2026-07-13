import unittest

from snapquiz.llm.prompt import build_messages

DATA_URL = "data:image/png;base64,AAAA"


class BuildMessagesTest(unittest.TestCase):
    def test_returns_system_then_user(self):
        msgs = build_messages(DATA_URL)
        self.assertEqual([m["role"] for m in msgs], ["system", "user"])

    def test_system_prompt_requests_json_with_required_keys(self):
        system = build_messages(DATA_URL)[0]["content"].lower()
        self.assertIn("json", system)
        for key in ("answer", "rationale", "confidence"):
            self.assertIn(key, system)

    def test_system_prompt_instructs_to_admit_uncertainty(self):
        # 幻觉护栏:信息不足时必须让模型明说,而不是硬猜
        system = build_messages(DATA_URL)[0]["content"]
        self.assertTrue(
            any(kw in system for kw in ("信息不足", "无法作答", "不确定")),
            "system prompt 应包含拒答/不确定的指令",
        )

    def test_user_message_carries_image_url_part(self):
        user = build_messages(DATA_URL)[1]
        image_parts = [
            p for p in user["content"]
            if isinstance(p, dict) and p.get("type") == "image_url"
        ]
        self.assertEqual(len(image_parts), 1)
        self.assertEqual(image_parts[0]["image_url"]["url"], DATA_URL)

    def test_hint_is_included_when_provided(self):
        user = build_messages(DATA_URL, question_hint="这是一道化学题")[1]
        text = " ".join(
            p.get("text", "") for p in user["content"] if isinstance(p, dict)
        )
        self.assertIn("这是一道化学题", text)

    def test_no_hint_still_valid(self):
        user = build_messages(DATA_URL)[1]
        text_parts = [p for p in user["content"] if isinstance(p, dict) and p.get("type") == "text"]
        self.assertGreaterEqual(len(text_parts), 1)


if __name__ == "__main__":
    unittest.main()
