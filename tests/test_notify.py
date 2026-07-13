import unittest

from snapquiz.llm.base import AnswerResult
from snapquiz.present.notify import format_result


def res(answer="B", rationale="因为二加二等于四", confidence=0.9, parsed_ok=True, raw="{}"):
    return AnswerResult(
        answer=answer, rationale=rationale, confidence=confidence, raw=raw, parsed_ok=parsed_ok
    )


class FormatResultTest(unittest.TestCase):
    def test_shows_answer_and_rationale(self):
        text = format_result(res())
        self.assertIn("B", text)
        self.assertIn("因为二加二等于四", text)

    def test_confidence_shown_as_percent(self):
        self.assertIn("90%", format_result(res(confidence=0.9)))

    def test_confidence_none_shown_as_unknown(self):
        self.assertIn("未知", format_result(res(confidence=None)))

    def test_unparsed_shows_fallback_note_and_raw_text(self):
        text = format_result(
            res(answer="", rationale="模型没吐 JSON 的原文", parsed_ok=False, raw="模型没吐 JSON 的原文")
        )
        self.assertIn("未能结构化解析", text)
        self.assertIn("模型没吐 JSON 的原文", text)


if __name__ == "__main__":
    unittest.main()
