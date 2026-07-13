import unittest

from snapquiz.llm.parse import parse_answer


class ParseAnswerTest(unittest.TestCase):
    def test_clean_json_object(self):
        r = parse_answer('{"answer": "B", "rationale": "因为二加二等于四", "confidence": 0.9}')
        self.assertTrue(r.parsed_ok)
        self.assertEqual(r.answer, "B")
        self.assertEqual(r.rationale, "因为二加二等于四")
        self.assertEqual(r.confidence, 0.9)

    def test_json_wrapped_in_markdown_fence(self):
        text = '```json\n{"answer": "C", "rationale": "见解析", "confidence": 0.7}\n```'
        r = parse_answer(text)
        self.assertTrue(r.parsed_ok)
        self.assertEqual(r.answer, "C")
        self.assertEqual(r.confidence, 0.7)

    def test_json_embedded_in_surrounding_prose(self):
        text = '好的,这是我的判断:\n{"answer": "A", "rationale": "第一项正确"}\n希望有帮助。'
        r = parse_answer(text)
        self.assertTrue(r.parsed_ok)
        self.assertEqual(r.answer, "A")
        self.assertEqual(r.rationale, "第一项正确")

    def test_missing_confidence_becomes_none(self):
        r = parse_answer('{"answer": "D", "rationale": "x"}')
        self.assertTrue(r.parsed_ok)
        self.assertIsNone(r.confidence)

    def test_confidence_as_numeric_string_is_coerced(self):
        r = parse_answer('{"answer": "A", "rationale": "x", "confidence": "0.8"}')
        self.assertEqual(r.confidence, 0.8)

    def test_out_of_range_confidence_becomes_none(self):
        r = parse_answer('{"answer": "A", "rationale": "x", "confidence": 5}')
        self.assertIsNone(r.confidence)

    def test_non_json_falls_back_to_whole_text_as_rationale(self):
        text = "答案是 B,因为它符合定义。"
        r = parse_answer(text)
        self.assertFalse(r.parsed_ok)
        self.assertEqual(r.answer, "")
        self.assertEqual(r.rationale, text)
        self.assertIsNone(r.confidence)

    def test_raw_is_always_preserved(self):
        text = '{"answer": "B", "rationale": "x", "confidence": 0.5}'
        self.assertEqual(parse_answer(text).raw, text)


if __name__ == "__main__":
    unittest.main()
