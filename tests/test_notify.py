import unittest

from snapquiz.domain.solve import ConfidenceKind, SolveResult, SolveStatus
from snapquiz.present.notify import format_result
from tests.helpers import provenance


def res(**over):
    fields = dict(
        schema_version="snapquiz.solve-result.v2",
        status=SolveStatus.ANSWERED,
        question_summary="二加二等于几",
        answer="4",
        rationale="因为二加二等于四",
        confidence=0.9,
        confidence_kind=ConfidenceKind.MODEL_SELF_REPORTED,
        confidence_calibration_ref=None,
        warnings=(),
        provenance=provenance(),
    )
    fields.update(over)
    return SolveResult(**fields)


class FormatResultTest(unittest.TestCase):
    def test_shows_answer_and_rationale(self):
        text = format_result(res())
        self.assertIn("4", text)
        self.assertIn("因为二加二等于四", text)

    def test_self_reported_confidence_is_not_a_percentage(self):
        """把模型自评渲染成 90% 会让主观自评看起来像可靠度。"""

        text = format_result(res(confidence=0.9))
        self.assertNotIn("90%", text)
        self.assertIn("模型自评", text)
        self.assertIn("未校准", text)
        self.assertIn("较高", text)

    def test_self_reported_levels(self):
        self.assertIn("较高", format_result(res(confidence=0.95)))
        self.assertIn("中等", format_result(res(confidence=0.6)))
        self.assertIn("较低", format_result(res(confidence=0.2)))

    def test_no_confidence_line_when_absent(self):
        text = format_result(res(confidence=None, confidence_kind=ConfidenceKind.NONE))
        self.assertNotIn("把握", text)

    def test_non_answered_status_is_labelled(self):
        for status, marker in (
            (SolveStatus.INSUFFICIENT_INPUT, "信息不足"),
            (SolveStatus.UNSUPPORTED_INPUT, "无法通过截图"),
            (SolveStatus.REFUSED, "拒绝作答"),
        ):
            with self.subTest(status=status):
                text = format_result(
                    res(status=status, answer=None, question_summary=None)
                )
                self.assertIn(marker, text)

    def test_warnings_are_shown(self):
        text = format_result(res(warnings=("截图较模糊",)))
        self.assertIn("截图较模糊", text)


if __name__ == "__main__":
    unittest.main()
