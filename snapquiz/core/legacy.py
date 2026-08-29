"""MVP-0 legacy pipeline 的集中 fail-closed 边界。

新的 v3 plan/consent/egress 链尚未完成时，任何旧入口都只能返回这个
稳定错误，不能继续读取屏幕、解析凭据、构造 SDK 或发起网络请求。
"""
from __future__ import annotations

from typing import NoReturn

LEGACY_PIPELINE_ID = "mvp0.direct_screen_to_glm"
LEGACY_DISABLED_EXIT_CODE = 3
LEGACY_DISABLED_MESSAGE = (
    "SnapQuiz MVP-0 远程截图管线已禁用；v3 安全链尚未就绪，"
    "未执行配置、权限、截屏或网络操作。"
)


class LegacyPipelineDisabledError(RuntimeError):
    """旧截图直连模型路径被显式冻结。"""

    code = "legacy_pipeline_disabled"
    pipeline_id = LEGACY_PIPELINE_ID

    def __init__(self) -> None:
        super().__init__(LEGACY_DISABLED_MESSAGE)


def raise_legacy_pipeline_disabled() -> NoReturn:
    """在所有 legacy 边界产生一致且不包含敏感数据的终态错误。"""

    raise LegacyPipelineDisabledError()
