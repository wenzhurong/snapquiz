"""SnapQuiz 命令行入口。

MVP-0 的 ``截图 → GLM`` 直连链已经冻结。v3 安全链就绪前，本入口只
解析命令行参数并返回稳定的禁用状态；不得加载配置或访问任何外部能力。
"""
from __future__ import annotations

import argparse
import sys

from snapquiz.core.legacy import (
    LEGACY_DISABLED_EXIT_CODE,
    LEGACY_DISABLED_MESSAGE,
    raise_legacy_pipeline_disabled,
)


def _build_orchestrator(cfg):
    """阻断仍直接调用旧初始化 helper 的代码。"""

    del cfg
    raise_legacy_pipeline_disabled()


def _startup_permission_hint() -> None:
    """阻断仍直接调用旧权限 helper 的代码。"""

    raise_legacy_pipeline_disabled()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="snapquiz",
        description="个人学习刷题助手（v3 安全链迁移中）",
    )
    parser.add_argument(
        "--trigger",
        choices=["stdin", "hotkey"],
        default="stdin",
        help="保留的旧参数；v3 安全链就绪前两种入口都不会启动",
    )
    parser.parse_args(argv)

    print(LEGACY_DISABLED_MESSAGE, file=sys.stderr, flush=True)
    return LEGACY_DISABLED_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
