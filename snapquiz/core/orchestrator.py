"""编排一次查询：权限 → 截屏 → Adapter.prepare → 发送 → decode → 严格校验 → 呈现。

所有外部依赖（截屏、发送、呈现、权限）都以可调用对象注入，便于测试与替换 Provider。
这是 MVP-0 就做对的形状，予以保留。

与 v3 的 ``MultimodalPipelineExecutor``（2,375 行、30+ 个私有方法做归属线性化）
相比，这里是一条直线。顺序本身就是安全边界：
权限没过不截图，截图没过不 prepare，prepare 没过不解析密钥，密钥只在发送时存在。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional
from uuid import uuid4

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.config import Config, resolve_api_key
from snapquiz.domain.adapter import TransportResponse
from snapquiz.domain.outbound import OutboundRequest
from snapquiz.domain.solve import (
    PipelineKind,
    SolveProvenance,
    SolveResult,
    StageProvenance,
    StageRole,
)
from snapquiz.result.validator import validate_answer_candidate

logger = logging.getLogger(__name__)

# 发送前的确认钩子。返回 False 即取消，且此时尚未解析密钥、尚未联网。
ApprovalFn = Callable[[OutboundRequest], bool]


def always_approve(prepared: OutboundRequest) -> bool:
    del prepared
    return True


class Orchestrator:
    def __init__(
        self,
        *,
        config: Config,
        adapter: DirectMultimodalAdapter,
        capture_fn: Callable[[], bytes],
        send_fn: Callable[..., TransportResponse],
        present_fn: Callable[[SolveResult], None],
        require_permission_fn: Callable[[], None],
        on_error: Callable[[str], None],
        approve_fn: ApprovalFn = always_approve,
        question_hint: Optional[str] = None,
    ) -> None:
        self._config = config
        self._adapter = adapter
        self._capture_fn = capture_fn
        self._send_fn = send_fn
        self._present_fn = present_fn
        self._require_permission_fn = require_permission_fn
        self._on_error = on_error
        self._approve_fn = approve_fn
        self._question_hint = question_hint

    def run_once(self) -> Optional[SolveResult]:
        """跑完整一次。任何一步失败都不抛给调用方，只走 on_error。"""

        try:
            return self._run_once()
        except Exception as exc:
            # 只暴露类型与安全消息；Provider 原文与密钥永远不进这里。
            logger.debug("run_once failed", exc_info=True)
            self._on_error(f"{type(exc).__name__}: {exc}")
            return None

    def _run_once(self) -> SolveResult:
        cfg = self._config

        # 1. 权限：非 granted 直接抛错，不截图。
        self._require_permission_fn()

        # 2. 截屏（含尺寸/黑帧/空白帧检查）。
        png = self._capture_fn()

        # 3. 准备确切出站字节。此时还没有密钥、没有网络。
        prepared = self._adapter.prepare(
            config=cfg, png=png, user_hint=self._question_hint
        )
        profile_id = cfg.provider_profile_id

        # 4. 发送前确认。取消则零网络、零密钥解析。
        if not self._approve_fn(prepared):
            raise RuntimeError("已取消,未发送任何数据")

        # 5. 批准之后才解析密钥。
        api_key = resolve_api_key(cfg)
        started = time.monotonic()
        try:
            response = self._send_fn(
                prepared,
                api_key=api_key,
                timeout=cfg.timeout,
                provider_profile_id=profile_id,
                error_scheme=cfg.provider.error_scheme,
            )
        finally:
            del api_key
        latency_ms = int((time.monotonic() - started) * 1000)

        # 6. 解码成不可信候选，再由本地严格 Validator 构造唯一可信结果。
        candidate = self._adapter.decode(
            prepared=prepared, response=response, provider_profile_id=profile_id
        )
        provenance = SolveProvenance(
            pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
            stages=(
                StageProvenance(
                    stage_id=uuid4(),
                    role=StageRole.SOLVER,
                    provider_id=cfg.provider.provider_id.value,
                    model_id=cfg.model,
                    adapter_family=self._adapter.adapter_family,
                    adapter_version=self._adapter.adapter_version,
                    attempts=1,
                    network_calls=1,
                    latency_ms=latency_ms,
                ),
            ),
        )
        result = validate_answer_candidate(
            candidate,
            response=response,
            provenance=provenance,
            provider_profile_id=profile_id,
        )

        self._present_fn(result)
        return result
