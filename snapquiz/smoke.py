"""对固定合成题图打一次真实 GLM，验证请求形状确实被服务端接受。

    python -m snapquiz.smoke                       # 用 tests/fixtures/sample_question.png
    python -m snapquiz.smoke --image path/to.png   # 换一张图

为什么需要这一步：到目前为止，请求形状只跟仓库里的 golden fixture 核对过，
**从未经过真实服务端验证**。golden 是当初照着文档写的，文档可能过时、
也可能当初就理解错了 —— 只有真打一次才知道。

这条路径刻意与产品入口分开：
- 输入是文件，不截屏，因此不需要屏幕权限、不需要选区；
- 只调一次，无自动重试（失败就是失败，不要用重试掩盖形状错误）；
- 记录的证据全是非内容的：HTTP 状态、延迟、token 用量、是否通过严格校验。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
import time
from uuid import uuid4

from snapquiz.adapters.openai_chat import OpenAIChatAdapter
from snapquiz.capture.validation import check_png_size
from snapquiz.config import ConfigError, load_config, resolve_api_key
from snapquiz.domain.solve import (
    PipelineKind,
    SolveProvenance,
    SolveStatus,
    StageProvenance,
    StageRole,
)
from snapquiz.present.notify import format_result
from snapquiz.result.validator import validate_answer_candidate
from snapquiz.transport.client import send_once

DEFAULT_IMAGE = (
    pathlib.Path(__file__).resolve().parent.parent
    / "tests"
    / "fixtures"
    / "sample_question.png"
)
EXPECTED_ANSWER = "C"  # sample_question.png 的唯一正确答案（29 是质数）

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_CANCELLED = 3
EXIT_API_ERROR = 5


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="snapquiz.smoke",
        description="对固定合成题图打一次真实 GLM(单次,无重试)",
    )
    parser.add_argument("--image", type=pathlib.Path, default=DEFAULT_IMAGE)
    parser.add_argument("--hint", default=None, help="可选的补充提示")
    parser.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    args = parser.parse_args(argv)

    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    try:
        cfg = load_config(os.environ, require_region=False)
    except ConfigError as exc:
        print(f"❌ 配置错误:{exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if not args.image.exists():
        print(f"❌ 找不到图片:{args.image}", file=sys.stderr)
        print("   先跑 python scripts/make_sample_question.py 生成", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    png = args.image.read_bytes()
    check_png_size(png)

    adapter = OpenAIChatAdapter()
    profile_id = cfg.provider_profile_id
    prepared = adapter.prepare(config=cfg, png=png, user_hint=args.hint)

    print("=" * 66)
    print("真实 API 冒烟 —— 单次调用,无自动重试")
    print("=" * 66)
    print(f"  图片      {args.image}  ({len(png)} 字节)")
    print(f"  provider  {cfg.provider.provider_id.value}")
    print(f"  模型      {cfg.model}" + ("  (推理模型)" if cfg.is_reasoning_model else ""))
    print(f"  端点      {prepared.canonical_url}")
    print(f"  请求体    {prepared.payload_byte_size} 字节")
    print(f"  envelope  {str(prepared.envelope_digest)[:16]}")
    print()

    if not args.yes:
        try:
            if input("发起真实 API 调用?[y/N] ").strip().lower() not in ("y", "yes"):
                print("已取消,未发送。")
                return EXIT_CANCELLED
        except (EOFError, KeyboardInterrupt):
            print("\n已取消,未发送。")
            return EXIT_CANCELLED

    api_key = resolve_api_key(cfg)
    started = time.monotonic()
    try:
        response = send_once(
            prepared,
            api_key=api_key,
            timeout=cfg.timeout,
            provider_profile_id=profile_id,
            error_scheme=cfg.provider.error_scheme,
        )
    except Exception as exc:
        elapsed = (time.monotonic() - started) * 1000
        print(f"❌ 调用失败 ({elapsed:.0f} ms): {type(exc).__name__}: {exc}")
        print("   不重试 —— 形状错误靠重试掩盖不掉。")
        return EXIT_API_ERROR
    finally:
        del api_key
    latency_ms = int((time.monotonic() - started) * 1000)

    print("— 传输 —")
    print(f"  HTTP        {response.http_status}")
    print(f"  延迟        {latency_ms} ms")
    print(f"  响应体      {response.response_byte_size} 字节")

    try:
        candidate = adapter.decode(
            prepared=prepared, response=response, provider_profile_id=profile_id
        )
    except Exception as exc:
        print(f"\n❌ 解码失败:{type(exc).__name__}: {exc}")
        print("   服务端接受了请求,但响应形状与 Adapter 预期不符。")
        return EXIT_API_ERROR

    # 智谱把 request_id 放在响应体里，不是响应头，所以要等解码后才拿得到。
    print(f"  request_id  {candidate.provider_request_id}")

    usage = candidate.usage
    print("\n— 用量 —")
    print(f"  prompt      {usage.input_tokens}")
    print(f"  completion  {usage.output_tokens}")
    print(f"  total       {usage.total_tokens}")

    provenance = SolveProvenance(
        pipeline_kind=PipelineKind.DIRECT_MULTIMODAL,
        stages=(
            StageProvenance(
                stage_id=uuid4(),
                role=StageRole.SOLVER,
                provider_id=cfg.provider.provider_id.value,
                model_id=cfg.model,
                adapter_family=adapter.adapter_family,
                adapter_version=adapter.adapter_version,
                attempts=1,
                network_calls=1,
                latency_ms=latency_ms,
            ),
        ),
    )
    try:
        result = validate_answer_candidate(
            candidate,
            response=response,
            provenance=provenance,
            provider_profile_id=profile_id,
        )
    except Exception as exc:
        print(f"\n❌ 严格校验拒绝了模型输出:{type(exc).__name__}: {exc}")
        print("   服务端与传输都正常,但模型没有按约定的 9 字段 schema 回答。")
        return EXIT_API_ERROR

    print("\n— 结果 —")
    print(format_result(result))

    if args.image == DEFAULT_IMAGE:
        correct = (
            result.status is SolveStatus.ANSWERED
            and (result.answer or "").strip().upper().startswith(EXPECTED_ANSWER)
        )
        print()
        print(
            f"  正确答案 {EXPECTED_ANSWER} → "
            + ("✅ 答对" if correct else f"❌ 答错(得到 {result.answer!r})")
        )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
