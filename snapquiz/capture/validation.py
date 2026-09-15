"""截图质量检查。

v3 版本有 1005 行，其中绝大部分是一个完整的 PNG signature/chunk CRC/zlib 解码器，
用来防御恶意 PNG。但截图是我们自己用 mss 生成的，不存在不可信 PNG 输入 ——
所以这里只保留真正有用的那部分：尺寸上限、黑帧、空白帧，直接在原始像素上算。

判定阈值沿用 v3（BLACK_LUMA_MAX / MIN_VISIBLE_LUMA_SPAN），它们是调过的。
"""
from __future__ import annotations

BLACK_LUMA_MAX = 8
MIN_VISIBLE_LUMA_SPAN = 8

MAX_IMAGE_EDGE_PX = 16_384
MAX_PNG_BYTES = 8 * 1_024 * 1_024

# 每行最多采样这么多像素；整幅全采在 4K 选区上是几百万次 Python 循环，没必要。
_SAMPLE_STRIDE = 7


class CaptureQualityError(Exception):
    """截图内容不可用（黑帧/空白/超限）。不含任何像素数据。"""


def check_dimensions(width_px: int, height_px: int) -> None:
    if width_px <= 0 or height_px <= 0:
        raise CaptureQualityError("截图尺寸为零")
    if width_px > MAX_IMAGE_EDGE_PX or height_px > MAX_IMAGE_EDGE_PX:
        raise CaptureQualityError(
            f"截图单边超过 {MAX_IMAGE_EDGE_PX}px,拒绝上传"
        )


def check_png_size(png: bytes) -> None:
    if not png:
        raise CaptureQualityError("截图为空")
    if len(png) > MAX_PNG_BYTES:
        raise CaptureQualityError(
            f"截图编码后 {len(png) // 1024} KB,超过 {MAX_PNG_BYTES // 1024} KB 上限"
        )


def check_frame_quality(rgb: bytes, width_px: int, height_px: int) -> None:
    """在原始 RGB 缓冲上判黑帧/空白帧。

    ``rgb`` 是紧密排列的 24-bit RGB（mss 的 ``ScreenShot.rgb``）。
    """

    expected = width_px * height_px * 3
    if len(rgb) != expected:
        raise CaptureQualityError("像素缓冲长度与尺寸不符")

    luma_min = 255
    luma_max = 0
    step = 3 * _SAMPLE_STRIDE
    for i in range(0, expected - 2, step):
        # ITU-R BT.601 亮度，整数近似，与 v3 一致。
        luma = (77 * rgb[i] + 150 * rgb[i + 1] + 29 * rgb[i + 2]) >> 8
        if luma < luma_min:
            luma_min = luma
        if luma > luma_max:
            luma_max = luma

    if luma_max <= BLACK_LUMA_MAX:
        raise CaptureQualityError("截图为黑帧或接近黑帧;检查选区坐标是否落在屏幕外")
    if luma_max - luma_min < MIN_VISIBLE_LUMA_SPAN:
        raise CaptureQualityError("截图为空白帧,没有可辨识的内容")
