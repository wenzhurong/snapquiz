"""生成 tests/fixtures/sample_question.png —— 固定的合成题图。

用 Cocoa 渲染文字（pyobjc-Cocoa 已经是运行依赖，不引入新东西）。
输出是确定性的：同一台机器上重复跑得到同一张图。

这张图用于 Task 3 的真实 API 冒烟：题目无歧义、答案唯一，
所以「模型答对了没有」是个可判定的问题，而不是主观判断。

    python scripts/make_sample_question.py
"""
from __future__ import annotations

import pathlib
import sys

WIDTH, HEIGHT = 720, 300
OUT = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sample_question.png"

QUESTION = "下列四个数中，哪一个是质数？"
OPTIONS = ["A.  21", "B.  27", "C.  29", "D.  33"]
EXPECTED_ANSWER = "C"


def render() -> bytes:
    # NSBitmapImageRep + 手动 graphics context 在这台机器上画不出东西（全黑），
    # NSImage 的 lockFocus 路线可靠，用它。
    from AppKit import (
        NSBitmapImageRep,
        NSColor,
        NSFont,
        NSFontAttributeName,
        NSForegroundColorAttributeName,
        NSImage,
        NSMakeRect,
        NSPNGFileType,
        NSRectFill,
        NSString,
    )
    from Foundation import NSMakeSize

    image = NSImage.alloc().initWithSize_(NSMakeSize(WIDTH, HEIGHT))
    image.lockFocus()

    NSColor.whiteColor().set()
    NSRectFill(NSMakeRect(0, 0, WIDTH, HEIGHT))

    black = NSColor.blackColor()

    def draw(text: str, x: float, y: float, size: float) -> None:
        attrs = {
            NSFontAttributeName: NSFont.systemFontOfSize_(size),
            NSForegroundColorAttributeName: black,
        }
        NSString.stringWithString_(text).drawAtPoint_withAttributes_((x, y), attrs)

    # Cocoa 的原点在左下角。
    draw(QUESTION, 48, HEIGHT - 90, 30)
    for index, option in enumerate(OPTIONS):
        draw(option, 80, HEIGHT - 150 - index * 40, 26)

    rep = NSBitmapImageRep.alloc().initWithFocusedViewRect_(
        NSMakeRect(0, 0, WIDTH, HEIGHT)
    )
    image.unlockFocus()
    return bytes(rep.representationUsingType_properties_(NSPNGFileType, {}))


def main() -> int:
    try:
        png = render()
    except ImportError:
        print("需要 pyobjc-framework-Cocoa（pip install -e .）", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(png)
    print(f"写入 {OUT}  ({len(png)} 字节, {WIDTH}x{HEIGHT})")
    print(f"题目:{QUESTION}  选项:{' '.join(OPTIONS)}")
    print(f"正确答案:{EXPECTED_ANSWER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
