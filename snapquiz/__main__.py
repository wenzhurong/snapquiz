"""``python -m snapquiz`` 与 .app 的启动入口。

py2app 会把这个文件当 main script;它必须尽量薄,真正的逻辑在 app.main。
"""
from snapquiz.app import main

if __name__ == "__main__":
    raise SystemExit(main())
