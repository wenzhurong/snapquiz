"""纯 Provider adapters；导入本包不产生任何 I/O。"""

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.openai_chat import OpenAIChatAdapter

__all__ = ["DirectMultimodalAdapter", "OpenAIChatAdapter"]
