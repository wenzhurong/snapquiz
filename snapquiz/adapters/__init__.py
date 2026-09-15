"""纯 v3 Provider adapters；导入本包不产生任何 I/O。"""

from snapquiz.adapters.base import DirectMultimodalAdapter
from snapquiz.adapters.glm import GlmChatAdapter

__all__ = ["DirectMultimodalAdapter", "GlmChatAdapter"]
