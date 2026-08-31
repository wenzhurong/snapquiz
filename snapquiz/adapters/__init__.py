"""Pure v3 Provider adapters; importing this package performs no I/O."""

# Keep package import minimal: the built-in Registry imports the content-
# addressed prompt policy, while concrete Adapters consume that Registry.
__all__: list[str] = []
