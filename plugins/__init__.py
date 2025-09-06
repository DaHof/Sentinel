from typing import Callable, Dict, Iterable, List, Tuple

_REGISTRY: Dict[str, Callable[[], None]] = {}


def register(name: str):
    """Decorator to register a plugin run function by name."""

    def _wrap(fn: Callable[[], None]) -> Callable[[], None]:
        _REGISTRY[name] = fn
        return fn

    return _wrap


def get_registered() -> List[str]:
    return sorted(_REGISTRY.keys())


def run_plugin(name: str) -> Tuple[str, bool, str | None]:
    """Run a single plugin by name with isolation.

    Returns (name, success, error_message_or_None)
    """
    fn = _REGISTRY.get(name)
    if not fn:
        return name, False, "not registered"
    try:
        fn()
        return name, True, None
    except Exception as e:  # noqa: BLE001
        # Intentionally swallow plugin exceptions so others can continue
        return name, False, str(e)


def run_all(names: Iterable[str]) -> List[Tuple[str, bool, str | None]]:
    """Run multiple plugins independently; never let one stop another."""
    results: List[Tuple[str, bool, str | None]] = []
    for n in names:
        results.append(run_plugin(n))
    return results

