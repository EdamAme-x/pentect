from __future__ import annotations

import inspect
from typing import Any


def validate_groups(validator: Any, groups: list[Any], batch_size: int) -> Any:
    """Call CredSweeper's ML validator across supported upstream signatures."""
    parameters = inspect.signature(validator.validate_groups).parameters
    if "progress_callback" in parameters:
        return validator.validate_groups(groups, batch_size, progress_callback=None)
    return validator.validate_groups(groups, batch_size)
