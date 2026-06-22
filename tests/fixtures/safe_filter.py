# Safe: values are validated before interpolation
import re

_SAFE_KEY = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _create_filter(filters):
    operands = []
    for key, value in filters.items():
        if not _SAFE_KEY.match(key):
            raise ValueError(f"Invalid key: {key}")
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            operands.append(f'(metadata["{key}"] == "{escaped}")')
        elif isinstance(value, (int, float, bool)):
            operands.append(f'(metadata["{key}"] == {value})')
        else:
            raise ValueError(f"Bad type: {type(value)}")
    return " and ".join(operands)
