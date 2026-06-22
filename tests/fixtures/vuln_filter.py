# Vulnerable: f-string interpolation of user values into filter expressions
def _create_filter(filters):
    operands = []
    for key, value in filters.items():
        if isinstance(value, str):
            operands.append(f'(metadata["{key}"] == "{value}")')
        else:
            operands.append(f'(metadata["{key}"] == {value})')
    return " and ".join(operands)


def build_tag_query(key, value):
    return f"@{key}:{{{value}}}"
