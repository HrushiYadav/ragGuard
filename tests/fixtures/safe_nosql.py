# Safe: has validation that rejects dicts
def _validate_filter_value(key, value):
    if isinstance(value, dict):
        raise ValueError(f"Filter value for {key!r} must be a scalar")


def build_filters(filters):
    for key, value in filters.items():
        _validate_filter_value(key, value)
    filter_conditions = []
    for key, value in filters.items():
        filter_conditions.append({"payload." + key: value})
    return {"$and": filter_conditions}
