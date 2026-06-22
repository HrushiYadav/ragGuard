# Vulnerable: dict values passed directly into MongoDB query
def build_filters(filters):
    filter_conditions = []
    for key, value in filters.items():
        filter_conditions.append({"payload." + key: value})
    return {"$and": filter_conditions}
