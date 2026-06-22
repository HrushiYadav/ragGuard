# Vulnerable: f-string SQL construction
def insert_data(table, values):
    sql = f"INSERT INTO {table} (id, data) VALUES {values}"
    return sql


def delete_record(table, record_id):
    cur.execute(f"DELETE FROM {table} WHERE id = {record_id}")
