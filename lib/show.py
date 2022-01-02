import sqlite3
from tabulate import tabulate

def show_table(table="banned", db="sqlite.db"):
    """Small function to display table output

    Parameter
    ---------
    table: str
      Name of the table, either "banned" or "ssh_denied"
    db: str
      Location of the db, defaults to "sqlite.db"

    Return
    ------
    None
    """
    if table not in ["banned", "ssh_denied"]:
        raise Exception(f"Table {table} does not exist")
    
    # Connect to database and get the cursor
    conn = sqlite3.connect(db)
    cursor = conn.execute(f"SELECT * from {table}")

    # Print!
    headers = [header[0] for header in cursor.description]
    print(tabulate(cursor, headers=headers))


if __name__ == "__main__":
    show_table()
