#!/usr/bin/env python3
"""Create the synthetic SQLite demo fixture used by tests and the demo.

The data is entirely synthetic. The demo database is separate from the
application's own audit/metadata-cache databases (spec §5)."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE customers (
    customer_id INTEGER PRIMARY KEY,
    full_name   TEXT NOT NULL,
    email       TEXT NOT NULL,
    country     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE accounts (
    account_id   INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(customer_id),
    account_type TEXT NOT NULL,
    currency     TEXT NOT NULL,
    opened_at    TEXT NOT NULL
);
CREATE TABLE transactions (
    txn_id      INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(account_id),
    amount_cents INTEGER NOT NULL,
    txn_type    TEXT NOT NULL,
    txn_at      TEXT NOT NULL
);
CREATE VIEW v_recent_transactions AS
    SELECT t.txn_id, a.account_id, c.customer_id, t.txn_type, t.txn_at
    FROM transactions t
    JOIN accounts a ON a.account_id = t.account_id
    JOIN customers c ON c.customer_id = a.customer_id
    WHERE t.txn_at >= '2026-01-01';
"""

NAMES = [
    "Amina Haddad", "Chen Wei", "Fatima Al-Sayed", "Diego Ramos",
    "Yuki Tanaka", "Priya Nair", "Lars Jensen", "Noor Abdallah",
    "Marco Rossi", "Grace Okafor",
]
COUNTRIES = ["QA", "CN", "EG", "MX", "JP", "IN", "DK", "JO", "IT", "NG"]
TYPES = ["checking", "savings", "savings", "checking", "investment"]
TXN_TYPES = ["debit", "credit", "transfer_out", "transfer_in"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=str(Path(__file__).parent / "finlink_demo.db"))
    args = parser.parse_args()
    path = Path(args.path)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for i, name in enumerate(NAMES):
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?)",
            (i + 1, name, f"user{i}@example.invalid", COUNTRIES[i], "2025-06-01"),
        )
        for j in range(2):
            acc = i * 2 + j + 1
            conn.execute(
                "INSERT INTO accounts VALUES (?,?,?,?,?)",
                (acc, i + 1, TYPES[(i + j) % 5], "EUR" if j == 0 else "USD", "2025-07-01"),
            )
            for k in range(20):
                conn.execute(
                    "INSERT INTO transactions VALUES (?,?,?,?,?)",
                    (acc * 100 + k, acc, (k * 37 + i * 13) % 500_00,
                     TXN_TYPES[k % 4], f"2026-0{(k % 6) + 1}-15"),
                )
    conn.commit()
    conn.close()
    config = Path(__file__).parent / "config.yaml"
    config.write_text(
        (Path(__file__).parent / "config.template.yaml").read_text()
        .replace("PLACEHOLDER_DB", str(path))
        .replace("PLACEHOLDER_DIR", str(path.parent)),
        encoding="utf-8",
    )
    print(f"created synthetic demo fixture: {path}")
    print(f"wrote demo config: {config}")


if __name__ == "__main__":
    main()
