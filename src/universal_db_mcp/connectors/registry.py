"""Connector registry with lazy loading.

Importing this module never imports a database driver. A driver is imported
only when its connection type is instantiated, so an absent Oracle wheel
cannot break SQLite or PostgreSQL. Registry maps config ``type`` -> module
path and constructor.
"""

from __future__ import annotations

from universal_db_mcp.config import ResolvedConnection
from universal_db_mcp.connectors.base import DatabaseConnector
from universal_db_mcp.security.policy import EffectivePolicy

_LAZY: dict[str, tuple[str, str]] = {
    "sqlite": ("universal_db_mcp.connectors.sqlite", "SQLiteConnector"),
    "postgres": ("universal_db_mcp.connectors.postgres", "PostgresConnector"),
    "mysql": ("universal_db_mcp.connectors.mysql", "MySQLConnector"),
    "clickhouse": ("universal_db_mcp.connectors.clickhouse", "ClickHouseConnector"),
    "oracle": ("universal_db_mcp.connectors.oracle", "OracleConnector"),
    "mssql": ("universal_db_mcp.connectors.mssql", "MssqlConnector"),
    "db2": ("universal_db_mcp.connectors.db2", "Db2Connector"),
}

_cache: dict[str, type[DatabaseConnector]] = {}


def connector_class(engine_type: str) -> type[DatabaseConnector]:
    if engine_type in _cache:
        return _cache[engine_type]
    if engine_type not in _LAZY:
        raise KeyError(f"unknown connection type '{engine_type}'")
    import importlib

    module_name, class_name = _LAZY[engine_type]
    module = importlib.import_module(module_name)
    cls: type[DatabaseConnector] = getattr(module, class_name)
    _cache[engine_type] = cls
    return cls


def build_connector(connection: ResolvedConnection, policy: EffectivePolicy) -> DatabaseConnector:
    cls = connector_class(connection.config.type)
    return cls(connection, policy)
