# References

Primary documentation starting points (checked 2026-09-08 when the
specification was prepared). Obtain approved copies during staging; never
fetch them inside the isolated environment. Match documentation to the
pinned versions actually shipped.

- [R1] PyPA pip, Repeatable installs: https://pip.pypa.io/en/stable/topics/repeatable-installs/
- [R2] PyPA pip, Secure installs: https://pip.pypa.io/en/stable/topics/secure-installs/
- [R3] IBM Python Db2 driver installation (wheel-bundled clidriver behavior): https://github.com/ibmdb/python-ibmdb/blob/master/INSTALL.md
- [R4] python-oracledb installation, Thin/Thick modes: https://python-oracledb.readthedocs.io/en/latest/user_guide/installation.html
- [R5] Microsoft ODBC driver offline packages: https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server
- [R6] Docker image save/load: https://docs.docker.com/reference/cli/docker/image/save/ , https://docs.docker.com/reference/cli/docker/image/load/
- [R7] Docker Compose service pull_policy: https://docs.docker.com/reference/compose-file/services/
- [R8] MCP transports (match the pinned SDK revision): https://modelcontextprotocol.io/specification/2026-07-28/basic/transports and https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- [R9] Claude Code MCP configuration: https://code.claude.com/docs/en/mcp
- [R10] Claude Code gateway protocol: https://code.claude.com/docs/en/llm-gateway-protocol
- [R11] Claude Code gateway setup / nonessential traffic: https://code.claude.com/docs/en/llm-gateway-connect

Pinned package versions used by this build (`requirements/runtime.in`; full
closure in the bundle's runtime.lock): mcp 2.2.0, PyYAML 6.0.3, sqlglot
30.18.0, uvicorn 0.53.0, h11 0.16.0, psycopg[binary] 3.3.5, PyMySQL 1.2.0,
clickhouse-connect 1.8.0, oracledb 4.0.2, pyodbc 5.3.0, ibm-db 3.2.9
(wheel), PyNaCl 1.6.2, cryptography 50.0.1; dev only: pytest 9.1.1, ruff
0.16.6 (`requirements/development.in`; CI installs 0.16.7 from `uv.lock`),
mypy 2.3.1.
