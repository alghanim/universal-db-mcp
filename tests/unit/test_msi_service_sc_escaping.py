"""Round-trip gates for the MSI service action's sc.exe argument escaping
and its credential-handling trust model.

packaging/msi/custom/service.ps1 embeds admin-supplied values (service
account, interpreter path) into a hand-built sc.exe command line that
sc.exe parses with CommandLineToArgvW rules. The escaping is subtle:

  * a run of n backslashes immediately followed by a double quote is an
    escape sequence and must be emitted as 2n+1 backslashes followed by \"
    (escaping only the quote leaves those backslashes to consume the
    escape instead of staying literal);
  * a trailing run of n backslashes sits immediately before the closing
    quote the caller appends, so it must be emitted as 2n: with an odd
    count the last backslash escapes the closing quote, the argument never
    terminates, and the following tokens are silently swallowed (the
    originally-shipped bug: a service password ending in '\' made the SCM
    store the wrong password with exit 0, and a trailing-'\' account
    absorbed the 'start= auto' token into obj=).

The MSI build host has no PowerShell runtime, so these tests extract the
actual ``-replace`` patterns from the shipped function, apply them with
.NET replacement semantics (backslash is NOT an escape character in .NET
replacement strings), and round-trip the result through a Python
implementation of the documented CommandLineToArgvW parsing rules.

Credential trust model (second defect fixed here): the service-account
password must never appear on any process command line (the OS captures
command lines into durable audit logs -- Event 4688 with
include-command-line / Sysmon EID 1 -- that no script output discipline
can suppress); it is written through the Service Control Manager API
(Win32_Service.Change -> ChangeServiceConfig) after sc.exe create.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
CUSTOM_DIR = PROJECT / "packaging" / "msi" / "custom"
SERVICE_PS1 = CUSTOM_DIR / "service.ps1"
UNINSTALL_PS1 = CUSTOM_DIR / "uninstall.ps1"


# --- source loading ------------------------------------------------------------


@pytest.fixture(scope="module")
def service_src() -> str:
    # ascii read doubles as an encoding guard: Windows PowerShell 5.1
    # treats a BOM-less non-ASCII file as ANSI, so the script must be pure
    # ASCII.
    return SERVICE_PS1.read_text(encoding="ascii")


@pytest.fixture(scope="module")
def uninstall_src() -> str:
    return UNINSTALL_PS1.read_text(encoding="ascii")


def code_lines(text: str) -> str:
    """Executable lines only (comment-only lines stripped): the trust
    assertions are about what the script does, so prose comments must not
    satisfy or defeat a gate."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# --- CommandLineToArgvW reference parser ----------------------------------------


def clapargvw_parse(cmdline: str) -> list[str]:
    """Split a raw Windows command line per the documented CommandLineToArgvW
    rules (see "About Command Line Parsing", learn.microsoft.com):

      * 2n backslashes followed by a quote -> n literal backslashes, and the
        quote toggles in-quote state;
      * 2n+1 backslashes followed by a quote -> n literal backslashes plus a
        literal double quote;
      * a quote outside a backslash run toggles in-quote state;
      * a space ends the argument only outside quotes.
    """
    argv: list[str] = []
    cur: list[str] = []
    in_quotes = False
    i = 0
    while i < len(cmdline):
        ch = cmdline[i]
        if ch == "\\":
            j = i
            while j < len(cmdline) and cmdline[j] == "\\":
                j += 1
            run = j - i
            if j < len(cmdline) and cmdline[j] == '"':
                cur.append("\\" * (run // 2))
                if run % 2 == 1:
                    cur.append('"')  # escaped quote: literal character
                else:
                    in_quotes = not in_quotes
                i = j + 1
                continue
            cur.append("\\" * run)  # not before a quote: all literal
            i = j
            continue
        if ch == '"':
            in_quotes = not in_quotes
            i += 1
            continue
        if ch == " " and not in_quotes:
            argv.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    argv.append("".join(cur))
    return argv


# --- the escaping function under test -------------------------------------------


@pytest.fixture(scope="module")
def escape_patterns(service_src: str) -> list[tuple[str, str]]:
    """The ``(pattern, replacement)`` pairs of ConvertTo-ScArgument, in
    order, extracted verbatim from the shipped script."""
    start = service_src.index("function ConvertTo-ScArgument")
    end = service_src.index("function Set-ServiceLogonCredential")
    body = service_src[start:end]
    pairs = re.findall(r"-replace\s+'([^']+)',\s*'([^']+)'", body)
    assert pairs, "ConvertTo-ScArgument lost its -replace escaping rules"
    return pairs


def apply_dotnet_replace(value: str, pairs: list[tuple[str, str]]) -> str:
    """Apply the extracted .NET regex replacements with .NET replacement
    semantics: ``$1``-style group references and otherwise literal text
    (backslash has no special meaning in a .NET replacement string)."""

    def replacement(ps_repl: str):
        parts = re.split(r"(\$\d)", ps_repl)

        def apply(match: re.Match[str]) -> str:
            out = []
            for part in parts:
                if len(part) == 2 and part.startswith("$") and part[1].isdigit():
                    out.append(match.group(int(part[1])) or "")
                else:
                    out.append(part)
            return "".join(out)

        return apply

    out = value
    for pattern, repl in pairs:
        out = re.sub(pattern, replacement(repl), out)
    return out


def escape(value: str, pairs: list[tuple[str, str]]) -> str:
    """The value as service.ps1 would embed it between the double quotes the
    caller appends."""
    return apply_dotnet_replace(value, pairs)


# --- round-trip property ---------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "udbmcp",
        "C:\\Program Files\\UniversalDB MCP\\venv\\Scripts\\python.exe",
        'a"b',  # bare embedded quote -> literal quote
        "he said \"hi\"",
        "pass\\",  # THE originally-shipped bug: trailing backslash
        "DOMAIN\\user\\",  # trailing-backslash service account
        "C:\\dir\\",
        "\\\\",  # run of backslashes
        'a\\"b',  # backslash run (n=1) directly before an embedded quote
        'x"\\\\"y',  # quote, backslash run, quote
        "ends with quote\"",
        "mix\"of\\things\"here\\",
    ],
)
def test_escaped_value_round_trips_through_commandline_to_argv_w(
    value: str, escape_patterns: list[tuple[str, str]]
) -> None:
    parsed = clapargvw_parse('"' + escape(value, escape_patterns) + '"')
    assert parsed == [value], (
        f"value {value!r} does not survive embedding in a quoted argument: "
        f"parsed back as {parsed!r}"
    )


def test_trailing_backslash_account_does_not_swallow_start_auto(
    escape_patterns: list[tuple[str, str]],
) -> None:
    """Regression gate for the shipped bug: with an account whose name ends
    in '\', the old quote-only escaping emitted an odd backslash run before
    the closing quote, so the quote became a literal character, the argument
    never terminated, and 'start= auto' was absorbed into the obj= value —
    the service silently registered without auto start. (sc.exe receives the
    quoted value as the argv token that follows the 'obj=' token.)"""
    account = "DOMAIN\\user\\"
    line = (
        "create udbmcp start= auto obj= \""
        + escape(account, escape_patterns)
        + "\""
    )
    argv = clapargvw_parse(line)
    assert argv == ["create", "udbmcp", "start=", "auto", "obj=", account]


def test_naive_quote_only_escaping_would_swallow_tokens(
    escape_patterns: list[tuple[str, str]],
) -> None:
    """Documents WHY the trailing-backslash rule is load-bearing: the naive
    '"' -> '\\"' escaping (the originally-shipped behavior) demonstrably
    swallows the 'start= auto' tokens for a trailing-backslash account, so
    simplifying the function back must fail this suite."""
    account = "DOMAIN\\user\\"
    naive = account.replace('"', '\\"')
    argv = clapargvw_parse('create udbmcp start= auto obj= "' + naive + '"')
    assert argv != ["create", "udbmcp", "start=", "auto", "obj=", account], (
        "naive quote-only escaping unexpectedly round-tripped; the trailing "
        "backslash rule in ConvertTo-ScArgument guards a real CommandLineToArgvW "
        "hazard and must not be simplified away"
    )


def test_binpath_embedding_round_trips(
    escape_patterns: list[tuple[str, str]],
) -> None:
    """The binPath value is itself quoted (interpreter path inside); it must
    come back as one token (the value token following 'binPath=')."""
    binpath = '"C:\\Program Files\\UniversalDB MCP\\venv\\Scripts\\python.exe" -m universal_db_mcp serve'
    line = 'create udbmcp binPath= "' + escape(binpath, escape_patterns) + '" start= auto'
    argv = clapargvw_parse(line)
    assert argv == ["create", "udbmcp", "binPath=", binpath, "start=", "auto"]


# --- credential trust model --------------------------------------------------------


def test_password_is_never_part_of_a_command_line(service_src: str) -> None:
    code = code_lines(service_src)
    # sc.exe's password flag must be gone entirely.
    assert "password= " not in code, (
        "service.ps1 still passes the service-account password as a sc.exe "
        "command-line token; command lines are captured into durable OS audit "
        "logs (Event 4688 include-command-line / Sysmon EID 1)"
    )
    # The create command line construction must not reference the password.
    for line in code.splitlines():
        if "createArgs" in line:
            assert "$ServicePassword" not in line, (
                "the sc.exe create command line is built from the service "
                "account password"
            )


def test_password_is_written_via_scm_api(service_src: str) -> None:
    code = code_lines(service_src)
    assert "Set-ServiceLogonCredential" in code
    # The call site: only when a password was supplied, and it goes to the
    # API wrapper, not to Invoke-Tool / sc.exe.
    branch = re.search(r"if \(\$ServicePassword\)\s*\{([^}]*)\}", code)
    assert branch, "the password branch (if ($ServicePassword)) is missing"
    assert "Set-ServiceLogonCredential" in branch.group(1)
    assert "Invoke-Tool" not in branch.group(1), (
        "the password must not be handed to an external process command line"
    )


def test_credential_api_fails_closed(service_src: str) -> None:
    """Any SCM API failure must throw into the caller's catch block, which
    removes the half-configured service before the action exits nonzero."""
    start = service_src.index("function Set-ServiceLogonCredential")
    end = service_src.index("function Test-ServiceExists")
    body = code_lines(service_src[start:end])
    assert re.search(r"throw\b", body), (
        "Set-ServiceLogonCredential must fail closed on every error "
        "(missing service, nonzero ChangeServiceConfig return value)"
    )
    assert "ReturnValue -ne 0" in body, (
        "the Win32_Service.Change return value must be checked, not ignored"
    )
    assert "Win32_Service" in body and "Change" in body, (
        "the credential must be written through the Service Control Manager "
        "API (Win32_Service.Change -> ChangeServiceConfig)"
    )


def test_password_is_never_logged(service_src: str) -> None:
    for line in service_src.splitlines():
        if "$ServicePassword" in line:
            assert "Write-Output" not in line and "Write-Host" not in line and "Write-" not in line, (
                f"the service password must never be echoed: {line!r}"
            )


# --- documented environment-variable fallbacks stay reachable ----------------------


@pytest.mark.parametrize(
    ("script", "fixture_name", "member", "envvar"),
    [
        ("service.ps1", "service_src", "ServiceName", "UDBMCP_SERVICE_NAME"),
        ("service.ps1", "service_src", "ServiceAccount", "UDBMCP_SERVICE_ACCOUNT"),
        ("uninstall.ps1", "uninstall_src", "ServiceName", "UDBMCP_SERVICE_NAME"),
    ],
)
def test_documented_env_fallbacks_are_kept(
    request: pytest.FixtureRequest, script: str, fixture_name: str, member: str, envvar: str
) -> None:
    """The scripts' headers document environment-variable fallbacks for
    manual runs (scripts/test_package_msi.ps1). They are only reachable when
    a caller passes an empty parameter value, so both the fallback line and
    the direct msiexec wiring default must exist (the fallback resolves, the
    default is applied last)."""
    src = request.getfixturevalue(fixture_name)
    assert f"${member} = $env:{envvar}" in src, (
        f"{script}: documented {envvar} fallback is missing"
    )
    assert f"if (-not ${member})" in src, (
        f"{script}: the fallback/default resolution for ${member} is missing"
    )


def test_service_name_is_validated_fail_closed(service_src: str) -> None:
    """The service name lands unquoted inside sc.exe command lines and inside
    a WMI filter string (Name='<name>'); quotes and whitespace must be
    rejected before any of that is built."""
    code = code_lines(service_src)
    guard_line = next(
        (line for line in code.splitlines() if "$ServiceName -match" in line), None
    )
    assert guard_line, "service.ps1 does not validate the service name"
    assert "\\s" in guard_line, "whitespace in the service name must be rejected"
    assert '"' in guard_line, "double quotes in the service name must be rejected"
    assert "'" in guard_line, "single quotes in the service name must be rejected"
    # The guard must run before the create command line is built.
    assert code.index("$ServiceName -match") < code.index("'create '"), (
        "the service name guard must run before the sc.exe create line is built"
    )
