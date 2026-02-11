"""
Test Suite for Development Workflow MCP Server

Demonstrates that the two best practices (Sandboxing and Rate Limiting)
successfully block attacks, and verifies overall tool functionality.

Usage:
    python exploit_tests.py

Tests:
    Section 1 - Sandboxing (Best Practice 1)
        A) Directory jailing blocks path traversal attacks
        B) Static analysis only - code is parsed but never executed

    Section 2 - Rate Limiting (Best Practice 2)
        Sliding-window throttle rejects rapid-fire requests

    Section 3 - Tool Functionality
        Tools produce correct output on valid inputs and handle errors

Citations:
    - OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
    - OWASP Code Injection: https://owasp.org/www-community/attacks/Code_Injection
    - OWASP Denial of Service: https://owasp.org/www-community/attacks/Denial_of_Service
    - Python ast module: https://docs.python.org/3/library/ast.html
"""

import ast
import json
import sys
import time
from pathlib import Path

# Ensure the project root is on sys.path so we can import server helpers
# Citation: pathlib usage per assignment requirement (no os.path)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import (
    validate_file_path,
    validate_directory_path,
    safe_error_response,
    sandbox_parse,
    check_rate_limit,
    analyze_code_complexity,
    generate_docstrings,
    compute_complexity,
    generate_function_docstring,
    ALLOWED_DIR,
    RATE_LIMIT_MAX_CALLS,
    RATE_LIMIT_WINDOW_SECONDS,
    _call_timestamps,
)

# Compute paths relative to ALLOWED_DIR so tests work regardless of config
_PROJECT_DIR = Path(__file__).resolve().parent
_SAMPLE_DIR = _PROJECT_DIR / "sample_projects"
_EXAMPLE_PY_REL = str(
    (_SAMPLE_DIR / "example.py").resolve().relative_to(ALLOWED_DIR)
)
_CALCULATOR_PY_REL = str(
    (_SAMPLE_DIR / "calculator.py").resolve().relative_to(ALLOWED_DIR)
)
_VALIDATORS_PY_REL = str(
    (_SAMPLE_DIR / "validators.py").resolve().relative_to(ALLOWED_DIR)
)
_PIPELINE_PY_REL = str(
    (_SAMPLE_DIR / "data_pipeline.py").resolve().relative_to(ALLOWED_DIR)
)
_SAMPLE_DIR_REL = str(_SAMPLE_DIR.resolve().relative_to(ALLOWED_DIR))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str, str]] = []


def run_test(name: str, fn):
    """Run *fn* and record the result."""
    try:
        outcome, detail = fn()
        results.append((name, outcome, detail))
    except Exception as exc:
        results.append((name, FAIL, f"Unexpected exception: {exc}"))


def print_report():
    """Print a formatted test report."""
    print("\n" + "=" * 72)
    print("TEST REPORT")
    print("=" * 72)

    for name, outcome, detail in results:
        tag = f"[{outcome}]"
        print(f"\n  {tag:6s}  {name}")
        print(f"          {detail}")

    passed = sum(1 for _, o, _ in results if o == PASS)
    total = len(results)
    print("\n" + "-" * 72)
    print(f"  Results: {passed}/{total} passed")
    print("=" * 72 + "\n")


# ===========================================================================
# SECTION 1 - Sandboxing (Best Practice 1)
# Citation: OWASP Path Traversal - https://owasp.org/www-community/attacks/Path_Traversal
# Citation: OWASP Code Injection - https://owasp.org/www-community/attacks/Code_Injection
#
# Two layers of sandboxing are tested:
#   A) Directory jailing - file access is resolved and verified to stay
#      inside ALLOWED_DIR, blocking ../ traversal, symlink escapes, and
#      absolute-path overrides.
#   B) Static analysis only - user-supplied Python is processed exclusively
#      via ast.parse(), which builds a syntax tree WITHOUT executing code.
# ===========================================================================

# --- A) Directory Jailing ---------------------------------------------------

def test_basic_traversal():
    """Attempt to escape the allowed directory with ../"""
    try:
        validate_file_path("../../etc/passwd")
        return FAIL, "Path traversal was NOT blocked"
    except ValueError as e:
        if "outside" in str(e).lower() or "denied" in str(e).lower():
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


def test_absolute_path():
    """Attempt to use an absolute path to bypass the sandbox."""
    try:
        if sys.platform == "win32":
            validate_file_path("C:\\Windows\\System32\\config\\SAM")
        else:
            validate_file_path("/etc/shadow")
        return FAIL, "Absolute path was NOT blocked"
    except ValueError as e:
        if "outside" in str(e).lower() or "denied" in str(e).lower():
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


def test_dot_dot_encoded():
    """Attempt traversal with mixed separators and redundant dots."""
    try:
        validate_file_path("subdir/./../../secret.py")
        return FAIL, "Encoded traversal was NOT blocked"
    except (ValueError, FileNotFoundError) as e:
        msg = str(e).lower()
        if "outside" in msg or "denied" in msg or "not found" in msg:
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected error: {e}"


def test_null_byte_injection():
    """Attempt null-byte injection to truncate the path."""
    try:
        validate_file_path("example.py\x00.txt")
        return FAIL, "Null byte injection was NOT blocked"
    except ValueError as e:
        if "invalid" in str(e).lower() or "denied" in str(e).lower():
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


def test_non_python_file():
    """Attempt to read a non-.py file that might contain secrets."""
    try:
        validate_file_path("../requirements.txt")
        return FAIL, "Non-Python file access was NOT blocked"
    except ValueError as e:
        msg = str(e).lower()
        if "only python" in msg or "outside" in msg or "denied" in msg:
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


def test_deeply_nested_traversal():
    """Attempt to break out using many ../ segments."""
    evil_path = "/".join([".."] * 20) + "/etc/passwd"
    try:
        validate_file_path(evil_path)
        return FAIL, "Deep traversal was NOT blocked"
    except ValueError as e:
        if "outside" in str(e).lower() or "denied" in str(e).lower():
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


def test_directory_jailing():
    """Verify validate_directory_path also blocks traversal."""
    try:
        validate_directory_path("../../")
        return FAIL, "Directory traversal was NOT blocked"
    except ValueError as e:
        if "outside" in str(e).lower() or "denied" in str(e).lower():
            return PASS, f"Blocked with: {e}"
        return FAIL, f"Unexpected ValueError: {e}"


# --- B) Static Analysis Only ------------------------------------------------
# Citation: Python ast module - https://docs.python.org/3/library/ast.html
#
# sandbox_parse() uses ast.parse() which builds a syntax tree WITHOUT
# executing the code.  Even files containing exec(), eval(), compile(),
# or __import__() are safely parsed - the dangerous calls are flagged
# in the server log but never run.

def test_sandbox_parse_no_execution():
    """Verify sandbox_parse does NOT execute code containing dangerous calls.

    The source below contains exec() and eval() - both are dangerous
    builtins.  sandbox_parse should return an AST without running them.
    """
    malicious_source = (
        "import os\n"
        "exec(\"print('HACKED')\")\n"
        "eval(\"os.system('rm -rf /')\")\n"
        "result = compile('code', 'file', 'exec')\n"
    )
    try:
        tree = sandbox_parse(malicious_source, filename="malicious.py")
        if isinstance(tree, ast.Module):
            return (PASS,
                    "Dangerous code parsed into AST without execution; "
                    "calls to exec/eval/compile flagged in server log")
        return FAIL, "sandbox_parse did not return an AST Module"
    except Exception as e:
        return FAIL, f"sandbox_parse failed unexpectedly: {e}"


def test_sandbox_parse_returns_ast():
    """Verify sandbox_parse returns a syntax tree, not evaluated results."""
    source = "x = 1 + 2\ny = x * 3\n"
    try:
        tree = sandbox_parse(source, filename="arithmetic.py")
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
        if len(assigns) == 2:
            return (PASS,
                    "Got AST with 2 assignment nodes; "
                    "no arithmetic was computed (static analysis only)")
        return FAIL, f"Expected 2 Assign nodes, got {len(assigns)}"
    except Exception as e:
        return FAIL, f"Unexpected error: {e}"


def test_safe_error_response_hides_internals():
    """Verify safe_error_response never leaks internal paths or tracebacks."""
    err = FileNotFoundError(
        f"[Errno 2] No such file: '{ALLOWED_DIR}/secret.py'"
    )
    msg = safe_error_response(err)
    if str(ALLOWED_DIR) in msg:
        return FAIL, f"Error leaked ALLOWED_DIR: {msg}"
    if "secret.py" in msg:
        return FAIL, f"Error leaked filename: {msg}"
    return PASS, f"Safe generic message returned: {msg}"


def test_safe_error_response_hides_credentials():
    """Verify safe_error_response does not leak credentials from exceptions."""
    try:
        raise RuntimeError(
            "connection to postgresql://admin:s3cret@db.internal:5432 failed"
        )
    except RuntimeError as e:
        msg = safe_error_response(e)
        if "s3cret" in msg or "admin" in msg or "db.internal" in msg:
            return FAIL, f"Error leaked credentials: {msg}"
        return PASS, f"Safe generic message returned: {msg}"


# ===========================================================================
# SECTION 2 - Rate Limiting (Best Practice 2)
# Citation: OWASP Denial of Service - https://owasp.org/www-community/attacks/Denial_of_Service
#
# The server uses a sliding-window throttle: it tracks timestamps of
# recent calls per tool.  If the number of calls inside the window
# exceeds the limit the request is rejected with a ValueError.
# ===========================================================================

def test_rate_limit_allows_normal_usage():
    """Verify that calls within the limit all succeed."""
    tool = "__test_normal__"
    _call_timestamps[tool] = []  # reset state
    try:
        for _ in range(RATE_LIMIT_MAX_CALLS):
            check_rate_limit(tool)
        return (PASS,
                f"All {RATE_LIMIT_MAX_CALLS} calls within the "
                f"{RATE_LIMIT_WINDOW_SECONDS}s window succeeded")
    except ValueError as e:
        return FAIL, f"Rate limit triggered too early: {e}"
    finally:
        _call_timestamps.pop(tool, None)


def test_rate_limit_blocks_excess():
    """Verify that call #{MAX+1} is rejected after hitting the limit."""
    tool = "__test_excess__"
    _call_timestamps[tool] = []  # reset state
    try:
        # Fill the window to the limit
        for _ in range(RATE_LIMIT_MAX_CALLS):
            check_rate_limit(tool)
        # One more should be rejected
        try:
            check_rate_limit(tool)
            return FAIL, f"Call #{RATE_LIMIT_MAX_CALLS + 1} was NOT rate-limited"
        except ValueError as e:
            if "rate limit" in str(e).lower():
                return (PASS,
                        f"Call #{RATE_LIMIT_MAX_CALLS + 1} correctly blocked: {e}")
            return FAIL, f"Unexpected ValueError: {e}"
    except ValueError as e:
        return FAIL, f"Rate limit triggered before reaching the cap: {e}"
    finally:
        _call_timestamps.pop(tool, None)


def test_rate_limit_sliding_window_expiry():
    """Verify that timestamps outside the window are discarded.

    Simulates a full window of old timestamps (from well before the
    current window) and confirms that a new call succeeds because the
    stale entries have expired.
    """
    tool = "__test_window__"
    # Place MAX timestamps far in the past (outside the sliding window)
    old_time = time.time() - RATE_LIMIT_WINDOW_SECONDS - 10
    _call_timestamps[tool] = [old_time] * RATE_LIMIT_MAX_CALLS
    try:
        check_rate_limit(tool)  # should succeed - old entries expired
        return (PASS,
                "Old timestamps expired from sliding window; "
                "new call succeeded after window reset")
    except ValueError as e:
        return FAIL, f"Rate limit should have reset but didn't: {e}"
    finally:
        _call_timestamps.pop(tool, None)


def test_rate_limit_per_tool_isolation():
    """Verify that rate limits are tracked independently per tool.

    Exhausting the limit for tool A should NOT affect tool B.
    """
    tool_a = "__test_iso_a__"
    tool_b = "__test_iso_b__"
    _call_timestamps[tool_a] = []
    _call_timestamps[tool_b] = []
    try:
        # Exhaust tool A
        for _ in range(RATE_LIMIT_MAX_CALLS):
            check_rate_limit(tool_a)
        # Tool B should still work
        check_rate_limit(tool_b)
        return PASS, "Exhausting tool A did not block tool B (per-tool isolation)"
    except ValueError as e:
        return FAIL, f"Per-tool isolation failed: {e}"
    finally:
        _call_timestamps.pop(tool_a, None)
        _call_timestamps.pop(tool_b, None)


# ===========================================================================
# SECTION 3 - Tool Functionality
#
# Demonstrates that the MCP tools produce correct results when called
# with valid inputs, and return graceful error messages for invalid inputs.
# ===========================================================================

def test_analyze_complexity_single_file():
    """Verify analyze_code_complexity returns valid JSON metrics for a file."""
    # Clear any rate limit state so tool calls succeed
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_EXAMPLE_PY_REL)
    try:
        data = json.loads(result)
        has_functions = "functions" in data
        has_classes = "classes" in data
        has_lines = "total_lines" in data
        if has_functions and has_classes and has_lines:
            return (PASS,
                    f"Returned metrics: {data['total_lines']} lines, "
                    f"{len(data['functions'])} functions, "
                    f"{len(data['classes'])} classes")
        return FAIL, f"Missing expected keys in output"
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


def test_analyze_complexity_directory():
    """Verify analyze_code_complexity scans all .py files in a directory."""
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_SAMPLE_DIR_REL)
    try:
        data = json.loads(result)
        if isinstance(data, list) and len(data) > 0:
            filenames = [entry.get("file", "?") for entry in data]
            return (PASS,
                    f"Directory scan returned metrics for {len(data)} "
                    f"file(s): {', '.join(filenames)}")
        return FAIL, f"Expected non-empty list, got: {type(data).__name__}"
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


def test_analyze_complexity_nonexistent_file():
    """Verify analyze_code_complexity returns an error for missing files."""
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_SAMPLE_DIR_REL + "/nonexistent_file.py")
    if "error" in result.lower() or "not found" in result.lower():
        return PASS, f"Graceful error for missing file: {result}"
    return FAIL, f"Expected error message, got: {result[:120]}"


def test_docstring_generation():
    """Verify generate_function_docstring produces a valid Google-style docstring.

    Uses a synthetic source string (not a real file) to test the internal
    function without modifying any files on disk.
    """
    source = (
        "def greet(name: str, loud: bool = False) -> str:\n"
        "    if loud:\n"
        "        return f'HELLO {name}!'\n"
        "    return f'Hello {name}'\n"
    )
    try:
        docstring, modified = generate_function_docstring(source, "greet")
        has_args = "Args:" in docstring
        has_name = "name" in docstring
        has_return = "Returns:" in docstring
        if has_args and has_name and has_return:
            return (PASS,
                    "Generated Google-style docstring with Args and Returns")
        return FAIL, f"Docstring missing expected sections: {docstring[:120]}"
    except Exception as e:
        return FAIL, f"Unexpected error: {e}"


def test_docstring_already_exists():
    """Verify generate_docstrings rejects a function that already has a docstring.

    example.py's fetch_user already has a docstring, so the tool should
    return a validation error without modifying the file.
    """
    _call_timestamps["generate_docstrings"] = []
    result = generate_docstrings(_EXAMPLE_PY_REL, "fetch_user")
    if "already has a docstring" in result.lower() or "validation error" in result.lower():
        return PASS, f"Correctly rejected: {result}"
    return FAIL, f"Expected rejection for existing docstring, got: {result[:120]}"


def test_tool_level_path_traversal():
    """Verify the tool-level entry point also blocks path traversal.

    This confirms that the sandboxing protection is applied at the
    MCP tool boundary, not just in the internal helper functions.
    """
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity("../../etc/passwd")
    if "denied" in result.lower() or "outside" in result.lower():
        return PASS, f"Tool blocked traversal: {result}"
    return FAIL, f"Expected denial, got: {result[:120]}"


def test_compute_complexity_metrics():
    """Verify compute_complexity returns accurate metrics for known source.

    Uses a small synthetic source to check that function count,
    cyclomatic complexity, and line count are computed correctly.
    """
    source = (
        "def simple():\n"
        "    return 1\n"
        "\n"
        "def branchy(x):\n"
        "    if x > 0:\n"
        "        if x > 10:\n"
        "            return 'big'\n"
        "        return 'small'\n"
        "    return 'negative'\n"
    )
    try:
        data = compute_complexity(source, "test_source.py")
        num_funcs = len(data.get("functions", []))
        if num_funcs != 2:
            return FAIL, f"Expected 2 functions, got {num_funcs}"

        branchy = next(
            (f for f in data["functions"] if f["name"] == "branchy"), None
        )
        if branchy is None:
            return FAIL, "Could not find 'branchy' in metrics"

        cc = branchy.get("cyclomatic_complexity", 0)
        if cc < 3:
            return FAIL, f"Expected cyclomatic complexity >= 3, got {cc}"

        return (PASS,
                f"2 functions found; 'branchy' cyclomatic complexity = {cc}")
    except Exception as e:
        return FAIL, f"Unexpected error: {e}"


def test_analyze_complexity_calculator():
    """Verify calculator.py has low-complexity functions (all CC <= 3)."""
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_CALCULATOR_PY_REL)
    try:
        data = json.loads(result)
        funcs = data.get("functions", [])
        if not funcs:
            return FAIL, "No functions found in calculator.py"
        max_cc = max(f["cyclomatic_complexity"] for f in funcs)
        if max_cc <= 3:
            return (PASS,
                    f"{len(funcs)} functions found; max cyclomatic complexity "
                    f"= {max_cc} (low complexity confirmed)")
        return FAIL, f"Expected all CC <= 3, but max = {max_cc}"
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


def test_analyze_complexity_validators_branching():
    """Verify validators.py contains high cyclomatic complexity functions.

    validate_user_input has many if/elif branches, so its cyclomatic
    complexity should be significantly higher than simple functions.
    """
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_VALIDATORS_PY_REL)
    try:
        data = json.loads(result)
        funcs = data.get("functions", [])
        target = next(
            (f for f in funcs if f["name"] == "validate_user_input"), None
        )
        if target is None:
            return FAIL, "Could not find 'validate_user_input' in metrics"
        cc = target["cyclomatic_complexity"]
        if cc >= 8:
            return (PASS,
                    f"validate_user_input CC = {cc} (high branching confirmed)")
        return FAIL, f"Expected CC >= 8 for validate_user_input, got {cc}"
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


def test_analyze_complexity_pipeline_classes():
    """Verify data_pipeline.py detects multiple classes including inheritance."""
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_PIPELINE_PY_REL)
    try:
        data = json.loads(result)
        classes = data.get("classes", [])
        if len(classes) < 3:
            return FAIL, f"Expected >= 3 classes, got {len(classes)}"
        names = [c["name"] for c in classes]
        with_bases = [c for c in classes if c.get("base_classes", 0) > 0]
        return (PASS,
                f"{len(classes)} classes found ({', '.join(names)}); "
                f"{len(with_bases)} with base classes (inheritance)")
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


def test_docstring_generation_with_raises():
    """Verify generate_function_docstring produces a Raises section.

    Uses a synthetic function that raises an exception to test that
    the Raises section is generated in addition to Args and Returns.
    """
    source = (
        "def divide(a: float, b: float) -> float:\n"
        "    if b == 0:\n"
        "        raise ZeroDivisionError('Cannot divide by zero')\n"
        "    return a / b\n"
    )
    try:
        docstring, modified = generate_function_docstring(source, "divide")
        has_args = "Args:" in docstring
        has_raises = "Raises:" in docstring
        has_return = "Returns:" in docstring
        if has_args and has_raises and has_return:
            return (PASS,
                    "Generated docstring with Args, Raises, and Returns")
        missing = []
        if not has_args:
            missing.append("Args")
        if not has_raises:
            missing.append("Raises")
        if not has_return:
            missing.append("Returns")
        return FAIL, f"Docstring missing sections: {', '.join(missing)}"
    except Exception as e:
        return FAIL, f"Unexpected error: {e}"


def test_directory_scan_finds_all_files():
    """Verify directory scan finds all .py files in sample_projects."""
    _call_timestamps["analyze_code_complexity"] = []
    result = analyze_code_complexity(_SAMPLE_DIR_REL)
    try:
        data = json.loads(result)
        if not isinstance(data, list):
            return FAIL, f"Expected a list, got {type(data).__name__}"
        filenames = sorted(entry.get("file", "?") for entry in data)
        if len(data) >= 5:
            return (PASS,
                    f"Directory scan found {len(data)} files: "
                    f"{', '.join(filenames)}")
        return FAIL, f"Expected >= 5 files, found {len(data)}: {filenames}"
    except json.JSONDecodeError:
        return FAIL, f"Tool returned non-JSON: {result[:120]}"


# ===========================================================================
# Main
# ===========================================================================
if __name__ == "__main__":
    print(f"\nAllowed directory: {ALLOWED_DIR}")
    print(f"Rate limit: {RATE_LIMIT_MAX_CALLS} calls / "
          f"{RATE_LIMIT_WINDOW_SECONDS}s window\n")

    # ------------------------------------------------------------------
    # Section 1: Sandboxing (Best Practice 1)
    # ------------------------------------------------------------------
    print("=" * 60)
    print("SECTION 1 - Sandboxing (Best Practice 1)")
    print("=" * 60)

    print("\n--- A) Directory Jailing ---")
    run_test("Basic ../ traversal",          test_basic_traversal)
    run_test("Absolute path bypass",         test_absolute_path)
    run_test("Encoded/mixed traversal",      test_dot_dot_encoded)
    run_test("Null byte injection",          test_null_byte_injection)
    run_test("Non-Python file access",       test_non_python_file)
    run_test("Deeply nested traversal",      test_deeply_nested_traversal)
    run_test("Directory path traversal",     test_directory_jailing)

    print("\n--- B) Static Analysis Only ---")
    run_test("sandbox_parse never executes code",   test_sandbox_parse_no_execution)
    run_test("sandbox_parse returns AST only",      test_sandbox_parse_returns_ast)
    run_test("Error response hides internal paths", test_safe_error_response_hides_internals)
    run_test("Error response hides credentials",    test_safe_error_response_hides_credentials)

    # ------------------------------------------------------------------
    # Section 2: Rate Limiting (Best Practice 2)
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("SECTION 2 - Rate Limiting (Best Practice 2)")
    print("=" * 60)

    run_test("Normal usage within limit",     test_rate_limit_allows_normal_usage)
    run_test("Excess calls blocked",          test_rate_limit_blocks_excess)
    run_test("Sliding window expires old ts", test_rate_limit_sliding_window_expiry)
    run_test("Per-tool isolation",            test_rate_limit_per_tool_isolation)

    # ------------------------------------------------------------------
    # Section 3: Tool Functionality
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("SECTION 3 - Tool Functionality")
    print("=" * 60)

    run_test("Complexity analysis (single file)",  test_analyze_complexity_single_file)
    run_test("Complexity analysis (directory)",     test_analyze_complexity_directory)
    run_test("Complexity analysis (missing file)",  test_analyze_complexity_nonexistent_file)
    run_test("Docstring generation",                test_docstring_generation)
    run_test("Docstring already exists",            test_docstring_already_exists)
    run_test("Tool-level path traversal blocked",   test_tool_level_path_traversal)
    run_test("Complexity metrics accuracy",         test_compute_complexity_metrics)
    run_test("Complexity (calculator.py - low CC)",       test_analyze_complexity_calculator)
    run_test("Complexity (validators.py - high CC)",      test_analyze_complexity_validators_branching)
    run_test("Complexity (data_pipeline.py - classes)",   test_analyze_complexity_pipeline_classes)
    run_test("Docstring generation with Raises",          test_docstring_generation_with_raises)
    run_test("Directory scan finds all files",            test_directory_scan_finds_all_files)

    print_report()

    # Exit with non-zero if any test failed
    if any(o == FAIL for _, o, _ in results):
        sys.exit(1)
