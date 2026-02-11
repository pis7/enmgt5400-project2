"""
Development Workflow MCP Server

An MCP server providing code analysis and documentation generation tools
for Python development workflows.

Tools:
    - analyze_code_complexity: Parse Python files/directories and return complexity metrics
    - generate_docstrings: Generate Google-style docstrings for functions
    - generate_uml_diagram: Generate a UML class diagram PNG from a file/directory and deps

Prompt:
    - code-review-assistant: Comprehensive code review template

Best Practices Implemented:
    1. Sandboxing - Directory jailing + static analysis only (no code execution)
    2. Rate Limiting - Sliding-window per-tool call throttle

Citations:
    - MCP Python SDK docs: https://modelcontextprotocol.io/docs
    - FastMCP pattern: https://github.com/modelcontextprotocol/python-sdk
    - Python ast module: https://docs.python.org/3/library/ast.html
    - Cyclomatic complexity: https://en.wikipedia.org/wiki/Cyclomatic_complexity
    - OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
    - OWASP Code Injection: https://owasp.org/www-community/attacks/Code_Injection
    - matplotlib: https://matplotlib.org/stable/api/index.html
"""

import ast
import json
import logging
import time
import traceback
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-GUI backend – no display server needed
import matplotlib.pyplot as plt                         # noqa: E402
import matplotlib.patches as mpatches                   # noqa: E402
import matplotlib.path as mpath                          # noqa: E402
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

# Citation: FastMCP server pattern from https://github.com/modelcontextprotocol/python-sdk
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration – loaded from .env via pydantic-settings (no os.environ)
# Citation: https://docs.pydantic.dev/latest/concepts/pydantic_settings/
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(_SCRIPT_DIR / ".env")


class ServerSettings(BaseSettings):
    """Server configuration loaded from .env file."""

    model_config = {"env_file": str(_SCRIPT_DIR / ".env")}

    allowed_directory: str = "./sample_projects"


settings = ServerSettings()
_raw = Path(settings.allowed_directory)
ALLOWED_DIR: Path = (_SCRIPT_DIR / _raw).resolve() if not _raw.is_absolute() else _raw.resolve()

SERVER_NAME = "dev-workflow-server"
logger = logging.getLogger(SERVER_NAME)
logging.basicConfig(level=logging.INFO)

# Initialize FastMCP server
# Citation: FastMCP pattern from https://github.com/modelcontextprotocol/python-sdk
mcp = FastMCP(SERVER_NAME)


# ===========================================================================
# BEST PRACTICE 1 – Sandboxing
# Citations:
#   - OWASP Path Traversal – https://owasp.org/www-community/attacks/Path_Traversal
#   - OWASP Code Injection – https://owasp.org/www-community/attacks/Code_Injection
#   - Python ast module    – https://docs.python.org/3/library/ast.html#ast.parse
#
# Two layers of sandboxing:
#   A) Directory jailing – all file access is resolved and verified to stay
#      inside ALLOWED_DIR, blocking ../ traversal, symlink escapes, and
#      absolute-path overrides.
#   B) Static analysis only – user-supplied Python is processed exclusively
#      via ast.parse(), which builds a syntax tree WITHOUT executing code.
#      The server never calls exec(), eval(), compile(), subprocess, or
#      os.system on user content.
# ===========================================================================

# --- A) Directory Jailing ---------------------------------------------------
def validate_file_path(file_path: str) -> Path:
    """Validate that *file_path* resolves inside ALLOWED_DIR.

    Raises ValueError / FileNotFoundError with safe messages.
    """
    if "\x00" in file_path:
        raise ValueError("Access denied: invalid characters in path")

    candidate = (ALLOWED_DIR / file_path).resolve()

    try:
        candidate.relative_to(ALLOWED_DIR)
    except ValueError:
        raise ValueError("Access denied: path is outside the allowed directory")

    if not candidate.exists():
        raise FileNotFoundError("File not found")

    if not candidate.is_file():
        raise ValueError("Path is not a file")

    if candidate.suffix != ".py":
        raise ValueError("Only Python files (.py) are supported")

    return candidate


def validate_directory_path(dir_path: str) -> Path:
    """Validate that *dir_path* resolves to a directory inside ALLOWED_DIR.

    Raises ValueError / FileNotFoundError with safe messages.
    """
    if "\x00" in dir_path:
        raise ValueError("Access denied: invalid characters in path")

    candidate = (ALLOWED_DIR / dir_path).resolve()

    try:
        candidate.relative_to(ALLOWED_DIR)
    except ValueError:
        raise ValueError("Access denied: path is outside the allowed directory")

    if not candidate.exists():
        raise FileNotFoundError("Directory not found")

    if not candidate.is_dir():
        raise ValueError("Path is not a directory")

    return candidate


# --- B) Static Analysis Only ------------------------------------------------
_BLOCKED_BUILTINS = {"exec", "eval", "compile", "__import__"}


def sandbox_parse(source: str, filename: str = "<unknown>") -> ast.AST:
    """Parse Python source into an AST **without executing it**.

    This is the ONLY entry-point for processing user-supplied Python files.
    ast.parse (mode="exec") builds a syntax tree; it never runs the code.

    As an extra layer of defence the tree is scanned for calls to dangerous
    builtins (exec, eval, compile, __import__).  If any are found the file
    is flagged so the caller can warn the user.
    """
    tree = ast.parse(source, filename=filename, mode="exec")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name and name in _BLOCKED_BUILTINS:
                logger.warning(
                    "Sandbox: file %s contains a call to '%s' – "
                    "NOT executed (static analysis only).", filename, name
                )
    return tree


def safe_error_response(error: Exception) -> str:
    """Return a client-safe error string; log internals server-side only."""
    if isinstance(error, ValueError):
        return f"Validation error: {error}"
    if isinstance(error, FileNotFoundError):
        return "Error: the requested file was not found"
    if isinstance(error, SyntaxError):
        return "Error: the file contains invalid Python syntax"
    if isinstance(error, PermissionError):
        return "Error: insufficient permissions to access the file"

    logger.error("Unhandled exception:\n%s", traceback.format_exc())
    return "An internal error occurred. Please try again."


# ===========================================================================
# BEST PRACTICE 2 – Rate Limiting: Sliding-Window Throttle
# Citation: OWASP Denial of Service – https://owasp.org/www-community/attacks/Denial_of_Service
#
# Strategy: track timestamps of recent tool calls in a per-tool sliding
# window.  If the number of calls inside the window exceeds the limit the
# request is rejected.  This prevents a single client from overwhelming
# the server with rapid-fire requests.
# ===========================================================================
RATE_LIMIT_MAX_CALLS = 10       # max calls allowed per window
RATE_LIMIT_WINDOW_SECONDS = 60  # sliding window size in seconds

_call_timestamps: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(tool_name: str) -> None:
    """Enforce a sliding-window rate limit for *tool_name*.

    Raises ValueError when the limit is exceeded.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS

    # Drop timestamps that have fallen outside the window
    _call_timestamps[tool_name] = [
        t for t in _call_timestamps[tool_name] if t > window_start
    ]

    if len(_call_timestamps[tool_name]) >= RATE_LIMIT_MAX_CALLS:
        raise ValueError(
            f"Rate limit exceeded: max {RATE_LIMIT_MAX_CALLS} calls "
            f"per {RATE_LIMIT_WINDOW_SECONDS}s for '{tool_name}'"
        )

    _call_timestamps[tool_name].append(now)


# ===========================================================================
# Code Complexity Analysis Helpers
# Citation: Python ast module – https://docs.python.org/3/library/ast.html
# ===========================================================================
def count_branches(node: ast.AST) -> int:
    """Count branching constructs contributing to cyclomatic complexity.

    Cyclomatic complexity ≈ 1 + number of decision points.
    Citation: McCabe, "A Complexity Measure", IEEE TSE, 1976.
    """
    count = 0
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                              ast.With, ast.Assert)):
            count += 1
        if isinstance(child, ast.BoolOp):
            count += len(child.values) - 1
    return count


def compute_max_depth(node: ast.AST, current: int = 0) -> int:
    """Return the maximum nesting depth below *node*."""
    best = current
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.With,
                              ast.Try, ast.ExceptHandler)):
            best = max(best, compute_max_depth(child, current + 1))
        else:
            best = max(best, compute_max_depth(child, current))
    return best


def _has_docstring(node: ast.AST) -> bool:
    """Check whether a function/class node has a docstring."""
    if not hasattr(node, "body") or not node.body:
        return False
    first = node.body[0]
    return (isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str))


def analyze_function(node: ast.FunctionDef) -> dict:
    """Return complexity metrics for a single function definition."""
    body_lines = (node.end_lineno - node.lineno + 1) if node.end_lineno else 0

    args = node.args
    param_count = (len(args.args) + len(args.posonlyargs)
                   + len(args.kwonlyargs)
                   + (1 if args.vararg else 0)
                   + (1 if args.kwarg else 0))

    return {
        "name": node.name,
        "line": node.lineno,
        "lines": body_lines,
        "parameters": param_count,
        "cyclomatic_complexity": 1 + count_branches(node),
        "max_nesting_depth": compute_max_depth(node),
        "has_docstring": _has_docstring(node),
    }


def analyze_class(node: ast.ClassDef) -> dict:
    """Return metrics for a class and each of its methods."""
    methods = [
        analyze_function(item)
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    return {
        "name": node.name,
        "line": node.lineno,
        "method_count": len(methods),
        "methods": methods,
        "has_docstring": _has_docstring(node),
        "base_classes": len(node.bases),
    }


def compute_complexity(source: str, display_path: str) -> dict:
    """Parse *source* and return a full complexity report."""
    tree = sandbox_parse(source, filename=display_path)

    functions = []
    classes = []
    import_count = 0
    global_vars = 0

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(analyze_function(node))
        elif isinstance(node, ast.ClassDef):
            classes.append(analyze_class(node))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_count += 1
        elif isinstance(node, ast.Assign):
            global_vars += 1

    return {
        "file": display_path,
        "total_lines": len(source.splitlines()),
        "functions": functions,
        "classes": classes,
        "imports": import_count,
        "global_variables": global_vars,
    }


# ===========================================================================
# Docstring Generation Helpers
# ===========================================================================
def _annotation_str(node: ast.AST | None) -> str:
    """Convert an AST annotation node to a human-readable type string."""
    if node is None:
        return "Any"
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_annotation_str(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return f"{_annotation_str(node.value)}[{_annotation_str(node.slice)}]"
    if isinstance(node, ast.Tuple):
        return ", ".join(_annotation_str(e) for e in node.elts)
    return "Any"


def _infer_summary(target: ast.FunctionDef) -> str:
    """Infer a one-line summary for a function from its name and body."""
    name = target.name
    params = [a.arg for a in target.args.args if a.arg not in ("self", "cls")]

    # __init__
    if name == "__init__":
        if params:
            return (
                "Initialize a new instance with the given "
                + ", ".join(f"``{p}``" for p in params)
                + "."
            )
        return "Initialize a new instance."

    # Single-return that is a binary operation → describe the math
    all_returns = [
        n for n in ast.walk(target)
        if isinstance(n, ast.Return) and n.value is not None
    ]
    if len(all_returns) == 1 and isinstance(all_returns[0].value, ast.BinOp):
        op_map = {
            ast.Add: "sum", ast.Sub: "difference", ast.Mult: "product",
            ast.Div: "quotient", ast.Mod: "remainder",
        }
        word = op_map.get(type(all_returns[0].value.op))
        if word and len(params) == 2:
            return f"Return the {word} of ``{params[0]}`` and ``{params[1]}``."

    words = name.split("_")

    # Well-known single-word function names
    _sw = {
        "power": "Raise the base to the given exponent and return the result.",
        "recall": "Retrieve the stored value from memory.",
        "clear": "Clear the internal state and reset to defaults.",
        "store": "Store the given value.",
        "transform": "Transform the input record and return the result.",
    }
    if len(words) == 1 and name in _sw:
        return _sw[name]

    # Multi-word names: use verb-specific templates
    verb = words[0].lower()
    subject = " ".join(words[1:])

    _templates = {
        "validate": "Validate the {s} and return any errors found.",
        "check": "Check the {s} and return any errors found.",
        "verify": "Verify the {s}.",
        "get": "Retrieve the {s}.",
        "fetch": "Retrieve the {s} and return the result.",
        "retrieve": "Retrieve the {s}.",
        "load": "Load the {s} from the source.",
        "store": "Store the {s}.",
        "save": "Save the {s}.",
        "set": "Set the {s}.",
        "process": "Process the {s} and return the results.",
        "handle": "Handle the {s}.",
        "run": "Execute the {s} and return a summary of results.",
        "execute": "Execute the {s}.",
        "build": "Build a {s} from the provided data.",
        "create": "Create a new {s}.",
        "generate": "Generate a {s}.",
        "transform": "Transform the {s} and return the result.",
        "convert": "Convert the {s} to the target format.",
        "filter": "Filter the {s} based on the given criteria.",
        "clear": "Clear the {s} and reset to defaults.",
        "reset": "Reset the {s} to the initial state.",
        "sanitize": "Sanitize the {s} by removing dangerous content.",
        "parse": "Parse the {s} and return the structured result.",
        "compute": "Compute the {s}.",
        "calculate": "Calculate the {s}.",
        "count": "Count the {s}.",
        "batch": "Batch-process the {s} and return the results.",
        "sort": "Sort the {s}.",
        "update": "Update the {s}.",
        "remove": "Remove the {s}.",
        "delete": "Delete the {s}.",
    }

    if subject and verb in _templates:
        return _templates[verb].format(s=subject.replace("_", " "))

    # is/has/can predicates
    if verb in ("is", "has", "can"):
        s = subject.replace("_", " ") if subject else "the condition"
        if verb == "is":
            return f"Return whether the instance is {s}."
        if verb == "has":
            return f"Return whether the instance has {s}."
        return f"Return whether the instance can {s}."

    # Fallback: capitalise the name as a phrase
    readable = " ".join(words)
    return readable[0].upper() + readable[1:] + "."


def _infer_param_description(
    arg_name: str, type_str: str, target: ast.FunctionDef,
) -> str:
    """Infer a parameter description from its name, type, and usage."""
    clean = arg_name.strip("*").lower()

    # Short operand names in arithmetic functions
    _math_verbs = {"add", "subtract", "multiply", "divide", "power", "mod", "sum"}
    func_words = set(target.name.lower().split("_"))
    if clean in ("a", "b", "x", "y") and func_words & _math_verbs:
        params = [a.arg for a in target.args.args if a.arg not in ("self", "cls")]
        idx = params.index(arg_name) if arg_name in params else -1
        return "The first operand." if idx == 0 else "The second operand."

    # Well-known parameter names
    _known: dict[str, str] = {
        "base": "The base value to exponentiate.",
        "exponent": "The exponent to raise the base to.",
        "name": "The name identifier.",
        "value": "The value to operate on.",
        "password": "The password string to validate.",
        "text": "The input text to process.",
        "data": "The input data to process.",
        "items": "The collection of items to process.",
        "records": "The collection of records to process.",
        "user_id": "The unique identifier of the user.",
        "threshold": "Minimum value threshold for filtering.",
        "strict": "If True, raise on errors instead of skipping.",
        "validate": "If True, validate each record before processing.",
        "include_metadata": "If True, include additional metadata in the result.",
        "max_errors": "Maximum number of errors to tolerate before stopping.",
        "group_key": "The dictionary key to group records by.",
        "sub_group_key": "Optional secondary key for nested sub-grouping.",
        "file_path": "Path to the file to process.",
        "function_name": "Name of the target function.",
        "source": "The source code string to parse.",
        "record": "A single data record to process.",
        "strategy": "The processing strategy to use.",
        "required_fields": "List of field names that must be present.",
        "field_map": "Dictionary mapping old field names to new field names.",
        "transformers": "Ordered list of transformers to apply to each record.",
    }
    if clean in _known:
        return _known[clean]

    # Boolean flags
    if type_str.lower() == "bool":
        if clean.startswith("include"):
            rest = clean.replace("include_", "").replace("_", " ") or "extra data"
            return f"If True, include {rest} in the result."
        readable = clean.replace("_", " ")
        return f"Whether to enable {readable}."

    # Type-based heuristics
    tl = type_str.lower()
    readable = clean.replace("_", " ")
    if tl.startswith("list"):
        return f"List of {readable} to process."
    if tl.startswith("dict"):
        return f"Dictionary containing {readable} data."
    if tl in ("int", "float"):
        return f"The {readable} value."
    if tl == "str":
        return f"The {readable} string."

    return f"The {readable} to use."


def _infer_raise_description(exc_class: str, target: ast.FunctionDef) -> str:
    """Infer when an exception is raised from its error message."""
    if exc_class == "NotImplementedError":
        return "Subclasses must override this method."

    for node in ast.walk(target):
        if not isinstance(node, ast.Raise) or not node.exc:
            continue
        if (isinstance(node.exc, ast.Call)
                and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == exc_class
                and node.exc.args
                and isinstance(node.exc.args[0], ast.Constant)
                and isinstance(node.exc.args[0].value, str)):
            msg = node.exc.args[0].value
            return msg if msg.endswith(".") else msg + "."

    return f"If a {exc_class} condition is encountered."


def _infer_return_description(target: ast.FunctionDef, return_type: str) -> str:
    """Infer a return-value description from the function body and type."""
    all_returns = [
        n for n in ast.walk(target)
        if isinstance(n, ast.Return) and n.value is not None
    ]

    if len(all_returns) == 1:
        ret = all_returns[0].value

        if isinstance(ret, ast.BinOp):
            op_map = {
                ast.Add: "sum", ast.Sub: "difference", ast.Mult: "product",
                ast.Div: "quotient", ast.Mod: "remainder",
            }
            word = op_map.get(type(ret.op))
            if word:
                return f"The {word} of the input values."

        if (isinstance(ret, ast.Attribute)
                and isinstance(ret.value, ast.Name)
                and ret.value.id == "self"):
            attr = ret.attr.lstrip("_").replace("_", " ")
            return f"The current {attr} value."

        if isinstance(ret, ast.Name):
            _var_map = {
                "result": "The computed result.",
                "results": "The list of processed results.",
                "output": "The processed output.",
                "errors": "List of error messages found, empty if valid.",
                "issues": "List of issues found, empty if valid.",
                "report": "The generated report dictionary.",
                "record": "The transformed record.",
            }
            if ret.id.lower() in _var_map:
                return _var_map[ret.id.lower()]

    tl = return_type.lower()
    if tl == "bool":
        return "True if the check passes, False otherwise."
    if tl.startswith("list"):
        return "The collected results."
    if tl.startswith("dict"):
        return "A dictionary containing the results."
    if tl.startswith("tuple"):
        return "A tuple containing the result components."
    if tl in ("str", "string"):
        return "The resulting string."
    if tl in ("int", "float"):
        return "The computed numeric result."

    return "The computed result."


def generate_function_docstring(source: str, function_name: str) -> tuple[str, str]:
    """Generate a Google-style docstring for *function_name* and insert it into *source*.

    Returns a (docstring_text, modified_source) tuple.
    """
    tree = sandbox_parse(source)

    target = None
    for node in ast.walk(tree):
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == function_name):
            target = node
            break

    if target is None:
        raise ValueError(f"Function '{function_name}' not found in the file")

    if _has_docstring(target):
        raise ValueError(f"Function '{function_name}' already has a docstring")

    # Detect indentation from the first statement in the function body
    source_lines = source.splitlines(keepends=True)
    first_body_line = source_lines[target.body[0].lineno - 1]
    indent = first_body_line[: len(first_body_line) - len(first_body_line.lstrip())]

    # ---- Collect parameter info ----
    params = []
    for arg in target.args.args:
        if arg.arg in ("self", "cls"):
            continue
        params.append({"name": arg.arg,
                       "type": _annotation_str(arg.annotation)})
    for arg in target.args.posonlyargs:
        params.append({"name": arg.arg,
                       "type": _annotation_str(arg.annotation)})
    for arg in target.args.kwonlyargs:
        params.append({"name": arg.arg,
                       "type": _annotation_str(arg.annotation)})
    if target.args.vararg:
        params.append({"name": f"*{target.args.vararg.arg}",
                       "type": _annotation_str(target.args.vararg.annotation)})
    if target.args.kwarg:
        params.append({"name": f"**{target.args.kwarg.arg}",
                       "type": _annotation_str(target.args.kwarg.annotation)})

    # ---- Collect raised exceptions ----
    raises: set[str] = set()
    for child in ast.walk(target):
        if isinstance(child, ast.Raise) and child.exc:
            if isinstance(child.exc, ast.Call) and isinstance(child.exc.func, ast.Name):
                raises.add(child.exc.func.id)
            elif isinstance(child.exc, ast.Name):
                raises.add(child.exc.id)

    return_type = _annotation_str(target.returns) if target.returns else None

    # ---- Build docstring lines (with inferred descriptions) ----
    summary = _infer_summary(target)
    doc_lines = [f'{indent}"""{summary}', ""]
    if params:
        doc_lines.append(f"{indent}Args:")
        for p in params:
            desc = _infer_param_description(p["name"], p["type"], target)
            doc_lines.append(f'{indent}    {p["name"]} ({p["type"]}): {desc}')
        doc_lines.append("")
    if raises:
        doc_lines.append(f"{indent}Raises:")
        for r in sorted(raises):
            desc = _infer_raise_description(r, target)
            doc_lines.append(f"{indent}    {r}: {desc}")
        doc_lines.append("")
    if return_type and return_type != "None":
        doc_lines.append(f"{indent}Returns:")
        ret_desc = _infer_return_description(target, return_type)
        doc_lines.append(f"{indent}    {return_type}: {ret_desc}")
        doc_lines.append("")
    doc_lines.append(f'{indent}"""')

    docstring_text = "\n".join(doc_lines)

    # ---- Insert docstring into source ----
    insert_at = target.body[0].lineno - 1  # 0-indexed, before the first body statement
    docstring_block = docstring_text + "\n"
    source_lines.insert(insert_at, docstring_block)

    modified_source = "".join(source_lines)
    return docstring_text, modified_source

# ===========================================================================
# Directory Scanning Helpers
# ===========================================================================
def _is_entry_point(tree: ast.AST) -> bool:
    """Return True if *tree* contains ``if __name__ == "__main__":`` or a
    top-level ``main()`` function definition."""
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare)
                    and len(test.ops) == 1
                    and isinstance(test.ops[0], ast.Eq)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"):
                return True
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "main"):
            return True
    return False


def _find_entry_points(directory: Path) -> list[Path]:
    """Find Python files that are top-level entry points in *directory*
    (files with ``if __name__ == "__main__":`` or a ``main()`` function).
    """
    entry_points: list[Path] = []
    for py_file in sorted(directory.rglob("*.py")):
        if not py_file.is_file():
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = sandbox_parse(
                source, filename=str(py_file.relative_to(ALLOWED_DIR))
            )
            if _is_entry_point(tree):
                entry_points.append(py_file)
        except (SyntaxError, UnicodeDecodeError):
            continue
    return entry_points


def _collect_py_files(directory: Path) -> list[Path]:
    """Collect all .py files inside *directory* (recursive)."""
    return sorted(f for f in directory.rglob("*.py") if f.is_file())


# ===========================================================================
# MCP Tools
# Citation: FastMCP @mcp.tool() pattern from https://github.com/modelcontextprotocol/python-sdk
# ===========================================================================
@mcp.tool()
def analyze_code_complexity(file_path: str) -> str:
    """Analyze a Python file **or every .py file in a directory** and return
    complexity metrics including cyclomatic complexity, nesting depth,
    function/class counts, and more.

    Args:
        file_path: Relative path to a Python file or directory to analyze
                   (relative to the allowed directory)
    """
    try:
        check_rate_limit("analyze_code_complexity")

        # Determine whether the target is a file or a directory
        if "\x00" in file_path:
            return "Access denied: invalid characters in path"
        candidate = (ALLOWED_DIR / file_path).resolve()
        try:
            candidate.relative_to(ALLOWED_DIR)
        except ValueError:
            return "Access denied: path is outside the allowed directory"

        if candidate.is_dir():
            validated_dir = validate_directory_path(file_path)
            py_files = _collect_py_files(validated_dir)
            if not py_files:
                return "No Python files found in the directory."
            results = []
            for pf in py_files:
                source = pf.read_text(encoding="utf-8")
                display = str(pf.relative_to(ALLOWED_DIR))
                results.append(compute_complexity(source, display))
            return json.dumps(results, indent=2)
        else:
            validated = validate_file_path(file_path)
            source = validated.read_text(encoding="utf-8")
            metrics = compute_complexity(source, file_path)
            return json.dumps(metrics, indent=2)
    except Exception as e:
        return safe_error_response(e)


@mcp.tool()
def generate_docstrings(file_path: str, function_name: str) -> str:
    """Generate a Google-style docstring for a specific function in a Python file
    and insert it directly into the file.

    Args:
        file_path: Relative path to the Python file
                   (relative to the allowed directory)
        function_name: Name of the function to generate a docstring for
    """
    try:
        check_rate_limit("generate_docstrings")
        validated = validate_file_path(file_path)
        source = validated.read_text(encoding="utf-8")
        docstring_text, modified_source = generate_function_docstring(source, function_name)
        validated.write_text(modified_source, encoding="utf-8")
        return f"Docstring inserted for '{function_name}' in {file_path}:\n\n{docstring_text}"
    except Exception as e:
        return safe_error_response(e)

# ===========================================================================
# MCP Prompt
# Citation: FastMCP @mcp.prompt() pattern from https://github.com/modelcontextprotocol/python-sdk
# ===========================================================================
@mcp.prompt()
def code_review_assistant(file_path: str) -> str:
    """Comprehensive code review template for analysing Python files or
    entire project directories.  Evaluates complexity, documentation
    coverage, architecture, and suggests improvements.

    Args:
        file_path: Relative path to a Python file **or directory** to review
    """
    return (
        f"Please perform a comprehensive code review of: {file_path}\n\n"
        "(This may be a single Python file or an entire directory of Python "
        "files — the tools accept either.)\n\n"
        "Use the available tools to analyse the code. Follow these steps:\n\n"
        "1. **Complexity Analysis**: Use the `analyze_code_complexity` tool "
        "to get metrics for the file or directory.\n\n"
        "2. **Code Quality Assessment**: Based on the metrics, evaluate:\n"
        "   - Are any functions too complex (cyclomatic complexity > 10)?\n"
        "   - Are any functions too long (> 50 lines)?\n"
        "   - Is nesting too deep (> 4 levels)?\n"
        "   - Are there functions missing docstrings?\n\n"
        "3. **Documentation Review**: For any functions missing docstrings, "
        "4. **Summary Report**: Provide a structured report with:\n"
        "   - Overall health score (Good / Needs Improvement / Critical)\n"
        "   - Key metrics summary\n"
        "   - Specific recommendations for improvement\n"
        "   - Generated docstrings for undocumented functions\n\n"
        "Please be thorough but constructive in your review."
    )


# ===========================================================================
# Entry Point
# ===========================================================================
def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
