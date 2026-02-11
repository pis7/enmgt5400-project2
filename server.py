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

    # ---- Build docstring lines ----
    doc_lines = [f'{indent}"""[Brief description of {function_name}]', ""]
    if params:
        doc_lines.append(f"{indent}Args:")
        for p in params:
            doc_lines.append(f'{indent}    {p["name"]} ({p["type"]}): [Description]')
        doc_lines.append("")
    if raises:
        doc_lines.append(f"{indent}Raises:")
        for r in sorted(raises):
            doc_lines.append(f"{indent}    {r}: [When this is raised]")
        doc_lines.append("")
    if return_type and return_type != "None":
        doc_lines.append(f"{indent}Returns:")
        doc_lines.append(f"{indent}    {return_type}: [Description of return value]")
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
# UML Diagram Generation Helpers
# Citation: matplotlib – https://matplotlib.org/stable/api/index.html
# ===========================================================================
def _resolve_local_imports(tree: ast.AST, file_dir: Path) -> list[Path]:
    """Resolve import statements to local .py files inside ALLOWED_DIR."""
    local_files: list[Path] = []
    for node in ast.iter_child_nodes(tree):
        modules: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)

        for mod in modules:
            candidate = file_dir / Path(*mod.split(".")).with_suffix(".py")
            if candidate.exists() and candidate.is_file():
                try:
                    resolved = candidate.resolve()
                    resolved.relative_to(ALLOWED_DIR)
                    if resolved not in local_files:
                        local_files.append(resolved)
                except ValueError:
                    pass  # outside sandbox – skip
    return local_files


def _extract_uml_classes(tree: ast.AST) -> list[dict]:
    """Extract class definitions with methods, attributes, and base classes."""
    classes = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        methods: list[str] = []
        attributes: list[str] = []

        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Build method signature
            params = []
            for arg in item.args.args:
                if arg.arg in ("self", "cls"):
                    continue
                params.append(f"{arg.arg}: {_annotation_str(arg.annotation)}")
            ret = _annotation_str(item.returns) if item.returns else "None"
            vis = "-" if item.name.startswith("_") else "+"
            methods.append(f"{vis} {item.name}({', '.join(params)}): {ret}")

            # Extract self.attr assignments from __init__
            if item.name == "__init__":
                for stmt in ast.walk(item):
                    if (isinstance(stmt, ast.Assign)):
                        for tgt in stmt.targets:
                            if (isinstance(tgt, ast.Attribute)
                                    and isinstance(tgt.value, ast.Name)
                                    and tgt.value.id == "self"):
                                attributes.append(f"+ {tgt.attr}")
                    elif (isinstance(stmt, ast.AnnAssign)
                          and stmt.target
                          and isinstance(stmt.target, ast.Attribute)
                          and isinstance(stmt.target.value, ast.Name)
                          and stmt.target.value.id == "self"):
                        t = _annotation_str(stmt.annotation)
                        attributes.append(f"+ {stmt.target.attr}: {t}")

        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(_annotation_str(base))

        classes.append({
            "name": node.name,
            "methods": methods,
            "attributes": attributes,
            "bases": bases,
        })
    return classes


def _extract_uml_functions(tree: ast.AST) -> list[str]:
    """Extract top-level (non-class) function signatures for UML."""
    functions: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = []
        for arg in node.args.args:
            params.append(f"{arg.arg}: {_annotation_str(arg.annotation)}")
        ret = _annotation_str(node.returns) if node.returns else "None"
        vis = "-" if node.name.startswith("_") else "+"
        functions.append(f"{vis} {node.name}({', '.join(params)}): {ret}")
    return functions


def _draw_class_box(ax, x: float, y: float, cls: dict,
                    font_size: float = 7) -> tuple[float, float]:
    """Draw a UML class box and return (width, height).

    (x, y) is the top-left corner.  y increases downward (inverted axis).
    The box has three compartments: name / attributes / methods.
    """
    char_w = font_size * 0.6   # approx character width in data-space units
    line_h = font_size * 1.8   # line height in data-space units
    pad = 6.0                  # internal padding

    # Determine box width from longest line
    all_lines = [cls["name"]] + cls["attributes"] + cls["methods"]
    max_chars = max((len(l) for l in all_lines), default=10)
    box_w = max(max_chars * char_w + 2 * pad, 80)

    # Section heights
    name_h = line_h + 2 * pad
    attr_h = max(len(cls["attributes"]), 1) * line_h + pad
    meth_h = max(len(cls["methods"]), 1) * line_h + pad
    box_h = name_h + attr_h + meth_h

    # Background
    bg = mpatches.FancyBboxPatch(
        (x, y), box_w, box_h,
        boxstyle="round,pad=2", facecolor="#FFFFCC", edgecolor="black", linewidth=1,
    )
    ax.add_patch(bg)

    # Name compartment (bold, centered)
    ax.text(x + box_w / 2, y + name_h / 2, cls["name"],
            ha="center", va="center", fontsize=font_size + 1,
            fontweight="bold", family="monospace")

    # Separator line
    ax.plot([x, x + box_w], [y + name_h, y + name_h], color="black", linewidth=0.8)

    # Attributes
    ay = y + name_h + pad / 2
    for attr in cls["attributes"]:
        ax.text(x + pad, ay, attr, ha="left", va="top",
                fontsize=font_size, family="monospace")
        ay += line_h

    # Separator line
    sep_y = y + name_h + attr_h
    ax.plot([x, x + box_w], [sep_y, sep_y], color="black", linewidth=0.8)

    # Methods
    my = sep_y + pad / 2
    for meth in cls["methods"]:
        ax.text(x + pad, my, meth, ha="left", va="top",
                fontsize=font_size, family="monospace")
        my += line_h

    return box_w, box_h


def _draw_module_box(ax, x: float, y: float, filename: str,
                     funcs: list[str], font_size: float = 7
                     ) -> tuple[float, float]:
    """Draw a <<module>> box for top-level functions and return (w, h).

    (x, y) is the top-left corner.  y increases downward (inverted axis).
    """
    char_w = font_size * 0.6
    line_h = font_size * 1.8
    pad = 6.0

    header = f"\u00ab module \u00bb {filename}"
    all_lines = [header] + funcs
    max_chars = max((len(l) for l in all_lines), default=10)
    box_w = max(max_chars * char_w + 2 * pad, 80)

    header_h = line_h + 2 * pad
    body_h = max(len(funcs), 1) * line_h + pad
    box_h = header_h + body_h

    bg = mpatches.FancyBboxPatch(
        (x, y), box_w, box_h,
        boxstyle="round,pad=2", facecolor="#CCE5FF", edgecolor="black", linewidth=1,
    )
    ax.add_patch(bg)

    ax.text(x + box_w / 2, y + header_h / 2, header,
            ha="center", va="center", fontsize=font_size + 1,
            fontweight="bold", family="monospace")
    ax.plot([x, x + box_w], [y + header_h, y + header_h],
            color="black", linewidth=0.8)

    fy = y + header_h + pad / 2
    for func in funcs:
        ax.text(x + pad, fy, func, ha="left", va="top",
                fontsize=font_size, family="monospace")
        fy += line_h

    return box_w, box_h


def build_uml_diagram(
    file_classes: dict[str, list[dict]],
    file_functions: dict[str, list[str]],
    output_path: Path,
) -> Path:
    """Render a UML class diagram to PNG using matplotlib.

    Citation: matplotlib – https://matplotlib.org/stable/api/index.html
    """
    # Flatten all classes and determine inheritance depth for layout
    all_classes: list[dict] = []
    for classes in file_classes.values():
        all_classes.extend(classes)

    class_names = {c["name"] for c in all_classes}

    # Compute depth: base classes = 0, children = parent_depth + 1
    depth: dict[str, int] = {}
    for cls in all_classes:
        depth[cls["name"]] = 0
    changed = True
    while changed:
        changed = False
        for cls in all_classes:
            for base in cls["bases"]:
                if base in depth and depth[base] + 1 > depth[cls["name"]]:
                    depth[cls["name"]] = depth[base] + 1
                    changed = True

    # Group classes by depth level
    levels: dict[int, list[dict]] = defaultdict(list)
    for cls in all_classes:
        levels[depth[cls["name"]]].append(cls)

    # --- Layout constants ---
    font_size = 7
    x_gap = 40
    y_gap = 60
    margin = 30

    # Pass 1: measure all boxes to determine positions
    fig_tmp, ax_tmp = plt.subplots()
    box_sizes: dict[str, tuple[float, float]] = {}
    for cls in all_classes:
        w, h = _draw_class_box(ax_tmp, 0, 0, cls, font_size)
        box_sizes[cls["name"]] = (w, h)
    plt.close(fig_tmp)

    # Compute positions level by level (depth 0 at top)
    positions: dict[str, tuple[float, float]] = {}  # top-left corner
    max_depth = max(levels.keys()) if levels else 0
    current_y = margin

    level_widths: dict[int, float] = {}
    for d in range(max_depth + 1):
        row = levels[d]
        total_w = sum(box_sizes[c["name"]][0] for c in row) + x_gap * max(len(row) - 1, 0)
        level_widths[d] = total_w
        row_h = max((box_sizes[c["name"]][1] for c in row), default=0)
        cx = margin
        for cls in row:
            w, h = box_sizes[cls["name"]]
            positions[cls["name"]] = (cx, current_y)
            cx += w + x_gap
        current_y += row_h + y_gap

    # Module function boxes below classes
    mod_positions: dict[str, tuple[float, float]] = {}
    mod_sizes: dict[str, tuple[float, float]] = {}
    fig_tmp2, ax_tmp2 = plt.subplots()
    for filename, funcs in file_functions.items():
        if not funcs:
            continue
        w, h = _draw_module_box(ax_tmp2, 0, 0, filename, funcs, font_size)
        mod_sizes[filename] = (w, h)
    plt.close(fig_tmp2)

    mx = margin
    for filename in mod_sizes:
        w, h = mod_sizes[filename]
        mod_positions[filename] = (mx, current_y)
        mx += w + x_gap

    if mod_sizes:
        current_y += max(h for _, h in mod_sizes.values()) + margin
    else:
        current_y += margin

    # Determine figure size
    all_right_edges = (
        [positions[n][0] + box_sizes[n][0] for n in positions]
        + [mod_positions[n][0] + mod_sizes[n][0] for n in mod_positions]
    )
    fig_w_pts = max(all_right_edges, default=200) + margin
    fig_h_pts = current_y

    # Scale to inches (use 1pt = 1 unit for simplicity, then scale)
    scale = 0.015  # pts → inches
    fig, ax = plt.subplots(figsize=(max(fig_w_pts * scale, 4), max(fig_h_pts * scale, 3)))
    ax.set_xlim(0, fig_w_pts)
    ax.set_ylim(fig_h_pts, 0)  # y increases downward
    ax.set_aspect("equal")
    ax.axis("off")

    # Pass 2: draw everything on the real axes
    # Draw classes (y coord = top of box, box draws downward)
    drawn_boxes: dict[str, tuple[float, float, float, float]] = {}  # name → (x, y, w, h)
    for cls in all_classes:
        cx, cy = positions[cls["name"]]
        w, h = _draw_class_box(ax, cx, cy, cls, font_size)
        drawn_boxes[cls["name"]] = (cx, cy, w, h)

    # Draw module boxes
    for filename, funcs in file_functions.items():
        if filename not in mod_positions:
            continue
        mx_, my_ = mod_positions[filename]
        _draw_module_box(ax, mx_, my_, filename, funcs, font_size)

    # Draw inheritance arrows (child top → parent bottom, y-axis inverted)
    for cls in all_classes:
        for base in cls["bases"]:
            if base not in drawn_boxes:
                continue
            # Child top-center (smaller y = higher on screen with inverted axis)
            cx, cy, cw, ch = drawn_boxes[cls["name"]]
            child_top = (cx + cw / 2, cy)
            # Parent bottom-center
            px, py, pw, ph = drawn_boxes[base]
            parent_bottom = (px + pw / 2, py + ph)
            ax.annotate(
                "", xy=parent_bottom, xytext=child_top,
                arrowprops=dict(
                    arrowstyle="-|>", facecolor="white",
                    edgecolor="black", linewidth=1.2,
                ),
            )

    fig.savefig(str(output_path), dpi=150, bbox_inches="tight",
                facecolor="white", pad_inches=0.2)
    plt.close(fig)
    return output_path


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


@mcp.tool()
def generate_uml_diagram(file_path: str) -> str:
    """Generate a UML class diagram PNG for a Python file **or directory**
    and its local dependencies.  Returns the path to the saved image.

    When given a directory the tool automatically locates entry-point files
    (those with ``if __name__ == "__main__":`` or a top-level ``main()``
    function) and recursively traces their local imports to build the diagram.

    Args:
        file_path: Relative path to a Python file or directory to diagram
                   (relative to the allowed directory)
    """
    try:
        check_rate_limit("generate_uml_diagram")

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
            roots = _find_entry_points(validated_dir)
            if not roots:
                return ("No entry-point files found in the directory "
                        "(looked for `if __name__ == \"__main__\":` or "
                        "a top-level `main()` function).")
            output_png = validated_dir / (validated_dir.name + "_uml.png")
        elif candidate.is_file():
            validated = validate_file_path(file_path)
            roots = [validated]
            output_png = validated.with_name(validated.stem + "_uml.png")
        else:
            return "Error: path not found"

        file_classes: dict[str, list[dict]] = {}
        file_functions: dict[str, list[str]] = {}
        visited: set[Path] = set()

        def _process_file(py_path: Path) -> None:
            """Recursively parse *py_path* and its local imports."""
            if py_path in visited:
                return
            visited.add(py_path)
            source = py_path.read_text(encoding="utf-8")
            rel = str(py_path.relative_to(ALLOWED_DIR))
            tree = sandbox_parse(source, filename=rel)
            file_classes[rel] = _extract_uml_classes(tree)
            file_functions[rel] = _extract_uml_functions(tree)
            for dep in _resolve_local_imports(tree, py_path.parent):
                _process_file(dep)

        for root in roots:
            _process_file(root)

        build_uml_diagram(file_classes, file_functions, output_png)

        rel_path = output_png.relative_to(ALLOWED_DIR)
        return f"UML diagram saved to: {rel_path}"
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
        "use the `generate_docstrings` tool to create suggested docstrings.\n\n"
        "4. **Architecture Visualization**: Use the `generate_uml_diagram` tool "
        "to create a UML class diagram.  When given a directory the tool "
        "automatically finds entry-point files and traces their imports.\n\n"
        "5. **Summary Report**: Provide a structured report with:\n"
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
