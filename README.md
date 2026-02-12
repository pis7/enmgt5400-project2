# Development Workflow MCP Server

An MCP (Model Context Protocol) server for Python development workflows, providing automated code complexity analysis and documentation generation.

## Features

| Component | Name | Description |
|-----------|------|-------------|
| Tool 1 | `analyze_code_complexity` | Parses Python files using the `ast` module and returns complexity metrics (cyclomatic complexity, nesting depth, line counts, docstring coverage) |
| Tool 2 | `generate_docstrings` | Analyses function signatures, parameters, return types, and raised exceptions to generate Google-style docstrings — works on a single function, a whole file, or an entire directory |
| Prompt | `code-review-assistant` | A comprehensive code review template that chains both tools together for a full file review |

## Best Practices

1. **Sandboxing** — Two layers: (A) **Directory jailing** resolves and validates all file paths against a jailed allowed directory, preventing `../` traversal, absolute path bypasses, null byte injection, and symlink escapes. (B) **Static analysis only** — user-supplied Python is processed exclusively via `ast.parse()`, which builds a syntax tree without executing code. Error messages are sanitised so internal paths, credentials, and stack traces are never exposed.

2. **Rate Limiting** — A sliding-window throttle tracks timestamps of recent calls per tool. If the number of calls inside a 30-second window exceeds the limit (2), the request is rejected. Each tool has its own independent counter, preventing one tool's usage from blocking another.

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) (recommended package manager)
- Claude Desktop (for MCP integration)

## Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd "enmgt5400-project2"
```

### 2. Create and activate virtual environment

```bash
uv venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
```

### 3. Install dependencies

```bash
uv pip install -r requirements.txt
```

### 4. Configure environment

Create a `.env` file in the project root (already provided):

```
ALLOWED_DIRECTORY=./sample_projects
```

This controls which directory the server is permitted to read files from.

### 5. Run the server (standalone test)

```bash
python server.py
```

The server communicates over stdio and will wait for MCP protocol messages.

### 6. Configure Claude Desktop

Copy the contents of `claude_desktop_config.json` into your Claude Desktop configuration file:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

Update the `--directory` path to match your local project location.

Then restart Claude Desktop.

## Running Tests

The test suite (`server_tests.py`) validates that both best practices work correctly and that the MCP tools produce expected results. It is organised into three sections:

### Quick Start

```bash
# Make sure the virtual environment is active, then:
python server_tests.py
```

Expected output: **28/28 tests pass**. The script exits with code `0` on success and `1` if any test fails.

### What the Tests Cover

**Section 1 — Sandboxing (Best Practice 1)** verifies the two layers of sandboxing:

| # | Test | What it proves |
|---|------|---------------|
| 1 | Basic `../` traversal | Directory jailing blocks relative path escapes |
| 2 | Absolute path bypass | Absolute paths outside the sandbox are rejected |
| 3 | Encoded/mixed traversal | Mixed separators and redundant dots are caught |
| 4 | Null byte injection | `\x00` characters are rejected before path resolution |
| 5 | Non-Python file access | Only `.py` files are permitted |
| 6 | Deeply nested traversal | 20 levels of `../` still blocked |
| 7 | Directory path traversal | `validate_directory_path` also enforces jailing |
| 8 | `sandbox_parse` never executes code | Source containing `exec()`/`eval()`/`compile()` is parsed into an AST without running it |
| 9 | `sandbox_parse` returns AST only | Arithmetic in source is not evaluated — only syntax nodes are returned |
| 10 | Error response hides internal paths | `safe_error_response` strips filesystem paths from error messages |
| 11 | Error response hides credentials | Connection strings with passwords are never exposed to the client |

**Section 2 — Rate Limiting (Best Practice 2)** verifies the sliding-window throttle:

| # | Test | What it proves |
|---|------|---------------|
| 12 | Normal usage within limit | All 2 calls inside the 30 s window succeed |
| 13 | Excess calls blocked | Call #3 is rejected with a `Rate limit exceeded` error |
| 14 | Sliding window expires old timestamps | Stale entries fall off; a new call succeeds after the window resets |
| 15 | Per-tool isolation | Exhausting tool A's limit does not affect tool B |

**Section 3 — Tool Functionality** demonstrates the tools working end-to-end:

| # | Test | What it proves |
|---|------|---------------|
| 16 | Complexity analysis (single file) | `analyze_code_complexity` returns valid JSON with functions, classes, and line counts |
| 17 | Complexity analysis (directory) | Directory mode scans all `.py` files and returns a list of metrics |
| 18 | Complexity analysis (missing file) | A graceful error message is returned for non-existent files |
| 19 | Docstring generation | `generate_function_docstring` produces a Google-style docstring with Args and Returns |
| 20 | Docstring already exists | The tool correctly rejects functions that already have a docstring |
| 21 | Tool-level path traversal blocked | Sandboxing is enforced at the MCP tool entry point, not just in helpers |
| 22 | Complexity metrics accuracy | Cyclomatic complexity is computed correctly for known source code |
| 23 | Complexity (calculator.py — low CC) | All functions in `calculator.py` have cyclomatic complexity ≤ 3 |
| 24 | Complexity (validators.py — high CC) | `validate_user_input` has CC ≥ 8 due to heavy branching |
| 25 | Complexity (data_pipeline.py — classes) | Detects ≥ 3 classes including those with inheritance |
| 26 | Docstring generation with Raises | Generated docstring includes Args, Raises, and Returns sections |
| 27 | Docstring generation (directory) | `generate_docstrings` processes all undocumented functions across a directory |
| 28 | Directory scan finds all files | Directory mode discovers all 5 `.py` files in `sample_projects/` |

## Project Structure

```
enmgt5400-project2/
├── server.py                  # Main MCP server implementation
├── server_tests.py            # Test suite
├── requirements.txt           # Python dependencies
├── .env                       # Configuration (not committed)
├── .gitignore                 # Git ignore rules
├── claude_desktop_config.json # Claude Desktop MCP configuration
├── README.md                  # This file
└── sample_projects/
    ├── example.py             # Mixed complexity: simple funcs, nested loops, a class
    ├── calculator.py           # Low complexity: basic arithmetic, a class with memory
    ├── validators.py           # High branching: input validation with many if/elif chains
    ├── data_pipeline.py        # Class hierarchy, deep nesting, entry point (__main__)
    └── malicious.py            # Dangerous constructs (exec/eval) for sandbox demo
```

## Claude Desktop Demo Guide

Below are concrete prompts you can type into Claude Desktop to demonstrate each tool, the prompt template, and both best practices. Make sure the server is configured and running before starting (see Setup above).

### Demo 1 — Analyze Code Complexity (Single File)

**What it shows:** The `analyze_code_complexity` tool parsing a Python file via the `ast` module and returning structured metrics.

> Analyze the complexity of example.py

**Expected result:** JSON output listing every function and class with cyclomatic complexity, nesting depth, parameter count, line count, and docstring coverage. Point out that `process_data` has a high nesting depth (4) because of its nested `if`/`for` loops.

### Demo 2 — Analyze Code Complexity (Directory Scan)

**What it shows:** The tool accepting a directory path and scanning all `.py` files recursively.

> Analyze the complexity of the entire sample_projects directory

**Expected result:** A JSON array with one entry per `.py` file found inside `sample_projects/` (5 files: `calculator.py`, `data_pipeline.py`, `example.py`, `malicious.py`, `validators.py`).

### Demo 3 — Generate a Docstring

**What it shows:** The `generate_docstrings` tool inspecting a function's signature, parameters, return type, and raised exceptions to produce a Google-style docstring and insert it into the file. The tool accepts a single function, a whole file, or an entire directory.

**Single function:**

> Generate a docstring for the divide function in calculator.py

**Expected result:** A Google-style docstring is generated with `Args` (a, b), `Raises` (ZeroDivisionError), and `Returns` sections, and is written directly into `calculator.py`. You can open the file afterwards to show the inserted docstring.

**Entire directory:**

> Generate docstrings for all undocumented functions in sample_projects

**Expected result:** The tool scans every `.py` file in the directory, finds all functions without docstrings, generates and inserts a docstring for each one, and returns a JSON summary listing the files and functions that were documented.

### Demo 4 — Generate Docstring (Already Exists)

**What it shows:** Graceful error handling when a function already has a docstring.

> Generate a docstring for the fetch_user function in example.py

**Expected result:** The tool returns a validation error explaining that `fetch_user` already has a docstring, rather than duplicating it.

### Demo 5 — Code Review Prompt

**What it shows:** The `code-review-assistant` prompt template, which chains both tools together for a full automated review.

Click the **prompt icon** (📎 or prompt selector) in Claude Desktop, select **code-review-assistant**, and enter `example.py` (single file) or `sample_projects` (entire directory) as the file path.

**Expected result:** Claude runs `analyze_code_complexity` first, evaluates the metrics against quality thresholds (complexity > 10, lines > 50, nesting > 4), identifies undocumented functions, offers to generate docstrings, and produces a structured report with an overall health score. When given the directory, it reviews all 5 `.py` files at once.

### Demo 6 — Best Practice 1: Path Traversal Prevention (Sandboxing)

**What it shows:** Directory jailing blocks attempts to read files outside the allowed directory.

> Analyze the complexity of ../../etc/sensitive_python.py

or

> Analyze the complexity of C:\Windows\sensitive_python.py

**Expected result:** The server returns `"Access denied: path is outside the allowed directory"` instead of leaking file contents. This demonstrates that all paths are resolved and validated against the jailed `ALLOWED_DIR`.

### Demo 7 — Best Practice 1: Non-Python File Rejection

**What it shows:** The sandbox only permits `.py` files, preventing misuse against other file types.

> Analyze the complexity of ../requirements.txt

**Expected result:** The server returns a validation error because the file does not have a `.py` extension (or is outside the allowed directory), demonstrating the file-type allow-list.

### Demo 8 — Best Practice 1: Static Analysis Only (No Code Execution)

**What it shows:** Files containing dangerous constructs like `exec()`, `eval()`, and `compile()` are parsed into an AST without ever being executed. The sample file `malicious.py` contains functions that attempt to steal secrets, open a reverse shell, wipe the filesystem, and exfiltrate data — none of which are executed.

> Analyze the complexity of malicious.py

**Expected result:** The tool returns normal complexity metrics (functions, classes, line counts) for the file — proving the code was parsed, not run. Meanwhile, the **server-side log** prints warnings like:

```
WARNING:dev-workflow-server:Sandbox: file malicious.py contains a call to 'exec' – NOT executed (static analysis only).
WARNING:dev-workflow-server:Sandbox: file malicious.py contains a call to 'eval' – NOT executed (static analysis only).
WARNING:dev-workflow-server:Sandbox: file malicious.py contains a call to 'compile' – NOT executed (static analysis only).
```

These warnings prove the server detected every dangerous builtin but processed the file exclusively through `ast.parse()` — no code was ever executed. If the code had actually run, the machine would have been compromised.

### Demo 9 — Best Practice 2: Rate Limiting

**What it shows:** The sliding-window throttle that prevents a single client from overwhelming the server.

Rapidly ask the same question more than 2 times within 30 seconds:

> Analyze the complexity of example.py

*(repeat 2+ times quickly)*

**Expected result:** The first 2 calls succeed. The 3rd returns `"Rate limit exceeded: max 2 calls per 30s for 'analyze_code_complexity'"`. After 30 seconds the window resets and calls succeed again. Each tool (`analyze_code_complexity`, `generate_docstrings`) has its own independent counter.

### Demo 10 — Sanitized Error Messages

**What it shows:** Internal error details (stack traces, file paths, credentials) are never exposed to the client.

> Analyze the complexity of nonexistent_file.py

**Expected result:** The server returns `"Error: the requested file was not found"` — a safe, generic message. Internal paths and stack traces are logged server-side only and are never sent to Claude Desktop.

---

### Tool Output Reference

**analyze_code_complexity** returns JSON with:
- Total line count, import count, global variable count
- Per-function: cyclomatic complexity, nesting depth, parameter count, docstring presence
- Per-class: method count, method-level metrics

**generate_docstrings** returns a Google-style docstring template with:
- Parameter names and types
- Raised exceptions
- Return type
