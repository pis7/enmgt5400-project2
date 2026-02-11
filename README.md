# Development Workflow MCP Server

An MCP (Model Context Protocol) server for Python development workflows, providing automated code complexity analysis and documentation generation.

## Features

| Component | Name | Description |
|-----------|------|-------------|
| Tool 1 | `analyze_code_complexity` | Parses Python files using the `ast` module and returns complexity metrics (cyclomatic complexity, nesting depth, line counts, docstring coverage) |
| Tool 2 | `generate_docstrings` | Analyses a function's signature, parameters, return type, and raised exceptions to generate a Google-style docstring |
| Prompt | `code-review-assistant` | A comprehensive code review template that chains both tools together for a full file review |

## Best Practices

1. **Input Sanitization (Path Traversal Prevention)** — All file paths are resolved and validated against a jailed allowed directory. Prevents `../` traversal, absolute path bypasses, null byte injection, and symlink escapes.

2. **Error Disclosure (Sanitised Error Messages)** — All exceptions are caught and mapped to safe, generic client-facing messages. Internal paths, stack traces, credentials, and library versions are never exposed to the client.

## Prerequisites

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) (recommended package manager)
- Claude Desktop (for MCP integration)

## Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd "Project 2"
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

## Running Exploit Tests

The exploit tests demonstrate that both best practices successfully block attacks:

```bash
python exploit_tests.py
```

Expected output: all 11 tests pass, showing that path traversal attempts and information disclosure attacks are blocked.

## Project Structure

```
Project 2/
├── server.py                  # Main MCP server implementation
├── exploit_tests.py           # Exploit demonstration scripts
├── requirements.txt           # Python dependencies
├── .env                       # Configuration (not committed)
├── .gitignore                 # Git ignore rules
├── claude_desktop_config.json # Claude Desktop MCP configuration
├── README.md                  # This file
└── sample_projects/
    └── example.py             # Sample Python file for testing
```

## Usage Examples

### From Claude Desktop

Once configured, you can use natural language:

- *"Analyse the complexity of example.py"* — triggers `analyze_code_complexity`
- *"Generate a docstring for the process_data function in example.py"* — triggers `generate_docstrings`
- Use the **code-review-assistant** prompt for a full automated review

### Tool Output Examples

**analyze_code_complexity** returns JSON with:
- Total line count, import count, global variable count
- Per-function: cyclomatic complexity, nesting depth, parameter count, docstring presence
- Per-class: method count, method-level metrics

**generate_docstrings** returns a Google-style docstring template with:
- Parameter names and types
- Raised exceptions
- Return type
