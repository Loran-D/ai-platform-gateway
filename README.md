# AI Platform Gateway

A secure, containerized Python microservice providing security guardrails and system tool execution for AI agents via the **Model Context Protocol (FastMCP)**.

## Architecture & Features
* **OOP Guardrail Engine (`engine.py`)**: Categorized threat detection (High, Medium, Low risks) with strict policy enforcement.
* **Structured Audit Logging**: Generates secure JSON audit records with timezone-aware timestamps for compliance and security review.
* **FastMCP Server (`mcp_server.py`)**: Exposes safe system diagnostic tools and guarded command execution over standard I/O (`stdio`).
* **Automated Testing**: Comprehensive unit test suite using `pytest`.
* **Containerization**: Production-ready `Dockerfile` built with a modern Python `src/` workspace layout.

## Getting Started

### 1. Installation
Clone the repository and install in editable mode with dependencies:
```bash
pip install -e.