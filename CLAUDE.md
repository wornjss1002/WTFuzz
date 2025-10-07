# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository appears to be a fresh setup for Claude Code with MCP (Model Context Protocol) server configurations. The project contains:

- MCP server configurations for: context7, playwright, notion, github, and sentry
- Python virtual environment setup
- No source code files yet

## MCP Configuration

The project uses multiple MCP servers configured in `.mcp.json`:

- **context7**: HTTP-based server for up-to-date library documentation
- **playwright**: Local server for browser automation
- **notion**: HTTP-based server for Notion integration
- **github**: Local server for GitHub operations
- **sentry**: HTTP-based server for error monitoring

All servers are enabled in `.claude/settings.local.json`.

## Development Environment

- **Python Environment**: Uses a virtual environment located in `venv/`
- **Activation**: Use `venv\Scripts\activate` (Windows) to activate the virtual environment
- **No Package Dependencies**: No requirements.txt or pyproject.toml found yet

## Architecture Notes

- This appears to be a fresh project setup with MCP servers configured
- No application code exists yet - this is a clean slate for development
- The project name "SHINOBI" suggests it may be intended for automation or monitoring tasks
- All MCP servers provide different capabilities that can be leveraged for various development tasks

## Commands

Since no package configuration files exist yet, standard development commands will depend on what type of project is built here. The virtual environment suggests Python development.

To activate the Python environment:
```bash
venv\Scripts\activate  # Windows
```
- Use Context7 to check up-to-data docs when needed for implementing new libraries or framworks, or adding features using them.
- When you answer, answer in Korean