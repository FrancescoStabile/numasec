"""security-mcp — MCP Security Tool Server.

Usage:
    security-mcp              # MCP server (stdio, default)
    security-mcp --mcp        # MCP server (stdio, explicit)
    security-mcp --mcp-http   # MCP server (HTTP)
    security-mcp --version    # Show version
"""

import os
import sys

from security_mcp import __version__


def main() -> None:
    """Entry point for console_scripts."""
    if "--version" in sys.argv:
        print(f"security-mcp {__version__}")
        return

    try:
        transport = "stdio"
        if "--mcp-http" in sys.argv or os.environ.get("MCP_TRANSPORT") == "http":
            transport = "http"
        elif os.environ.get("MCP_TRANSPORT"):
            transport = os.environ["MCP_TRANSPORT"]

        from security_mcp.mcp.server import create_mcp_server

        server = create_mcp_server()
        server.run(transport=transport)
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
