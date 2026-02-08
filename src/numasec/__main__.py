"""
NumaSec — Entry Point

Usage:
    numasec                      # Interactive mode
    numasec check <url>          # Quick security check (non-interactive)
    numasec --demo               # Demo mode (no API key needed)
    numasec --resume <session>   # Resume previous session
    numasec --verbose            # Debug logging
"""

import argparse
import asyncio
import sys

from numasec import __version__


def _suppress_shutdown_noise(loop: asyncio.AbstractEventLoop):
    """Suppress 'Future exception was never retrieved' from Playwright during shutdown."""
    original_handler = loop.get_exception_handler()

    def handler(loop, context):
        msg = context.get("message", "")
        exc = context.get("exception")
        # Suppress Playwright driver disconnection noise on shutdown
        if exc and "Connection closed while reading from the driver" in str(exc):
            return
        if "Future exception was never retrieved" in msg:
            if exc and "driver" in str(exc).lower():
                return
        # Everything else: use original handler or default
        if original_handler:
            original_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


async def async_main():
    """Async main entry point."""
    # Suppress Playwright shutdown noise early
    _suppress_shutdown_noise(asyncio.get_running_loop())

    parser = argparse.ArgumentParser(
        description="NumaSec — AI Security Testing for Your Apps",
        epilog="Examples:\n"
               "  numasec                         Interactive mode\n"
               "  numasec check http://localhost:3000  Quick security check\n"
               "  numasec --demo                  See NumaSec in action (no API key)\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"numasec {__version__}")
    parser.add_argument("--resume", metavar="SESSION_ID", help="Resume a previous session")
    parser.add_argument("--budget", type=float, default=10.0, help="Cost budget limit (default: $10)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--show-browser", action="store_true", help="Show browser in real-time")
    parser.add_argument("--demo", action="store_true", help="See NumaSec in action (no API key needed)")

    # Subcommand: check <url>
    subparsers = parser.add_subparsers(dest="command")
    check_parser = subparsers.add_parser("check", help="Quick security check (non-interactive)")
    check_parser.add_argument("url", help="URL to check (e.g. http://localhost:3000)")
    check_parser.add_argument("--budget", type=float, default=5.0, help="Cost budget limit")
    check_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    check_parser.add_argument("--show-browser", action="store_true", help="Show browser in real-time")

    args = parser.parse_args()

    # Demo mode — standalone replay, no config needed
    if args.demo:
        from numasec.demo import run_demo
        await run_demo()
        return

    # Non-interactive check mode
    if args.command == "check":
        from numasec.logging_config import setup_logging
        logger = setup_logging(verbose=args.verbose)
        logger.info("NumaSec check mode", extra={"url": args.url})

        from numasec.cli import NumaSecCLI
        cli = NumaSecCLI(show_browser=args.show_browser)
        cli.cost_tracker.budget_limit = args.budget
        await cli.run_check(args.url)
        return

    # Interactive mode
    from numasec.logging_config import setup_logging
    logger = setup_logging(verbose=args.verbose)
    logger.info("NumaSec starting", extra={"cli_args": vars(args)})

    try:
        from numasec.cli import NumaSecCLI

        cli = NumaSecCLI(resume_session_id=args.resume, show_browser=args.show_browser)
        if args.budget:
            cli.cost_tracker.budget_limit = args.budget

        await cli.run()

    except KeyboardInterrupt:
        logger.info("User interrupted with Ctrl-C")
        print("\nBye! Stay safe.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Sync entry point for console_scripts (pyproject.toml)."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
