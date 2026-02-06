"""
NumaSec v3 — Entry Point

Usage:
    python -m numasec
    python -m numasec --resume <session_id>
    python -m numasec --verbose  # Enable debug logging
"""

import argparse
import asyncio
import sys
from numasec.logging_config import setup_logging


async def async_main():
    """Async main entry point."""
    # Parse arguments
    parser = argparse.ArgumentParser(description="NumaSec v3 — AI Pentesting Agent")
    parser.add_argument("--version", action="version", version="numasec 3.0.0")
    parser.add_argument("--resume", metavar="SESSION_ID", help="Resume a previous session")
    parser.add_argument("--budget", type=float, default=10.0, help="Cost budget limit (default: $10)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--show-browser", action="store_true", help="Show browser UI in real-time (for XSS testing demo)")
    parser.add_argument("--demo", action="store_true", help="Run a mocked demo assessment (no API keys needed)")
    args = parser.parse_args()
    
    # Demo mode — standalone replay, no config needed
    if args.demo:
        from numasec.demo import run_demo
        await run_demo()
        return
    
    # Phase 5: Setup structured logging
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
        print("\nDisconnected. Stay safe.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Sync entry point wrapper for console script."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        # Final catch for Ctrl-C
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
