"""
NumaSec v3 - Browser Tool (Playwright)

Headless browser automation for:
- XSS testing (reflected, stored, DOM-based)
- CSRF testing
- Form interaction
- JavaScript-heavy apps
- Screenshot evidence collection

Supports --show-browser flag for real-time visual demo.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None
    Page = None
    BrowserContext = None


# ═══════════════════════════════════════════════════════════════════════════
# Browser Context Pool (Phase 3: Performance Optimization)
# ═══════════════════════════════════════════════════════════════════════════


class BrowserContextPool:
    """
    Pool of browser contexts with TTL for performance optimization.
    
    Reduces overhead from ~2.5s per call to <100ms by reusing contexts.
    Contexts expire after TTL and are automatically cleaned up.
    """
    
    def __init__(self, ttl_minutes: int = 10, max_contexts: int = 3):
        self._pool: dict[str, tuple[BrowserContext, datetime]] = {}
        self._ttl = timedelta(minutes=ttl_minutes)
        self._max_contexts = max_contexts
        self._lock = asyncio.Lock()
    
    async def get_context(self, browser: Browser, key: str = "default") -> BrowserContext:
        """
        Get or create context from pool.
        
        Args:
            browser: Browser instance
            key: Context key (use different keys for different sessions)
        
        Returns:
            BrowserContext ready to use
        """
        async with self._lock:
            # Check if exists and not expired
            if key in self._pool:
                context, created_at = self._pool[key]
                age = datetime.now() - created_at
                
                if age < self._ttl:
                    # Context still valid, reuse it
                    return context
                else:
                    # Expired, close and remove
                    try:
                        await context.close()
                    except:
                        pass
                    del self._pool[key]
            
            # Create new context
            context = await browser.new_context(
                user_agent="NumaSec/2.0 (Security Scanner)"
            )
            self._pool[key] = (context, datetime.now())
            
            # Enforce max contexts limit (LRU-style)
            if len(self._pool) > self._max_contexts:
                await self._evict_oldest()
            
            return context
    
    async def _evict_oldest(self):
        """Evict oldest context from pool."""
        if not self._pool:
            return
        
        # Find oldest
        oldest_key = min(self._pool.keys(), key=lambda k: self._pool[k][1])
        oldest_context, _ = self._pool[oldest_key]
        
        try:
            await oldest_context.close()
        except:
            pass
        
        del self._pool[oldest_key]
    
    async def cleanup(self):
        """Close all contexts in pool."""
        async with self._lock:
            for context, _ in self._pool.values():
                try:
                    await context.close()
                except:
                    pass
            self._pool.clear()
    
    async def cleanup_expired(self):
        """Remove expired contexts from pool."""
        async with self._lock:
            now = datetime.now()
            expired = [
                key for key, (_, created_at) in self._pool.items()
                if now - created_at >= self._ttl
            ]
            
            for key in expired:
                context, _ = self._pool[key]
                try:
                    await context.close()
                except:
                    pass
                del self._pool[key]


# ═══════════════════════════════════════════════════════════════════════════
# Browser Manager with Session Persistence + Performance Pool
# ═══════════════════════════════════════════════════════════════════════════


class BrowserManager:
    """
    Singleton manager for persistent browser with session persistence + context pooling.
    
    Features:
    - Single browser instance reused across calls
    - Context pooling with TTL (reduces overhead from 2.5s to <100ms)
    - Persistent session context with automatic cookie save/load
    - Cookie storage in ./evidence/browser_sessions/cookies.json
    - Session clearing for testing as unauthenticated user
    
    Performance:
    - First call: ~2.5s (browser launch + context creation)
    - Subsequent calls: <100ms (reuses pooled context)
    - Context TTL: 10 minutes
    """
    
    _instance: Optional['BrowserManager'] = None
    _browser: Optional[Browser] = None
    _playwright = None
    _session_context = None  # Persistent context for session
    _session_page: Optional[Page] = None  # NEW: Persistent page for session continuity
    _context_pool: Optional[BrowserContextPool] = None  # Context pool for performance
    _session_cookies_file = Path("./evidence/browser_sessions/cookies.json")
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    async def get_browser(self) -> Browser:
        """Get or create browser instance."""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")
        
        if self._browser is None:
            self._playwright = await async_playwright().start()
            
            # Check if --show-browser flag is set via environment
            headless = not os.environ.get("NUMASEC_SHOW_BROWSER", "")
            
            # Fallback to headless if no DISPLAY (container/SSH)
            if not headless and not os.environ.get('DISPLAY'):
                logger.debug("No DISPLAY found, falling back to headless mode")
                headless = True
            
            self._browser = await self._playwright.chromium.launch(
                headless=headless,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            # Initialize context pool with browser
            self._context_pool = BrowserContextPool(ttl_minutes=10, max_contexts=3)
        
        return self._browser
    
    async def get_context(self, use_session: bool = False, key: str = "default") -> BrowserContext:
        """
        Get browser context - either from pool (fast) or session (persistent).
        
        Args:
            use_session: If True, use persistent session context with cookies
            key: Pool key for non-session contexts (allows multiple isolated contexts)
        
        Returns:
            BrowserContext ready to use
        
        Performance:
        - use_session=False (pooled): <100ms after first call
        - use_session=True (persistent): ~500ms but maintains cookies
        """
        browser = await self.get_browser()
        
        if use_session:
            return await self.get_session_context(browser)
        else:
            # Use context pool for non-session (FAST)
            return await self._context_pool.get_context(browser, key)
    
    async def get_session_context(self, browser: Browser):
        """
        Get or create persistent session context with saved cookies.
        This allows maintaining login state across multiple browser calls.
        """
        if self._session_context is None:
            # Create session directory
            self._session_cookies_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Load saved cookies if exist
            cookies = []
            if self._session_cookies_file.exists():
                try:
                    cookies = json.loads(self._session_cookies_file.read_text())
                except:
                    pass
            
            # Create persistent context
            self._session_context = await browser.new_context()
            
            # Apply saved cookies
            if cookies:
                await self._session_context.add_cookies(cookies)
        
        return self._session_context
    
    async def get_session_page(self) -> Page:
        """
        Get or create persistent session page.
        
        This maintains state across calls:
        - Cookies persist
        - Local storage persists
        - Navigation history persists
        - Modal dismissals persist (e.g., OWASP Juice Shop welcome dialog)
        
        Returns:
            Page instance ready to use
        """
        browser = await self.get_browser()
        context = await self.get_session_context(browser)
        
        if self._session_page is None or self._session_page.is_closed():
            self._session_page = await context.new_page()
        
        return self._session_page
    
    async def save_session_cookies(self):
        """Save current session cookies to disk."""
        if self._session_context:
            try:
                cookies = await self._session_context.cookies()
                self._session_cookies_file.parent.mkdir(parents=True, exist_ok=True)
                self._session_cookies_file.write_text(json.dumps(cookies, indent=2))
            except:
                pass
    
    async def clear_session(self):
        """Clear session context, page, and cookies."""
        if self._session_page and not self._session_page.is_closed():
            await self._session_page.close()
            self._session_page = None
        
        if self._session_context:
            await self._session_context.close()
            self._session_context = None
        
        if self._session_cookies_file.exists():
            self._session_cookies_file.unlink()
    
    async def close(self):
        """Close browser and cleanup."""
        # Save session before closing
        await self.save_session_cookies()
        
        # Close session page
        if self._session_page and not self._session_page.is_closed():
            await self._session_page.close()
            self._session_page = None
        
        # Cleanup context pool
        if self._context_pool:
            await self._context_pool.cleanup()
            self._context_pool = None
        
        if self._session_context:
            await self._session_context.close()
            self._session_context = None
        
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None


# ═══════════════════════════════════════════════════════════════════════════
# Browser Tools
# ═══════════════════════════════════════════════════════════════════════════


def _urls_match(page_url: str, target_url: str) -> bool:
    """Check if session page is already on the target URL (skip re-navigation)."""
    if not page_url or not target_url:
        return False
    # Normalize: strip trailing slashes and compare
    return page_url.rstrip("/") == target_url.rstrip("/")


async def browser_navigate(url: str, wait_for: str = "networkidle", timeout: int = 30000, use_session: bool = True) -> str:
    """
    Navigate to URL with Playwright.
    
    Args:
        url: Target URL to navigate to
        wait_for: Wait condition ('load', 'domcontentloaded', 'networkidle')
        timeout: Timeout in milliseconds (default 30s)
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with page title, URL, status code, and HTML content
    
    Performance:
    - First call: ~2.5s (browser launch + context creation)
    - Subsequent calls with use_session=False: <100ms (reuses pooled context)
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"})
    
    manager = BrowserManager()
    
    try:
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Navigate
        response = await page.goto(url, wait_until=wait_for, timeout=timeout)
        
        # Get page info
        title = await page.title()
        final_url = page.url
        status = response.status if response else None
        
        # Get HTML content (limit to 10KB for LLM context)
        html = await page.content()
        html_preview = html[:10000] + "..." if len(html) > 10000 else html
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        return json.dumps({
            "success": True,
            "url": final_url,
            "title": title,
            "status_code": status,
            "html": html_preview,
            "redirected": final_url != url
        }, indent=2)
        
    except PlaywrightTimeout:
        return json.dumps({"error": f"Navigation timeout after {timeout}ms"})
    except Exception as e:
        return json.dumps({"error": f"Navigation failed: {str(e)}"})


async def browser_fill(url: str, selector: str, value: str, submit: bool = False, use_session: bool = True) -> str:
    """
    Fill a form field and optionally submit.
    
    Args:
        url: Target URL
        selector: CSS selector for input field
        value: Value to fill
        submit: Whether to submit form after filling
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with result and response
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Skip navigation if session page is already on target URL
        if not (use_session and _urls_match(page.url, url)):
            await page.goto(url, wait_until="networkidle", timeout=30000)
        
        # Fill field
        await page.fill(selector, value)
        
        if submit:
            # Try to find and click submit button
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Submit")',
                'button:has-text("Login")',
                'button:has-text("Search")'
            ]
            
            submitted = False
            for submit_selector in submit_selectors:
                try:
                    await page.click(submit_selector, timeout=2000)
                    submitted = True
                    break
                except:
                    continue
            
            if not submitted:
                # Fallback: press Enter in the field
                await page.press(selector, "Enter")
            
            # Wait for navigation or response
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except:
                pass
        
        # Get result
        final_url = page.url
        html = await page.content()
        html_preview = html[:5000] + "..." if len(html) > 5000 else html
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        return json.dumps({
            "success": True,
            "filled": True,
            "submitted": submit,
            "final_url": final_url,
            "html": html_preview
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Fill failed: {str(e)}"})


async def browser_click(url: str, selector: str, wait_after: int = 2000, use_session: bool = True) -> str:
    """
    Click an element on the page.
    
    Args:
        url: Target URL
        selector: CSS selector for element to click
        wait_after: Time to wait after click (ms)
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with result
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Skip navigation if session page is already on target URL
        if not (use_session and _urls_match(page.url, url)):
            await page.goto(url, wait_until="networkidle", timeout=30000)
        await page.click(selector)
        await page.wait_for_timeout(wait_after)
        
        final_url = page.url
        html = await page.content()
        html_preview = html[:5000] + "..." if len(html) > 5000 else html
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        return json.dumps({
            "success": True,
            "clicked": True,
            "final_url": final_url,
            "html": html_preview
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Click failed: {str(e)}"})


async def browser_screenshot(url: str, filename: str, selector: Optional[str] = None, use_session: bool = True) -> str:
    """
    Take screenshot as evidence.
    
    Args:
        url: Target URL
        filename: Output filename (will be saved in ./evidence/)
        selector: Optional CSS selector to screenshot specific element
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with screenshot path
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        # Create evidence directory
        evidence_dir = Path("./evidence")
        evidence_dir.mkdir(exist_ok=True)
        
        filepath = evidence_dir / filename
        if not filepath.suffix:
            filepath = filepath.with_suffix('.png')
        
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Skip navigation if session page is already on target URL
        if not (use_session and _urls_match(page.url, url)):
            await page.goto(url, wait_until="networkidle", timeout=30000)
        
        if selector:
            element = await page.query_selector(selector)
            if element:
                await element.screenshot(path=str(filepath))
            else:
                return json.dumps({"error": f"Selector not found: {selector}"})
        else:
            await page.screenshot(path=str(filepath), full_page=True)
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        return json.dumps({
            "success": True,
            "screenshot": str(filepath),
            "size_kb": filepath.stat().st_size / 1024
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Screenshot failed: {str(e)}"})


async def browser_login(
    url: str,
    username_selector: str,
    username: str,
    password_selector: str,
    password: str,
    submit_selector: str = 'button[type="submit"]',
    use_session: bool = True
) -> str:
    """
    Login to site and save session (cookies) for subsequent requests.
    
    Args:
        url: Login page URL
        username_selector: CSS selector for username input
        username: Username to enter
        password_selector: CSS selector for password input
        password: Password to enter
        submit_selector: CSS selector for submit button
        use_session: Whether to save session for reuse (default True)
    
    Returns:
        JSON with login result and session status
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        # Use persistent session page if requested
        if use_session:
            page = await manager.get_session_page()
        else:
            browser = await manager.get_browser()
            page = await browser.new_page()
        
        # Navigate to login page
        await page.goto(url, wait_until="networkidle", timeout=30000)
        
        # Fill credentials
        await page.fill(username_selector, username)
        await page.fill(password_selector, password)
        
        # Submit
        await page.click(submit_selector)
        
        # Wait for navigation
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except:
            pass
        
        final_url = page.url
        
        # Save session cookies if using session
        if use_session:
            await manager.save_session_cookies()
        
        # Check if login succeeded (heuristic)
        success_indicators = [
            final_url != url,  # Redirected
            "dashboard" in final_url.lower(),
            "profile" in final_url.lower(),
            "logout" in await page.content(),
        ]
        
        login_success = any(success_indicators)
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        return json.dumps({
            "success": login_success,
            "final_url": final_url,
            "session_saved": use_session,
            "message": "Login successful - session saved" if login_success and use_session else "Login may have failed"
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Login failed: {str(e)}"})


async def browser_get_cookies(url: str) -> str:
    """
    Get all cookies from current session.
    Useful for cookie stealing, session fixation tests.
    
    Args:
        url: URL to get cookies from (determines scope)
    
    Returns:
        JSON with cookie list
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        browser = await manager.get_browser()
        context = await manager.get_session_context(browser)
        page = await context.new_page()
        
        await page.goto(url, wait_until="networkidle", timeout=30000)
        
        # Get all cookies
        cookies = await context.cookies()
        
        await page.close()
        
        return json.dumps({
            "success": True,
            "cookies": cookies,
            "count": len(cookies)
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Failed to get cookies: {str(e)}"})


async def browser_set_cookies(url: str, cookies: list[dict]) -> str:
    """
    Set cookies in session (for session hijacking tests).
    
    Args:
        url: URL to set cookies for
        cookies: List of cookie dicts with name, value, domain, path
    
    Returns:
        JSON with result
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        browser = await manager.get_browser()
        context = await manager.get_session_context(browser)
        
        # Add cookies to context
        await context.add_cookies(cookies)
        await manager.save_session_cookies()
        
        return json.dumps({
            "success": True,
            "cookies_set": len(cookies),
            "message": "Cookies set in session"
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Failed to set cookies: {str(e)}"})


async def browser_clear_session() -> str:
    """
    Clear browser session (logout, clear cookies).
    Use when you need to test as unauthenticated user.
    
    Returns:
        JSON with result
    """
    if not PLAYWRIGHT_AVAILABLE:
        return json.dumps({"error": "Playwright not installed"})
    
    manager = BrowserManager()
    
    try:
        await manager.clear_session()
        
        return json.dumps({
            "success": True,
            "message": "Browser session cleared"
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Failed to clear session: {str(e)}"})


# ═══════════════════════════════════════════════════════════════════════════
# Tool Schemas (for LLM)
# ═══════════════════════════════════════════════════════════════════════════


TOOL_SCHEMAS = {
    "browser_navigate": {
        "description": "Navigate to URL with browser (Playwright). Use for JavaScript-heavy apps, XSS testing, or when you need to see rendered page. SESSION PERSISTENT by default (modals stay dismissed, cookies maintained). FAST: ~100ms after first call.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to navigate to"
                },
                "wait_for": {
                    "type": "string",
                    "enum": ["load", "domcontentloaded", "networkidle"],
                    "description": "Wait condition (default: networkidle)",
                    "default": "networkidle"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in milliseconds (default: 30000)",
                    "default": 30000
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (DEFAULT=True). Set False only for isolated one-off checks.",
                    "default": True
                }
            },
            "required": ["url"]
        }
    },
    
    "browser_fill": {
        "description": "Fill form field and optionally submit. SESSION PERSISTENT by default (stays on same page, maintains state). Use for login forms, search boxes, or testing XSS in input fields.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for input field (e.g., 'input[name=\"username\"]', '#search')"
                },
                "value": {
                    "type": "string",
                    "description": "Value to fill in the field"
                },
                "submit": {
                    "type": "boolean",
                    "description": "Whether to submit the form after filling",
                    "default": False
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (DEFAULT=True). Already logged in? Session is maintained automatically.",
                    "default": True
                }
            },
            "required": ["url", "selector", "value"]
        }
    },
    
    "browser_click": {
        "description": "Click an element on the page. SESSION PERSISTENT by default (great for dismissing modals, navigating within same session). Use for clicking buttons, links, or testing clickjacking.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for element to click"
                },
                "wait_after": {
                    "type": "integer",
                    "description": "Time to wait after click in milliseconds (default: 2000)",
                    "default": 2000
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (DEFAULT=True). Modal dismissed? It stays dismissed!",
                    "default": True
                }
            },
            "required": ["url", "selector"]
        }
    },
    
    "browser_screenshot": {
        "description": "Take screenshot as evidence. Use to document XSS, visual vulnerabilities, or proof of exploitation.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "filename": {
                    "type": "string",
                    "description": "Output filename (saved in ./evidence/)"
                },
                "selector": {
                    "type": "string",
                    "description": "Optional CSS selector to screenshot specific element only"
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (DEFAULT=True). Screenshots authenticated pages automatically if already logged in.",
                    "default": True
                }
            },
            "required": ["url", "filename"]
        }
    },
    
    "browser_login": {
        "description": "Login to site and save session cookies for authenticated testing. Use when you need to test features that require login.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Login page URL"
                },
                "username_selector": {
                    "type": "string",
                    "description": "CSS selector for username input (e.g., 'input[name=\"username\"]')"
                },
                "username": {
                    "type": "string",
                    "description": "Username to login with"
                },
                "password_selector": {
                    "type": "string",
                    "description": "CSS selector for password input"
                },
                "password": {
                    "type": "string",
                    "description": "Password to login with"
                },
                "submit_selector": {
                    "type": "string",
                    "description": "CSS selector for submit button (default: 'button[type=\"submit\"]')",
                    "default": "button[type=\"submit\"]"
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Save session cookies for reuse (default: true)",
                    "default": True
                }
            },
            "required": ["url", "username_selector", "username", "password_selector", "password"]
        }
    },
    
    "browser_get_cookies": {
        "description": "Get all cookies from current session. Use for cookie stealing, session analysis.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to get cookies from"
                }
            },
            "required": ["url"]
        }
    },
    
    "browser_set_cookies": {
        "description": "Set cookies in session (for session hijacking tests). Use to test with stolen cookies.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to set cookies for"
                },
                "cookies": {
                    "type": "array",
                    "description": "List of cookie objects with name, value, domain, path",
                    "items": {"type": "object"}
                }
            },
            "required": ["url", "cookies"]
        }
    },
    
    "browser_clear_session": {
        "description": "Clear browser session and cookies. Use when you need to test as unauthenticated user.",
        "parameters": {
            "type": "object",
            "properties": {}
        }
    }
}
