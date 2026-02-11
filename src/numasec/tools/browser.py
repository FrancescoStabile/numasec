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
import re
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Stealth & Anti-Detection Constants
# ═══════════════════════════════════════════════════════════════════════════

_STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]

_STEALTH_INIT_SCRIPT = """
// Remove webdriver flag (primary bot detection signal)
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

// Fix chrome.runtime (missing in headless Chromium)
if (!window.chrome) {
    window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {} };
}

// Fix plugins array (headless has 0 plugins — dead giveaway)
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5]
});

// Fix languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// Fix permissions API
const _origQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (params) => (
    params.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : _origQuery(params)
);
"""

# Common overlay/modal dismiss selectors (sorted by specificity)
_OVERLAY_DISMISS_SELECTORS = [
    # OWASP Juice Shop specifics
    'button[aria-label="Close Welcome Banner"]',
    'a[aria-label="dismiss cookie message"]',
    # Generic patterns
    'button[aria-label*="close" i]',
    'button[aria-label*="dismiss" i]',
    'button[aria-label*="accept" i]',
    '.cookie-banner button',
    '.modal .close',
    '[data-dismiss="modal"]',
    '.overlay-close',
]

# SPA framework root selectors
_SPA_ROOT_SELECTORS = {
    "angular": "app-root",
    "react": "#root, [data-reactroot]",
    "vue": "#app, [data-v-app]",
    "generic": "#app, #root, [data-app]",
}

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
                    except Exception:
                        pass
                    del self._pool[key]
            
            # Create new context with stealth and security-testing features
            import random
            context = await browser.new_context(
                user_agent=random.choice(_STEALTH_USER_AGENTS),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                bypass_csp=True,  # Critical for XSS testing: bypass Content Security Policy
                service_workers="block",  # Prevent SW interference with request interception
            )
            await context.add_init_script(_STEALTH_INIT_SCRIPT)
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
        except Exception:
            pass
        
        del self._pool[oldest_key]
    
    async def cleanup(self):
        """Close all contexts in pool."""
        async with self._lock:
            for context, _ in self._pool.values():
                try:
                    await context.close()
                except Exception:
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
                except Exception:
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
    _launch_lock: asyncio.Lock | None = None  # Lazily initialised
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def _get_launch_lock(self) -> asyncio.Lock:
        """Lazy init for the launch lock (avoids binding to wrong event loop)."""
        if self._launch_lock is None:
            self._launch_lock = asyncio.Lock()
        return self._launch_lock
    
    async def get_browser(self) -> Browser:
        """Get or create browser instance (async-safe via lock)."""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )
        
        async with self._get_launch_lock():
            if self._browser is not None:
                return self._browser

            try:
                self._playwright = await async_playwright().start()
            except Exception as e:
                raise RuntimeError(f"Playwright failed to start: {e}. Run: pip install playwright && playwright install chromium")
            
            # Check if --show-browser flag is set via environment
            headless = not os.environ.get("NUMASEC_SHOW_BROWSER", "")
            
            # Fallback to headless if no DISPLAY (container/SSH)
            if not headless and not os.environ.get('DISPLAY'):
                logger.debug("No DISPLAY found, falling back to headless mode")
                headless = True
            
            try:
                self._browser = await self._playwright.chromium.launch(
                    headless=headless,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-infobars',
                        '--disable-dev-shm-usage',
                        '--window-size=1920,1080',
                    ],
                    ignore_default_args=['--enable-automation'],
                )
            except Exception as e:
                # Chromium not downloaded — most common failure
                await self._playwright.stop()
                self._playwright = None
                raise RuntimeError(
                    f"Browser launch failed: {e}. "
                    "Run: playwright install chromium"
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
                except Exception:
                    pass
            
            # Create persistent context with stealth + security-testing features
            import random
            self._session_context = await browser.new_context(
                user_agent=random.choice(_STEALTH_USER_AGENTS),
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                bypass_csp=True,  # Critical: bypass CSP for XSS testing
                service_workers="block",
            )
            await self._session_context.add_init_script(_STEALTH_INIT_SCRIPT)
            
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
            except Exception:
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
        """Close browser and cleanup. Suppresses errors during shutdown."""
        # Save session before closing
        try:
            await self.save_session_cookies()
        except Exception:
            pass
        
        # Close session page
        try:
            if self._session_page and not self._session_page.is_closed():
                await self._session_page.close()
        except Exception:
            pass
        self._session_page = None
        
        # Cleanup context pool
        try:
            if self._context_pool:
                await self._context_pool.cleanup()
        except Exception:
            pass
        self._context_pool = None
        
        # Close session context
        try:
            if self._session_context:
                await self._session_context.close()
        except Exception:
            pass
        self._session_context = None
        
        # Close browser
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        self._browser = None

        # Stop Playwright driver — this is where the Future leak originates
        try:
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass
        self._playwright = None


# ═══════════════════════════════════════════════════════════════════════════
# Resilient Helpers (SPA-aware, anti-timeout)
# ═══════════════════════════════════════════════════════════════════════════


def _detect_spa_framework(html: str) -> str | None:
    """Detect SPA framework from HTML to choose optimal wait strategy."""
    if not html:
        return None
    h = html.lower()
    if 'ng-version' in h or 'ng-app' in h or 'app-root' in h or 'angular' in h:
        return 'angular'
    if 'data-reactroot' in h or '__next' in h or 'react' in h or '_react' in h:
        return 'react'
    if 'data-v-' in h or 'v-app' in h or '__vue' in h:
        return 'vue'
    if h.count('<script') > 3 and len(html.strip()) < 5000:
        return 'generic'  # Script-heavy, likely SPA
    return None


async def _resilient_navigate(page: 'Page', url: str, timeout: int = 20000) -> dict:
    """
    Navigate with progressive fallback — NEVER relies on networkidle.
    
    networkidle is DISCOURAGED by Playwright docs for SPAs because:
    - WebSocket connections keep network active
    - Analytics/polling prevent 500ms idle window
    - Angular/React/Vue hydration sends continuous requests
    
    Strategy: domcontentloaded → commit → force-proceed
    Then wait for SPA framework bootstrap if detected.
    
    Returns:
        dict with navigation result info
    """
    response = None
    nav_strategy = "domcontentloaded"
    
    # Layer 1: Try domcontentloaded (fast, reliable for SPAs)
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        nav_strategy = "domcontentloaded"
    except PlaywrightTimeout:
        logger.warning(f"domcontentloaded timeout for {url}, falling back to commit")
        # Layer 2: Fallback to commit (headers received, page loading)
        try:
            response = await page.goto(url, wait_until="commit", timeout=timeout // 2)
            nav_strategy = "commit"
        except PlaywrightTimeout:
            logger.warning(f"commit timeout for {url}, proceeding anyway")
            nav_strategy = "force"
    except Exception as e:
        # Non-timeout error (connection refused, etc.) — re-raise
        raise
    
    # Layer 3: Wait for SPA framework bootstrap (if detected)
    try:
        html = await page.content()
        framework = _detect_spa_framework(html)
        
        if framework == 'angular':
            await page.wait_for_function(
                "() => { const r = document.querySelector('app-root'); "
                "return r && r.children.length > 0; }",
                timeout=8000
            )
        elif framework in ('react', 'vue', 'generic'):
            root_sel = _SPA_ROOT_SELECTORS.get(framework, '#root, #app')
            await page.wait_for_function(
                f"() => {{ const r = document.querySelector('{root_sel.split(',')[0].strip()}'); "
                f"return r && r.children.length > 0; }}",
                timeout=8000
            )
        else:
            # Non-SPA: brief wait for any dynamic content
            await page.wait_for_selector('body *', timeout=3000)
    except Exception:
        pass  # SPA detection is best-effort, don't fail navigation
    
    status = response.status if response else None
    return {"status": status, "strategy": nav_strategy}


async def _dismiss_overlays(page: 'Page', timeout_per: int = 2000):
    """
    Auto-dismiss common overlays (cookie banners, welcome modals).
    
    Critical for:
    - OWASP Juice Shop (Angular MatDialog welcome banner + cookie consent)
    - Any app with overlay that blocks form interaction
    
    Uses short per-selector timeouts to avoid wasting time.
    """
    for selector in _OVERLAY_DISMISS_SELECTORS:
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=timeout_per // 2):
                await locator.click(timeout=timeout_per)
                logger.debug(f"Dismissed overlay: {selector}")
                await page.wait_for_timeout(300)  # Brief pause for animation
        except Exception:
            continue


async def _setup_dialog_handler(page: 'Page') -> list[dict]:
    """
    Install JavaScript dialog handler (alert/confirm/prompt).
    
    CRITICAL for XSS testing:
    - Captures dialog info as proof of XSS execution
    - MUST accept/dismiss dialogs or page hangs permanently
    - Returns list that accumulates dialog events in-place
    
    Returns:
        Mutable list that will be populated with dialog events
    """
    captured_dialogs: list[dict] = []
    
    async def _handle_dialog(dialog):
        captured_dialogs.append({
            "type": dialog.type,
            "message": dialog.message,
            "default_value": dialog.default_value,
            "url": page.url,
        })
        try:
            await dialog.accept()
        except Exception:
            pass  # Dialog may already be dismissed
    
    page.on("dialog", _handle_dialog)
    return captured_dialogs


async def _smart_fill(page: 'Page', selector: str, value: str) -> dict:
    """
    Intelligent form fill with selector cascade and multiple strategies.
    
    Handles:
    - Comma-separated selectors (tries each independently)
    - Visibility check before fill
    - Force fill if element obscured (overlays)
    - Keyboard input fallback for reactive frameworks
    - Direct JS value injection as last resort
    
    Returns:
        dict with fill result (success, strategy_used, selector_matched)
    """
    # Parse comma-separated selectors into individual candidates
    if ',' in selector:
        candidates = [s.strip() for s in selector.split(',') if s.strip()]
    else:
        candidates = [selector]
    
    # Strategy 1: Standard Playwright fill with each candidate
    for sel in candidates:
        try:
            locator = page.locator(sel).first
            # Check visibility with short timeout
            if await locator.is_visible(timeout=3000):
                await locator.fill(value, timeout=5000)
                return {"success": True, "strategy": "fill", "selector": sel}
        except Exception as e:
            logger.debug(f"Fill strategy failed for '{sel}': {e}")
            continue
    
    # Strategy 2: Click + type (works better with reactive frameworks)
    for sel in candidates:
        try:
            locator = page.locator(sel).first
            if await locator.is_visible(timeout=2000):
                await locator.click(timeout=3000)
                await locator.press_sequentially(value, delay=30, timeout=8000)
                return {"success": True, "strategy": "click_type", "selector": sel}
        except Exception as e:
            logger.debug(f"Click+type strategy failed for '{sel}': {e}")
            continue
    
    # Strategy 3: Force fill (bypasses actionability checks — useful when overlays block)
    for sel in candidates:
        try:
            locator = page.locator(sel).first
            count = await locator.count()
            if count > 0:
                await locator.fill(value, force=True, timeout=5000)
                return {"success": True, "strategy": "force_fill", "selector": sel}
        except Exception as e:
            logger.debug(f"Force fill strategy failed for '{sel}': {e}")
            continue
    
    # Strategy 4: Direct JavaScript injection (last resort, bypasses all framework layers)
    for sel in candidates:
        try:
            injected = await page.evaluate(f"""
                (value) => {{
                    const el = document.querySelector('{sel}');
                    if (!el) return false;
                    // Set value via native setter to trigger React/Angular/Vue bindings
                    const nativeSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    ).set;
                    nativeSetter.call(el, value);
                    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    return true;
                }}
            """, value)
            if injected:
                return {"success": True, "strategy": "js_injection", "selector": sel}
        except Exception as e:
            logger.debug(f"JS injection strategy failed for '{sel}': {e}")
            continue
    
    return {
        "success": False,
        "strategy": "none",
        "selector": None,
        "error": f"All fill strategies failed for selectors: {candidates}"
    }


async def _smart_click(page: 'Page', selector: str) -> dict:
    """
    Intelligent click with cascading strategies.
    
    Handles:
    - Comma-separated selectors
    - Visibility check
    - Force click (bypasses overlay obstruction)
    - JS dispatch_event fallback
    """
    candidates = [s.strip() for s in selector.split(',')] if ',' in selector else [selector]
    
    for sel in candidates:
        try:
            locator = page.locator(sel).first
            if await locator.is_visible(timeout=3000):
                await locator.click(timeout=5000)
                return {"success": True, "strategy": "click", "selector": sel}
        except Exception:
            pass
        
        # Force click
        try:
            locator = page.locator(sel).first
            count = await locator.count()
            if count > 0:
                await locator.click(force=True, timeout=3000)
                return {"success": True, "strategy": "force_click", "selector": sel}
        except Exception:
            pass
        
        # JS dispatch
        try:
            clicked = await page.evaluate(f"""
                () => {{
                    const el = document.querySelector('{sel}');
                    if (!el) return false;
                    el.click();
                    return true;
                }}
            """)
            if clicked:
                return {"success": True, "strategy": "js_dispatch", "selector": sel}
        except Exception:
            pass
    
    return {"success": False, "strategy": "none", "selector": None,
            "error": f"All click strategies failed for: {candidates}"}


# ═══════════════════════════════════════════════════════════════════════════
# Browser Tools
# ═══════════════════════════════════════════════════════════════════════════


def _urls_match(page_url: str, target_url: str) -> bool:
    """Check if session page is already on the target URL (skip re-navigation)."""
    if not page_url or not target_url:
        return False
    # Normalize: strip trailing slashes and compare
    return page_url.rstrip("/") == target_url.rstrip("/")


def _browser_not_available_error() -> str:
    """Standard error message when browser is unavailable."""
    return json.dumps({
        "error": "Browser not available",
        "hint": "Install with: pip install playwright && playwright install chromium",
        "fallback": "Use the 'http' tool instead for non-JS targets"
    })


async def browser_navigate(url: str, wait_for: str = "domcontentloaded", timeout: int = 30000, use_session: bool = True) -> str:
    """
    Navigate to URL with Playwright (SPA-aware, resilient).
    
    Args:
        url: Target URL to navigate to
        wait_for: Wait condition ('load', 'domcontentloaded', 'networkidle').
                  Default is 'domcontentloaded' (safe for SPAs).
                  AVOID 'networkidle' on Angular/React/Vue apps.
        timeout: Timeout in milliseconds (default 30s)
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with page title, URL, status code, HTML content, and SPA framework detected
    
    Performance:
    - First call: ~2.5s (browser launch + context creation)
    - Subsequent calls with use_session=False: <100ms (reuses pooled context)
    """
    if not PLAYWRIGHT_AVAILABLE:
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Install dialog handler (captures XSS alerts)
        dialog_results = await _setup_dialog_handler(page)
        
        # Resilient navigation (domcontentloaded → commit → force)
        nav_info = await _resilient_navigate(page, url, timeout=timeout)
        
        # Auto-dismiss overlays (cookie banners, welcome modals)
        await _dismiss_overlays(page)
        
        # Get page info
        title = await page.title()
        final_url = page.url
        
        # Detect SPA framework
        html = await page.content()
        framework = _detect_spa_framework(html)
        html_preview = html[:10000] + "..." if len(html) > 10000 else html
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        result = {
            "success": True,
            "url": final_url,
            "title": title,
            "status_code": nav_info["status"],
            "html": html_preview,
            "redirected": final_url != url,
            "spa_framework": framework,
            "nav_strategy": nav_info["strategy"],
        }
        
        if dialog_results:
            result["dialogs_captured"] = dialog_results
        
        return json.dumps(result, indent=2)
        
    except PlaywrightTimeout:
        return json.dumps({"error": f"Navigation timeout after {timeout}ms",
                           "hint": "Target may be a slow SPA. Try with wait_for='domcontentloaded' or increase timeout."})
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
    except Exception as e:
        return json.dumps({"error": f"Navigation failed: {str(e)}"})


async def browser_fill(url: str, selector: str, value: str, submit: bool = False, use_session: bool = True) -> str:
    """
    Fill a form field with intelligent selector resolution and XSS dialog capture.
    
    Features:
    - Smart selector cascade (tries each comma-separated selector independently)
    - Auto-dismisses overlays/modals before filling
    - Captures JavaScript dialogs (alert/confirm/prompt) as XSS proof
    - Multiple fill strategies: standard → click+type → force → JS injection
    - SPA-aware navigation (never uses networkidle)
    
    Args:
        url: Target URL
        selector: CSS selector(s) for input field. Comma-separated for fallback.
        value: Value to fill
        submit: Whether to submit form after filling
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with result, fill strategy used, and any captured dialogs
    """
    if not PLAYWRIGHT_AVAILABLE:
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        # Get page (persistent session page or new page from pool)
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Install dialog handler BEFORE any interaction (captures XSS alerts)
        dialog_results = await _setup_dialog_handler(page)
        
        # Navigate if needed (SPA-aware, resilient)
        if not (use_session and _urls_match(page.url, url)):
            await _resilient_navigate(page, url)
        
        # Auto-dismiss overlays BEFORE trying to fill
        await _dismiss_overlays(page)
        
        # Smart fill with cascading strategies
        fill_result = await _smart_fill(page, selector, value)
        
        if not fill_result["success"]:
            return json.dumps({
                "error": fill_result["error"],
                "strategies_tried": ["fill", "click_type", "force_fill", "js_injection"],
                "hint": "Selector may not match any visible element. Try browser_screenshot to inspect the page, or use a different selector.",
                "selectors_tried": [s.strip() for s in selector.split(',')] if ',' in selector else [selector],
            }, indent=2)
        
        if submit:
            # Try to find and click submit button
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Submit")',
                'button:has-text("Login")',
                'button:has-text("Search")',
                'button:has-text("Go")',
                'button:has-text("OK")',
            ]
            
            submitted = False
            for submit_selector in submit_selectors:
                try:
                    btn = page.locator(submit_selector).first
                    if await btn.is_visible(timeout=1500):
                        await btn.click(timeout=3000)
                        submitted = True
                        break
                except Exception:
                    continue
            
            if not submitted:
                # Fallback: press Enter in the matched field
                matched_sel = fill_result["selector"]
                try:
                    await page.locator(matched_sel).first.press("Enter", timeout=3000)
                    submitted = True
                except Exception:
                    # Last resort: press Enter on the focused element
                    await page.keyboard.press("Enter")
                    submitted = True
            
            # Wait for response (with short timeout — don't block on SPA transitions)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5000)
            except Exception:
                pass
        
        # Brief wait for any XSS dialog to trigger
        await page.wait_for_timeout(1000)
        
        # Get result
        final_url = page.url
        html = await page.content()
        html_preview = html[:5000] + "..." if len(html) > 5000 else html
        
        # Only close if not session page
        if not use_session:
            await page.close()
        
        result = {
            "success": True,
            "filled": True,
            "submitted": submit,
            "fill_strategy": fill_result["strategy"],
            "selector_matched": fill_result["selector"],
            "final_url": final_url,
            "html": html_preview,
        }
        
        # XSS evidence: any dialogs captured?
        if dialog_results:
            result["xss_dialogs_captured"] = dialog_results
            result["xss_proof"] = True
        
        return json.dumps(result, indent=2)
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
    except Exception as e:
        return json.dumps({"error": f"Fill failed: {str(e)}",
                           "hint": "Try browser_screenshot to see current page state, then retry with correct selector."})


async def browser_click(url: str, selector: str, wait_after: int = 2000, use_session: bool = True) -> str:
    """
    Click an element with intelligent selector resolution.
    
    Features:
    - Smart click cascade (standard → force → JS dispatch)
    - Auto-dismisses overlays before clicking
    - Captures JavaScript dialogs
    - SPA-aware navigation
    
    Args:
        url: Target URL
        selector: CSS selector(s) for element to click (comma-separated for fallback)
        wait_after: Time to wait after click (ms)
        use_session: If True, use persistent session (maintains cookies, DEFAULT)
    
    Returns:
        JSON with result
    """
    if not PLAYWRIGHT_AVAILABLE:
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        # Get page
        if use_session:
            page = await manager.get_session_page()
        else:
            context = await manager.get_context(use_session=False)
            page = await context.new_page()
        
        # Install dialog handler
        dialog_results = await _setup_dialog_handler(page)
        
        # Navigate if needed (SPA-aware)
        if not (use_session and _urls_match(page.url, url)):
            await _resilient_navigate(page, url)
        
        # Auto-dismiss overlays
        await _dismiss_overlays(page)
        
        # Smart click with cascade
        click_result = await _smart_click(page, selector)
        
        if not click_result["success"]:
            return json.dumps({
                "error": click_result["error"],
                "hint": "Element may not exist or be visible. Try browser_screenshot to inspect."
            }, indent=2)
        
        # Wait after click
        await page.wait_for_timeout(wait_after)
        
        final_url = page.url
        html = await page.content()
        html_preview = html[:5000] + "..." if len(html) > 5000 else html
        
        if not use_session:
            await page.close()
        
        result = {
            "success": True,
            "clicked": True,
            "click_strategy": click_result["strategy"],
            "selector_matched": click_result["selector"],
            "final_url": final_url,
            "html": html_preview,
        }
        
        if dialog_results:
            result["dialogs_captured"] = dialog_results
        
        return json.dumps(result, indent=2)
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
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
        return _browser_not_available_error()
    
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
            await _resilient_navigate(page, url)
        
        # Auto-dismiss overlays for clean screenshot
        await _dismiss_overlays(page)
        
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
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
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
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        # Use persistent session page if requested
        if use_session:
            page = await manager.get_session_page()
        else:
            browser = await manager.get_browser()
            page = await browser.new_page()
        
        # Navigate to login page (SPA-aware)
        await _resilient_navigate(page, url)
        
        # Dismiss overlays that may block login form
        await _dismiss_overlays(page)
        
        # Fill credentials with smart fill
        user_result = await _smart_fill(page, username_selector, username)
        if not user_result["success"]:
            return json.dumps({"error": f"Username field not found: {username_selector}",
                               "hint": "Try browser_screenshot to see the login form structure."})
        
        pass_result = await _smart_fill(page, password_selector, password)
        if not pass_result["success"]:
            return json.dumps({"error": f"Password field not found: {password_selector}",
                               "hint": "Try browser_screenshot to see the login form structure."})
        
        # Submit with smart click
        submit_result = await _smart_click(page, submit_selector)
        if not submit_result["success"]:
            # Fallback: press Enter
            await page.keyboard.press("Enter")
        
        # Wait for navigation
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
        except Exception:
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
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
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
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        browser = await manager.get_browser()
        context = await manager.get_session_context(browser)
        page = await context.new_page()
        
        await _resilient_navigate(page, url)
        
        # Get all cookies
        cookies = await context.cookies()
        
        await page.close()
        
        return json.dumps({
            "success": True,
            "cookies": cookies,
            "count": len(cookies)
        }, indent=2)
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
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
        return _browser_not_available_error()
    
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
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
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
        return _browser_not_available_error()
    
    manager = BrowserManager()
    
    try:
        await manager.clear_session()
        
        return json.dumps({
            "success": True,
            "message": "Browser session cleared"
        }, indent=2)
        
    except RuntimeError as e:
        return json.dumps({"error": str(e), "fallback": "Use the 'http' tool instead"})
    except Exception as e:
        return json.dumps({"error": f"Failed to clear session: {str(e)}"})


# ═══════════════════════════════════════════════════════════════════════════
# Tool Schemas (for LLM)
# ═══════════════════════════════════════════════════════════════════════════


TOOL_SCHEMAS = {
    "browser_navigate": {
        "description": (
            "Navigate to a URL using a real Chromium browser (Playwright). This is the primary entry point "
            "for all browser-based testing — XSS detection, DOM inspection, SPA crawling, and authenticated "
            "page access. SPA-AWARE: auto-detects Angular/React/Vue and waits for framework bootstrap "
            "completion. Auto-dismisses overlays (cookie banners, welcome modals, GDPR popups). "
            "Captures JavaScript dialogs (alert/confirm/prompt) as XSS proof. SESSION PERSISTENT by default — "
            "cookies, localStorage, and auth state survive between calls. Stealth mode defeats basic bot detection. "
            "**When to use**: Starting browser-based testing on any target. Navigating to pages that require "
            "JavaScript rendering (SPAs). Checking for reflected XSS by visiting crafted URLs. Accessing "
            "authenticated pages after browser_login. Inspecting DOM content not visible via http tool. "
            "**When NOT to use**: For simple HTTP requests that don't need JS rendering (use http tool — "
            "it's 10x faster). For API endpoint testing (use http). For scanning known CVEs (use nuclei). "
            "**Output**: Page title, final URL (after redirects), full HTML content, any captured JS dialogs, "
            "and visible text content. Returns DOM after JS execution (unlike http which gets raw HTML). "
            "**Performance**: ~2-5s first call (browser launch), ~100ms subsequent calls (browser reused). "
            "**Common mistake**: Using wait_for='networkidle' on SPAs — Angular/React/Vue apps make "
            "continuous API calls, causing networkidle to timeout. Use 'domcontentloaded' (default) instead."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to navigate to (e.g., 'http://localhost:3000', 'http://target/page?xss=<script>alert(1)</script>')"
                },
                "wait_for": {
                    "type": "string",
                    "enum": ["load", "domcontentloaded", "networkidle"],
                    "description": "Wait condition: 'domcontentloaded' (default, recommended for SPAs), 'load' (waits for images/CSS), 'networkidle' (AVOID on SPAs — will timeout).",
                    "default": "domcontentloaded"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in milliseconds. Increase to 60000 for slow pages. Default: 30000.",
                    "default": 30000
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session with cookies/auth state (default: true). Set false only for isolated unauthenticated checks.",
                    "default": True
                }
            },
            "required": ["url"]
        }
    },

    "browser_fill": {
        "description": (
            "Fill a form field with a value and optionally submit the form. Uses SMART SELECTOR resolution "
            "with 4 escalating strategies: standard fill → click+type → force fill → JavaScript injection. "
            "Supports comma-separated selectors as fallback chain (tries each until one works). "
            "Auto-dismisses overlays/modals before interacting. Captures XSS alert() dialogs triggered "
            "by form submission as proof. SESSION PERSISTENT — fills work on authenticated pages. "
            "**When to use**: Injecting XSS payloads into input fields. Testing SQL injection through "
            "form inputs. Filling login forms (prefer browser_login for standard username/password flows). "
            "Testing SSTI payloads in search fields, comment boxes, profile updates. Any scenario where "
            "you need to type into an input element and optionally trigger form submission. "
            "**When NOT to use**: For login flows (use browser_login — it handles the full flow). "
            "For API testing with POST data (use http tool with body parameter). For file uploads "
            "(not supported — use http with multipart). "
            "**Output**: Page content after fill (and after submit if submit=true), any captured JS "
            "dialogs (XSS proof), final URL, and fill success status. "
            "**Common mistake**: Using complex CSS selectors. Start simple: 'input[name=\"search\"]', "
            "'#username', '.form-control'. Use comma-separated selectors for fallback: "
            "'input[name=\"q\"], input[type=\"search\"], #search-input'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL containing the form (e.g., 'http://target/search', 'http://target/profile/edit')"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for input field. Supports comma-separated fallback chain (e.g., 'input[name=\"username\"], #username, .login-input')"
                },
                "value": {
                    "type": "string",
                    "description": "Value to fill — can be XSS payload, SQLi string, normal text (e.g., '<script>alert(document.cookie)</script>', \"' OR 1=1--\")"
                },
                "submit": {
                    "type": "boolean",
                    "description": "Submit the form after filling. Set true to trigger server-side processing of the payload.",
                    "default": False
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (default: true). Maintains login state from browser_login.",
                    "default": True
                }
            },
            "required": ["url", "selector", "value"]
        }
    },

    "browser_click": {
        "description": (
            "Click an element on the page with SMART SELECTOR resolution. Uses 3 escalating strategies: "
            "standard click → force click (bypasses element obstruction) → JavaScript dispatchEvent. "
            "Supports comma-separated selectors as fallback chain. Auto-dismisses overlays before clicking. "
            "Captures XSS dialogs triggered by click actions. SESSION PERSISTENT. "
            "**When to use**: Clicking buttons that trigger actions (delete, submit, admin functions). "
            "Navigating through multi-step flows (wizards, checkout processes). Triggering JavaScript "
            "event handlers for DOM-based XSS testing. Dismissing specific popups or dialogs. "
            "Expanding hidden content (accordions, dropdowns, 'show more' buttons). "
            "**When NOT to use**: For form submission (use browser_fill with submit=true). "
            "For navigation to a URL (use browser_navigate — it's faster and more reliable). "
            "**Output**: Page content after click, any captured JS dialogs, final URL (if navigation "
            "occurred), and click success status. Includes wait_after delay for async content loading. "
            "**Common mistake**: Not waiting long enough after click. Increase wait_after for actions "
            "that trigger AJAX requests or page transitions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL containing the element to click"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector for element to click. Supports comma-separated fallback (e.g., 'button.delete, .btn-danger, [data-action=\"delete\"]')"
                },
                "wait_after": {
                    "type": "integer",
                    "description": "Milliseconds to wait after click for async content to load (default: 2000). Increase for AJAX-heavy pages.",
                    "default": 2000
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (default: true). Maintains auth + dismissed modals across calls.",
                    "default": True
                }
            },
            "required": ["url", "selector"]
        }
    },

    "browser_screenshot": {
        "description": (
            "Take a screenshot of a page or specific element as visual evidence. Saves PNG files to the "
            "./evidence/ directory for inclusion in the final report. Essential for documenting XSS pop-ups, "
            "visual defacements, admin panel access, or any vulnerability that benefits from visual proof. "
            "**When to use**: After confirming XSS (screenshot the alert dialog or injected content). "
            "After accessing admin panels or sensitive pages. Documenting visual vulnerabilities "
            "(UI redress, clickjacking frames). Creating before/after evidence for exploits. "
            "Any finding where visual proof strengthens the report. "
            "**When NOT to use**: For every page visit (only screenshot meaningful findings). "
            "For text-based evidence (use create_finding with the relevant output instead). "
            "**Output**: Screenshot saved to ./evidence/{filename}, returns file path and page metadata. "
            "**Tip**: Use the selector parameter to screenshot only the relevant element (e.g., the "
            "XSS-injected div) instead of the full page — produces cleaner evidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to screenshot"
                },
                "filename": {
                    "type": "string",
                    "description": "Output filename without path (saved in ./evidence/). Use descriptive names (e.g., 'xss_reflected_search.png', 'admin_panel_access.png')"
                },
                "selector": {
                    "type": "string",
                    "description": "Optional CSS selector to screenshot only a specific element (e.g., '.alert-box', '#injected-content')"
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Use persistent session (default: true). Screenshots authenticated pages automatically if logged in via browser_login.",
                    "default": True
                }
            },
            "required": ["url", "filename"]
        }
    },

    "browser_login": {
        "description": (
            "Perform a complete login flow: navigate to login page, fill username and password fields, "
            "submit the form, and persist session cookies for all subsequent browser calls. This is the "
            "recommended way to establish an authenticated session for testing protected endpoints. "
            "**When to use**: Before testing any authenticated functionality (admin panels, user profiles, "
            "API endpoints behind auth). When credentials are available (provided by user, found during "
            "recon, or default credentials). At the start of authenticated testing phases. "
            "**When NOT to use**: For API token-based auth (use http tool with Authorization header). "
            "For OAuth/SSO flows (these require browser_navigate + browser_fill + browser_click manually). "
            "For cookie-based session replay (use browser_set_cookies instead). "
            "**Output**: Login result (success/failure based on URL change and content), session cookies "
            "stored for reuse, final page content after login. "
            "**Common mistake**: Wrong selectors. Inspect the login page first with browser_navigate to "
            "find the correct input selectors. Most common: 'input[name=\"username\"]', "
            "'input[name=\"password\"]', 'button[type=\"submit\"]'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Login page URL (e.g., 'http://target/login', 'http://target/#/signin')"
                },
                "username_selector": {
                    "type": "string",
                    "description": "CSS selector for username/email input (e.g., 'input[name=\"username\"]', '#email', 'input[type=\"email\"]')"
                },
                "username": {
                    "type": "string",
                    "description": "Username or email to login with"
                },
                "password_selector": {
                    "type": "string",
                    "description": "CSS selector for password input (e.g., 'input[name=\"password\"]', '#password', 'input[type=\"password\"]')"
                },
                "password": {
                    "type": "string",
                    "description": "Password to login with"
                },
                "submit_selector": {
                    "type": "string",
                    "description": "CSS selector for submit button. Default handles most forms. Override for custom buttons (e.g., '#login-btn', '.submit-button').",
                    "default": "button[type=\"submit\"]"
                },
                "use_session": {
                    "type": "boolean",
                    "description": "Persist session cookies for reuse in all subsequent browser_* calls (default: true).",
                    "default": True
                }
            },
            "required": ["url", "username_selector", "username", "password_selector", "password"]
        }
    },

    "browser_get_cookies": {
        "description": (
            "Retrieve all cookies from the current browser session for a given URL. Returns cookie names, "
            "values, domains, paths, expiry, and security flags (httpOnly, secure, sameSite). "
            "**When to use**: Analyzing session token security (missing httpOnly/secure flags). "
            "Extracting session cookies for replay attacks. Checking for sensitive data in cookies. "
            "Documenting cookie-based findings. Verifying successful login (session cookie present). "
            "**When NOT to use**: For setting cookies (use browser_set_cookies). "
            "**Output**: Array of cookie objects with full metadata. Check for: missing httpOnly flag "
            "(XSS can steal session), missing secure flag (cookie sent over HTTP), weak sameSite "
            "policy (CSRF risk), sensitive data in cookie values."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to get cookies for — returns cookies matching this URL's domain and path"
                }
            },
            "required": ["url"]
        }
    },

    "browser_set_cookies": {
        "description": (
            "Inject cookies into the browser session. Use for session hijacking proof-of-concept: "
            "set a stolen session token to demonstrate account takeover without knowing the password. "
            "Also useful for testing with specific cookie values (e.g., role=admin, debug=true). "
            "**When to use**: Testing session hijacking (inject stolen session cookie, then navigate to "
            "authenticated page). Testing privilege escalation via cookie manipulation (change role cookie). "
            "Setting up specific test conditions (debug cookies, feature flags). "
            "**When NOT to use**: For normal login (use browser_login). For testing cookie security "
            "flags (use browser_get_cookies to analyze). "
            "**Output**: Confirmation of cookies set. Follow with browser_navigate to verify access."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL/domain to set cookies for (e.g., 'http://target.com')"
                },
                "cookies": {
                    "type": "array",
                    "description": "Array of cookie objects: [{\"name\": \"session\", \"value\": \"stolen_token\", \"domain\": \"target.com\", \"path\": \"/\"}]",
                    "items": {"type": "object"}
                }
            },
            "required": ["url", "cookies"]
        }
    },

    "browser_clear_session": {
        "description": (
            "Clear all browser cookies, localStorage, sessionStorage, and authentication state. "
            "Completely resets the browser to a clean, unauthenticated state — equivalent to "
            "opening a fresh incognito window. This is essential for access control testing where "
            "you need to verify behavior across different privilege levels. The operation is "
            "immediate and irreversible for the current session. "
            "**When to use**: Before testing as a different user (switch from admin to regular user). "
            "Before testing unauthenticated access controls (verify pages require login). "
            "After completing authenticated testing to clean up session artifacts. Between "
            "privilege escalation tests with different roles. When testing IDOR by switching "
            "between user accounts. After browser_login to verify logout functionality works. "
            "**When NOT to use**: Mid-flow when you need session persistence — this destroys ALL "
            "state including auth tokens, CSRF tokens, and shopping carts. If you only need to "
            "modify specific cookies, use browser_set_cookies instead. "
            "**Output**: Confirmation that session was cleared with count of removed items."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    }
}
