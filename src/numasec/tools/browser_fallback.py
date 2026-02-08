"""
Browser Fallback Detection - Phase 2 (Enhanced)

Detects when http tool result warrants browser retry.
Includes SPA framework detection and selector suggestions.
"""

import json
import re


# ═══════════════════════════════════════════════════════════════════════════
# SPA Framework Detection (Enhanced)
# ═══════════════════════════════════════════════════════════════════════════


def detect_javascript_spa(html: str) -> dict:
    """
    Detect if page is JavaScript-heavy SPA that needs browser rendering.
    
    Returns:
        dict with: is_spa (bool), framework (str|None), confidence (float),
                   wait_strategy (str), indicators (list[str])
    """
    result = {
        "is_spa": False,
        "framework": None,
        "confidence": 0.0,
        "wait_strategy": "domcontentloaded",
        "indicators": [],
    }
    
    if not html or len(html) < 100:
        return result
    
    html_lower = html.lower()
    score = 0.0
    
    # Angular detection
    angular_signals = [
        ('ng-version' in html_lower, 0.9, "ng-version attribute found"),
        ('ng-app' in html_lower, 0.8, "ng-app attribute found"),
        ('app-root' in html_lower, 0.7, "app-root element found"),
        ('angular' in html_lower and '<script' in html_lower, 0.5, "Angular scripts detected"),
        ('zone.js' in html_lower, 0.8, "Zone.js (Angular runtime) detected"),
        ('polyfills' in html_lower and 'runtime' in html_lower, 0.6, "Angular build chunks detected"),
    ]
    for condition, weight, desc in angular_signals:
        if condition:
            score = max(score, weight)
            result["indicators"].append(desc)
            result["framework"] = "angular"
    
    # React detection
    react_signals = [
        ('data-reactroot' in html_lower, 0.9, "data-reactroot found"),
        ('__next' in html_lower, 0.9, "Next.js detected"),
        ('<div id="root"' in html_lower and 'react' in html_lower, 0.8, "React root + react scripts"),
        ('_react' in html_lower, 0.7, "React fiber internals detected"),
        ('react-dom' in html_lower, 0.6, "react-dom script detected"),
    ]
    if not result["framework"]:  # Only if Angular not already detected
        for condition, weight, desc in react_signals:
            if condition:
                score = max(score, weight)
                result["indicators"].append(desc)
                result["framework"] = "react"
    
    # Vue detection
    vue_signals = [
        ('data-v-' in html_lower, 0.9, "Vue scoped style attributes found"),
        ('<div id="app"' in html_lower and 'vue' in html_lower, 0.8, "Vue app root + vue scripts"),
        ('v-app' in html_lower, 0.8, "Vuetify v-app found"),
        ('__vue' in html_lower, 0.7, "Vue internals detected"),
    ]
    if not result["framework"]:
        for condition, weight, desc in vue_signals:
            if condition:
                score = max(score, weight)
                result["indicators"].append(desc)
                result["framework"] = "vue"
    
    # Generic SPA signals (no specific framework)
    generic_signals = [
        (html_lower.count('<script') > 5 and len(html.strip()) < 5000, 0.6,
         "Heavy scripts with minimal HTML (likely SPA)"),
        ('<body' in html_lower and html_lower.count('<div') <= 2 and '<script' in html_lower, 0.5,
         "Near-empty body with scripts (client-side rendered)"),
        ('webpack' in html_lower or 'chunk' in html_lower, 0.4,
         "Webpack/bundled assets detected"),
        ('manifest.json' in html_lower and 'service-worker' in html_lower, 0.5,
         "PWA manifest + service worker detected"),
    ]
    if not result["framework"]:
        for condition, weight, desc in generic_signals:
            if condition:
                score = max(score, weight)
                result["indicators"].append(desc)
                result["framework"] = "generic"
    
    result["confidence"] = score
    result["is_spa"] = score >= 0.4
    
    # Wait strategy recommendation
    if result["is_spa"]:
        result["wait_strategy"] = "domcontentloaded"  # NEVER networkidle for SPAs
    
    return result


def should_retry_with_browser(tool_name: str, tool_args: dict, result: str) -> tuple[bool, str]:
    """
    Determine if tool result warrants browser retry.
    
    Args:
        tool_name: Name of tool that executed
        tool_args: Arguments passed to tool
        result: Tool result string
    
    Returns:
        (should_retry: bool, reason: str)
    """
    # Only suggest browser for http tool
    if tool_name != "http":
        return False, ""
    
    try:
        result_json = json.loads(result)
        
        # Extract response details
        status = result_json.get('status_code', 200)
        body = result_json.get('body', result_json.get('text', result_json.get('html', '')))
        url = tool_args.get('url', '')
        
        # Case 1: 200 OK but SPA detected
        spa_info = detect_javascript_spa(body)
        if status == 200 and spa_info["is_spa"]:
            framework = spa_info["framework"] or "unknown"
            indicators = ", ".join(spa_info["indicators"][:3])
            return True, f"""
The http response is a **{framework.upper()} SPA** (confidence: {spa_info['confidence']:.0%}).
Indicators: {indicators}

The actual content is rendered client-side and not visible in the raw HTTP response.

**CRITICAL:** Do NOT use wait_for='networkidle' — it will TIMEOUT on SPAs.
The browser tools now auto-detect SPAs and use domcontentloaded + framework bootstrap wait.

**Recommended action:**
Use browser_navigate to render JavaScript and see the actual page content.
"""
        
        # Case 2: Very short response (likely client-side rendered)
        if status == 200 and len(body.strip()) < 500:
            # But not if it's clearly an error or redirect
            if 'error' not in body.lower() and '<!doctype' in body.lower():
                return True, """
The HTTP response body is very short for a web page.
This suggests content may be loaded dynamically via JavaScript.

**Recommended action:**
Try browser_navigate to see if additional content loads via JavaScript.
"""
        
        # Case 3: Testing for XSS (should always use browser for proof)
        if '<script>' in url or 'xss' in url.lower():
            return True, """
You're testing for XSS vulnerabilities.

**CRITICAL:** XSS testing REQUIRES visual proof via screenshot.
- http tool can only show if payload is reflected in HTML
- It cannot show if JavaScript actually executes
- Browser screenshot is mandatory evidence

**Recommended action:**
1. Use browser_fill to input XSS payload
2. Use browser_screenshot to capture proof of execution
"""
        
        # Case 4: Form submission (browser may be better)
        if tool_args.get('method', '').upper() == 'POST' and tool_args.get('data'):
            # Check if response looks like it might have client-side validation or JS
            if 'javascript' in body.lower() or '<script' in body.lower():
                return True, """
You submitted a form via http POST, but the response contains JavaScript.
The page may have client-side validation or dynamic behavior.

**Consider:**
Using browser_fill to interact with the form as a real browser would.
This can bypass client-side validation and see actual rendered results.
"""
        
        return False, ""
    
    except json.JSONDecodeError:
        # Not JSON response, might be plain text
        if '<script>' in result or 'xss' in result.lower():
            return True, "XSS testing detected. Use browser tools for visual proof."
        return False, ""
    
    except Exception:
        return False, ""


def format_browser_suggestion(tool_name: str, tool_args: dict, reason: str) -> str:
    """
    Format browser retry suggestion for LLM.
    
    Args:
        tool_name: Tool that was executed
        tool_args: Tool arguments
        reason: Reason for suggesting browser
    
    Returns:
        Formatted suggestion string
    """
    url = tool_args.get('url', 'the target')
    
    suggestion = f"""
[*] Browser Tool Suggestion

The {tool_name} tool completed, but the result suggests browser tools might work better.

{reason}

**Browser tools available:**
- browser_navigate(url) - Render JavaScript and get actual page content
- browser_fill(url, selector, value) - Fill forms and interact with page
- browser_screenshot(url, filename) - Capture visual evidence

**Example:**
```
browser_navigate(url="{url}", wait_for="networkidle")
```

Would you like to retry with browser tools?
"""
    
    return suggestion
