"""
Browser Fallback Detection - Phase 2

Detects when http tool result warrants browser retry.
"""

import json
import re


def detect_javascript_spa(html: str) -> bool:
    """
    Detect if page is JavaScript-heavy SPA that needs browser rendering.
    
    Indicators:
    - React/Vue/Angular frameworks detected
    - Minimal HTML with large script tags
    - No actual content, just loading scripts
    """
    if not html or len(html) < 100:
        return False
    
    html_lower = html.lower()
    
    # SPA framework indicators
    spa_indicators = [
        # React
        'react' in html_lower and '<div id="root"' in html_lower,
        'react' in html_lower and 'data-reactroot' in html_lower,
        
        # Vue
        'vue' in html_lower and '<div id="app"' in html_lower,
        'vue' in html_lower and 'v-app' in html_lower,
        
        # Angular
        'angular' in html_lower and 'ng-app' in html_lower,
        'angular' in html_lower and 'ng-version' in html_lower,
        
        # Generic: lots of scripts, little content
        html_lower.count('<script') > 5 and len(html.strip()) < 5000,
        
        # Empty body with only root div
        '<body' in html_lower and html_lower.count('<div') == 1 and 'root' in html_lower,
    ]
    
    return any(spa_indicators)


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
        if status == 200 and detect_javascript_spa(body):
            return True, """
The http response suggests this is a JavaScript-heavy Single Page Application (SPA).
The actual content is likely rendered client-side and not visible in the raw HTTP response.

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
