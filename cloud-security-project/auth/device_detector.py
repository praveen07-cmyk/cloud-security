"""
device_detector.py
------------------------------------------------
Lightweight, pure-Python User-Agent parser for security auditing.
Extracts browser name, version, operating system, device type, and device name.
No external C dependencies required; safe, fast, and offline.
"""

import re


def parse_user_agent(ua_string):
    """
    Parses a User-Agent header string and returns a dictionary with:
    - browser
    - browser_version
    - operating_system
    - device_type (Desktop, Mobile, Tablet, Unknown)
    - device_name
    """
    if not ua_string or not isinstance(ua_string, str):
        return {
            "browser": "Unknown",
            "browser_version": None,
            "operating_system": "Unknown",
            "device_type": "Unknown",
            "device_name": "Unknown",
        }

    ua = ua_string.strip()

    # 1. Operating System Detection
    os_name = "Unknown"
    device_name = "Unknown"

    if "Windows Phone" in ua:
        os_name = "Windows Phone"
        device_name = "Windows Phone"
    elif "Windows" in ua:
        if "Windows NT 10.0" in ua:
            os_name = "Windows 10/11"
        elif "Windows NT 6.3" in ua:
            os_name = "Windows 8.1"
        elif "Windows NT 6.2" in ua:
            os_name = "Windows 8"
        elif "Windows NT 6.1" in ua:
            os_name = "Windows 7"
        else:
            os_name = "Windows"
        device_name = "Windows PC"
    elif "Android" in ua:
        os_name = "Android"
        android_ver_match = re.search(r"Android\s+([\d\.]+)", ua)
        if android_ver_match:
            os_name = f"Android {android_ver_match.group(1)}"
        device_name = "Android Device"
    elif "iPad" in ua or ("Macintosh" in ua and "Touch" in ua):
        os_name = "iPadOS"
        device_name = "iPad"
    elif "iPhone" in ua:
        os_name = "iOS"
        ios_ver_match = re.search(r"OS\s+([\d_]+)\s+like\s+Mac", ua)
        if ios_ver_match:
            os_name = f"iOS {ios_ver_match.group(1).replace('_', '.')}"
        device_name = "iPhone"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name = "macOS"
        mac_ver_match = re.search(r"Mac OS X\s+([\d_\.]+)", ua)
        if mac_ver_match:
            os_name = f"macOS {mac_ver_match.group(1).replace('_', '.')}"
        device_name = "Mac"
    elif "CrOS" in ua:
        os_name = "ChromeOS"
        device_name = "Chromebook"
    elif "Linux" in ua:
        os_name = "Linux"
        if "Ubuntu" in ua:
            os_name = "Ubuntu Linux"
        elif "Debian" in ua:
            os_name = "Debian Linux"
        elif "Fedora" in ua:
            os_name = "Fedora Linux"
        device_name = "Linux PC"
    elif "PostmanRuntime" in ua:
        os_name = "API Client Environment"
        device_name = "Postman"
    elif "curl" in ua.lower():
        os_name = "CLI"
        device_name = "cURL Client"
    elif "python-requests" in ua.lower() or "pytest" in ua.lower():
        os_name = "Automated Agent"
        device_name = "Python Test Runner"

    # 2. Device Type Categorization
    device_type = "Desktop"
    if any(k in ua for k in ["Mobile", "iPhone", "Android", "Windows Phone"]) and "Tablet" not in ua and "iPad" not in ua:
        device_type = "Mobile"
    elif any(k in ua for k in ["Tablet", "iPad"]) or ("Android" in ua and "Mobile" not in ua):
        device_type = "Tablet"
    elif os_name in ["Unknown", "CLI", "Automated Agent"]:
        device_type = "Unknown"

    # 3. Browser Detection
    browser = "Unknown"
    browser_version = None

    if "PostmanRuntime" in ua:
        browser = "Postman"
        ver_match = re.search(r"PostmanRuntime/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "curl" in ua.lower():
        browser = "cURL"
        ver_match = re.search(r"curl/([\d\.]+)", ua, re.IGNORECASE)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "pytest" in ua.lower() or "python-requests" in ua.lower() or "werkzeug" in ua.lower():
        browser = "Automated Test Client"
    elif "Edg/" in ua or "Edge/" in ua:
        browser = "Microsoft Edge"
        ver_match = re.search(r"Edg(?:e)?/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
        ver_match = re.search(r"(?:OPR|Opera)/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "Chrome/" in ua and "Chromium/" not in ua:
        browser = "Google Chrome"
        ver_match = re.search(r"Chrome/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "Firefox/" in ua:
        browser = "Mozilla Firefox"
        ver_match = re.search(r"Firefox/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Apple Safari"
        ver_match = re.search(r"Version/([\d\.]+)", ua)
        if ver_match:
            browser_version = ver_match.group(1)
    elif "MSIE" in ua or "Trident/" in ua:
        browser = "Internet Explorer"

    return {
        "browser": browser,
        "browser_version": browser_version,
        "operating_system": os_name,
        "device_type": device_type,
        "device_name": device_name,
    }
