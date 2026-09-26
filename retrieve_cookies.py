import json

# See: https://github.com/lorenzodifuccia/safaribooks/issues/358

try:
    from safaribooks import COOKIES_FILE
except ImportError:
    COOKIES_FILE = "cookies.json"

def get_oreilly_cookies():
    from safaribooks import load_browser_oreilly_cookies

    cookies = load_browser_oreilly_cookies()
    if cookies is None:
        raise ImportError(
            "browser_cookie3 is not installed for this interpreter.\n"
            "    .venv/bin/python -m pip install -r requirements.txt\n"
            "    .venv/bin/python retrieve_cookies.py"
        )
    if not cookies.get("orm-jwt"):
        report = "\n".join("    %s" % line for line in load_browser_oreilly_cookies.report)
        detail = ("\n" + report) if report else ""
        raise RuntimeError(
            "No orm-jwt cookie found for this user.%s\n"
            "    The browser that is logged in has to be on this same machine and user."
            % detail
        )
    return cookies

def main():
    cookies = get_oreilly_cookies()
    with open(COOKIES_FILE, "w") as f:
        json.dump(cookies, f)
    print(f"Cookies saved to {COOKIES_FILE}")

if __name__ == "__main__":
    main()