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
        raise RuntimeError(
            "No orm-jwt cookie found in the local browser.\n"
            "    Log in at https://learning.oreilly.com in Chrome or Firefox, then retry."
        )
    return cookies

def main():
    cookies = get_oreilly_cookies()
    with open(COOKIES_FILE, "w") as f:
        json.dump(cookies, f)
    print(f"Cookies saved to {COOKIES_FILE}")

if __name__ == "__main__":
    main()