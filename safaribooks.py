#!/usr/bin/env python3
# coding: utf-8
import re
import os
import sys
import glob
import json
import time
import base64
import shutil
import pathlib
import getpass
import logging
import argparse
import requests
import traceback
from html import escape
from random import random
from lxml import html, etree
from multiprocessing import Process, Queue, Value
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus


PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")
# Re-read the browser session before orm-jwt actually expires.
JWT_REFRESH_MARGIN_SECONDS = 10 * 60
# How long to wait for the open O'Reilly tab to write a newer orm-jwt.
JWT_REFRESH_WAIT_SECONDS = 3 * 60


class AuthExpired(Exception):
    """Raised when the O'Reilly session is dead and the browser has no newer cookie."""


def jwt_expiry(token):
    """Return the orm-jwt exp claim as a unix timestamp, or None."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        exp = data.get("exp")
        if isinstance(exp, (int, float)):
            return int(exp)
    except Exception:
        return None
    return None


def load_saved_cookies():
    if not os.path.isfile(COOKIES_FILE):
        return {}
    try:
        with open(COOKIES_FILE) as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if value}
    except (OSError, ValueError):
        return {}
    return {}


_SKIP_WALK = {
    ".git", "venv", ".venv", "node_modules", "Books", "__pycache__",
    "site-packages", ".cache",
}
_COOKIE_FILENAMES = {"Cookies", "cookies.sqlite"}
_MISSING_COOKIE_DB = ("failed to find", "could not find", "cannot find", "can not find")


def _cookie_search_roots():
    roots = []
    home = os.path.expanduser("~")
    if home and home != "~" and os.path.isdir(home):
        roots.append(home)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg and os.path.isdir(xdg) and xdg not in roots:
        roots.append(xdg)
    return roots


def _find_cookie_databases():
    """Find Chromium Cookies and Firefox cookies.sqlite files under the current home.

    Snap, Flatpak, and Network/Cookies layouts are not on browser_cookie3's default
    path list, so a normal login is invisible when only those defaults are tried.
    """
    found = []
    for root in _cookie_search_roots():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in _SKIP_WALK]
            if dirpath[len(root):].count(os.sep) > 8:
                dirnames[:] = []
                continue
            for name in filenames:
                if name not in _COOKIE_FILENAMES:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "rb") as handle:
                        if handle.read(16).startswith(b"SQLite format 3"):
                            found.append(path)
                except OSError:
                    continue
    return list(dict.fromkeys(found))


def _loader_for_cookie_file(browser_cookie3, path):
    low = path.lower()
    if os.path.basename(path) == "cookies.sqlite" or "mozilla" in low or "firefox" in low:
        return browser_cookie3.firefox
    if "brave" in low:
        return browser_cookie3.brave
    if "edge" in low:
        return browser_cookie3.edge
    if "vivaldi" in low:
        return browser_cookie3.vivaldi
    if "chromium" in low and "google-chrome" not in low:
        return browser_cookie3.chromium
    return browser_cookie3.chrome


def _open_cookie_file(browser_cookie3, path):
    primary = _loader_for_cookie_file(browser_cookie3, path)
    fallbacks = [primary]
    if primary is not browser_cookie3.firefox:
        for extra in (browser_cookie3.chrome, browser_cookie3.chromium):
            if extra not in fallbacks:
                fallbacks.append(extra)
    last_error = None
    for loader in fallbacks:
        try:
            return loader(cookie_file=path, domain_name="oreilly.com")
        except Exception as error:
            last_error = error
    raise last_error


def _oreilly_cookies_from_jar(jar):
    cookies = {}
    names = []
    for cookie in jar:
        domain = (getattr(cookie, "domain", "") or "").lower()
        if "oreilly" not in domain or not cookie.value:
            continue
        cookies[cookie.name] = cookie.value
        names.append(cookie.name)
    return cookies, names


def load_browser_oreilly_cookies():
    """Read O'Reilly cookies from the local browser. None if the reader is unavailable.

    Each browser is opened on its own. browser_cookie3.load() aborts on Arc, which
    has no Linux cookie path. Chromium Network/Cookies files are opened explicitly
    because the library's default path still points at the legacy Cookies file.
    """
    try:
        import browser_cookie3
    except ImportError:
        load_browser_oreilly_cookies.missing = True
        load_browser_oreilly_cookies.report = []
        return None

    notes = []
    best = None  # (exp, cookies)
    seen_names = []

    def consider(cookies, names, label):
        nonlocal best
        if names:
            seen_names.append("%s: %s" % (label, ", ".join(sorted(set(names)))))
        token = cookies.get("orm-jwt")
        if not token:
            return
        exp = jwt_expiry(token) or 0
        if best is None or exp >= best[0]:
            best = (exp, cookies)

    for browser in getattr(browser_cookie3, "all_browsers", ()):
        label = getattr(browser, "__name__", "browser")
        try:
            jar = browser(domain_name="oreilly.com")
        except Exception as error:
            text = str(error).lower()
            if any(phrase in text for phrase in _MISSING_COOKIE_DB):
                continue
            notes.append("%s: %s" % (label, error))
            continue
        try:
            cookies, names = _oreilly_cookies_from_jar(jar)
        except Exception as error:
            notes.append("%s: %s" % (label, error))
            continue
        consider(cookies, names, label)

    databases = _find_cookie_databases()
    for path in databases:
        try:
            jar = _open_cookie_file(browser_cookie3, path)
            cookies, names = _oreilly_cookies_from_jar(jar)
        except Exception as error:
            notes.append("%s: %s" % (path, error))
            continue
        if not names:
            notes.append("%s: opened, no O'Reilly cookies" % path)
            continue
        consider(cookies, names, path)

    if not databases and best is None:
        home = os.path.expanduser("~")
        notes.append(
            "no browser cookie database under %s. A login in a browser on another machine is not visible here."
            % home
        )
    load_browser_oreilly_cookies.report = notes + seen_names
    if best is None:
        return {}
    return best[1]


def merge_fresher_cookies(saved, browser_cookies):
    """Prefer whichever orm-jwt expires later. Browser-only cookies fill gaps."""
    if not browser_cookies:
        return dict(saved or {})
    if not saved:
        return dict(browser_cookies)

    saved_exp = jwt_expiry(saved.get("orm-jwt", "")) or 0
    browser_exp = jwt_expiry(browser_cookies.get("orm-jwt", "")) or 0
    if browser_exp >= saved_exp and browser_cookies.get("orm-jwt"):
        merged = dict(saved)
        merged.update(browser_cookies)
        return merged
    return dict(saved)


def persist_cookies(cookies):
    """Write cookies.json. Never replace a live orm-jwt with an empty or older one."""
    fresh = {key: value for key, value in (cookies or {}).items() if value}
    if not fresh.get("orm-jwt"):
        return False

    current = load_saved_cookies()
    current_exp = jwt_expiry(current.get("orm-jwt", "")) or 0
    fresh_exp = jwt_expiry(fresh.get("orm-jwt", "")) or 0
    if current.get("orm-jwt") and fresh_exp and current_exp > fresh_exp:
        return False

    current.update(fresh)
    with open(COOKIES_FILE, "w") as handle:
        json.dump(current, handle)
    return True


_WAITED_FOR_TOKEN = None


def wait_for_browser_jwt(current_token):
    """Poll the browser until it has a different, still-valid orm-jwt.

    The same dead token is only waited on once, so a long queue does not
    pause again for every remaining book.
    """
    global _WAITED_FOR_TOKEN
    if _WAITED_FOR_TOKEN == (current_token or ""):
        return None

    if getattr(load_browser_oreilly_cookies, "missing", False) or (
        load_browser_oreilly_cookies() is None and getattr(load_browser_oreilly_cookies, "missing", False)
    ):
        print("browser_cookie3 is not installed, so cookies cannot be re-read from the browser.")
        print("Install it with: ./venv/bin/pip install browser_cookie3")
        _WAITED_FOR_TOKEN = current_token or ""
        return None

    print(
        "\nSession cookie is about to expire or is already dead.\n"
        "Leave https://learning.oreilly.com open and reload that tab.\n"
        "Waiting up to %d seconds for a new orm-jwt from the browser..."
        % JWT_REFRESH_WAIT_SECONDS
    )
    deadline = time.time() + JWT_REFRESH_WAIT_SECONDS
    while time.time() < deadline:
        browser_cookies = load_browser_oreilly_cookies()
        token = (browser_cookies or {}).get("orm-jwt")
        exp = jwt_expiry(token) if token else None
        if token and token != current_token and exp and exp > time.time() + 30:
            print("Picked up a new orm-jwt from the browser.")
            return browser_cookies
        time.sleep(5)
    print("No new orm-jwt showed up in the browser.")
    _WAITED_FOR_TOKEN = current_token or ""
    return None


ORLY_BASE_HOST = "oreilly.com"  # PLEASE INSERT URL HERE

SAFARI_BASE_HOST = "learning." + ORLY_BASE_HOST
API_ORIGIN_HOST = "api." + ORLY_BASE_HOST

ORLY_BASE_URL = "https://www." + ORLY_BASE_HOST
SAFARI_BASE_URL = "https://" + SAFARI_BASE_HOST
API_ORIGIN_URL = "https://" + API_ORIGIN_HOST
PROFILE_URL = SAFARI_BASE_URL + "/profile/"

# DEBUG
USE_PROXY = False
PROXIES = {"https": "https://127.0.0.1:8080"}


class Display:
    BASE_FORMAT = logging.Formatter(
        fmt="[%(asctime)s] %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S"
    )

    SH_DEFAULT = "\033[0m" if "win" not in sys.platform else ""  # TODO: colors for Windows
    SH_YELLOW = "\033[33m" if "win" not in sys.platform else ""
    SH_BG_RED = "\033[41m" if "win" not in sys.platform else ""
    SH_BG_YELLOW = "\033[43m" if "win" not in sys.platform else ""

    def __init__(self, log_file):
        self.output_dir = ""
        self.output_dir_set = False
        self.log_file = os.path.join(PATH, log_file)

        self.logger = logging.getLogger("SafariBooks")
        self.logger.setLevel(logging.INFO)
        logs_handler = logging.FileHandler(filename=self.log_file)
        logs_handler.setFormatter(self.BASE_FORMAT)
        logs_handler.setLevel(logging.INFO)
        self.logger.addHandler(logs_handler)

        self.columns, _ = shutil.get_terminal_size()

        self.logger.info("** Welcome to SafariBooks! **")

        self.book_ad_info = False
        self.css_ad_info = Value("i", 0)
        self.images_ad_info = Value("i", 0)
        self.last_request = (None,)
        self.in_error = False

        self.state_status = Value("i", 0)
        sys.excepthook = self.unhandled_exception

    def set_output_dir(self, output_dir):
        self.info("Output directory:\n    %s" % output_dir)
        self.output_dir = output_dir
        self.output_dir_set = True

    def unregister(self):
        self.logger.handlers[0].close()
        sys.excepthook = sys.__excepthook__

    def log(self, message):
        try:
            self.logger.info(str(message, "utf-8", "replace"))

        except (UnicodeDecodeError, Exception):
            self.logger.info(message)

    def out(self, put):
        pattern = "\r{!s}\r{!s}\n"
        try:
            s = pattern.format(" " * self.columns, str(put, "utf-8", "replace"))

        except TypeError:
            s = pattern.format(" " * self.columns, put)

        sys.stdout.write(s)

    def info(self, message, state=False):
        self.log(message)
        output = (self.SH_YELLOW + "[*]" + self.SH_DEFAULT if not state else
                  self.SH_BG_YELLOW + "[-]" + self.SH_DEFAULT) + " %s" % message
        self.out(output)

    def error(self, error):
        if not self.in_error:
            self.in_error = True

        self.log(error)
        output = self.SH_BG_RED + "[#]" + self.SH_DEFAULT + " %s" % error
        self.out(output)

    def exit(self, error):
        self.error(str(error))

        if self.output_dir_set:
            output = (self.SH_YELLOW + "[+]" + self.SH_DEFAULT +
                      " Please delete the output directory '" + self.output_dir + "'"
                      " and restart the program.")
            self.out(output)

        output = self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Aborting..."
        self.out(output)

        self.save_last_request()
        sys.exit(1)

    def unhandled_exception(self, _, o, tb):
        self.log("".join(traceback.format_tb(tb)))
        self.exit("Unhandled Exception: %s (type: %s)" % (o, o.__class__.__name__))

    def save_last_request(self):
        if any(self.last_request):
            self.log("Last request done:\n\tURL: {0}\n\tDATA: {1}\n\tOTHERS: {2}\n\n\t{3}\n{4}\n\n{5}\n"
                     .format(*self.last_request))

    def intro(self):
        output = self.SH_YELLOW + (r"""
       ____     ___         _
      / __/__ _/ _/__ _____(_)
     _\ \/ _ `/ _/ _ `/ __/ /
    /___/\_,_/_/ \_,_/_/ /_/
      / _ )___  ___  / /__ ___
     / _  / _ \/ _ \/  '_/(_-<
    /____/\___/\___/_/\_\/___/
""" if random() > 0.5 else r"""
 ██████╗     ██████╗ ██╗  ██╗   ██╗██████╗
██╔═══██╗    ██╔══██╗██║  ╚██╗ ██╔╝╚════██╗
██║   ██║    ██████╔╝██║   ╚████╔╝   ▄███╔╝
██║   ██║    ██╔══██╗██║    ╚██╔╝    ▀▀══╝
╚██████╔╝    ██║  ██║███████╗██║     ██╗
 ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
""") + self.SH_DEFAULT
        output += "\n" + "~" * (self.columns // 2)

        self.out(output)

    def parse_description(self, desc):
        if not desc:
            return "n/d"

        try:
            return html.fromstring(desc).text_content()

        except (html.etree.ParseError, html.etree.ParserError) as e:
            self.log("Error parsing the description: %s" % e)
            return "n/d"

    def book_info(self, info):
        description = self.parse_description(info.get("description", None)).replace("\n", " ")
        for t in [
            ("Title", info.get("title", "")), ("Authors", ", ".join(aut.get("name", "") for aut in info.get("authors", []))),
            ("Identifier", info.get("identifier", "")), ("ISBN", info.get("isbn", "")),
            ("Publishers", ", ".join(pub.get("name", "") for pub in info.get("publishers", []))),
            ("Rights", info.get("rights", "")),
            ("Description", description[:500] + "..." if len(description) >= 500 else description),
            ("Release Date", info.get("issued", "")),
            ("URL", info.get("web_url", ""))
        ]:
            self.info("{0}{1}{2}: {3}".format(self.SH_YELLOW, t[0], self.SH_DEFAULT, t[1]), True)

    def state(self, origin, done):
        progress = int(done * 100 / origin)
        bar = int(progress * (self.columns - 11) / 100)
        if self.state_status.value < progress:
            self.state_status.value = progress
            sys.stdout.write(
                "\r    " + self.SH_BG_YELLOW + "[" + ("#" * bar).ljust(self.columns - 11, "-") + "]" +
                self.SH_DEFAULT + ("%4s" % progress) + "%" + ("\n" if progress == 100 else "")
            )

    def done(self, epub_file):
        self.info("Done: %s\n\n" % epub_file +
                  "    If you like it, please * this project on GitHub to make it known:\n"
                  "        https://github.com/lorenzodifuccia/safaribooks\n"
                  "    e don't forget to renew your Safari Books Online subscription:\n"
                  "        " + SAFARI_BASE_URL + "\n\n" +
                  self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Bye!!")

    @staticmethod
    def api_error(response):
        message = "API: "
        # v1 API used {"detail": "Not found."}, v2 API uses {"message": "Not Found"}
        detail = ""
        if isinstance(response, dict):
            if "detail" in response:
                detail = str(response["detail"])
            elif "message" in response:
                detail = str(response["message"])
        if detail and "not found" in detail.lower():
            message += "book's not present in Safari Books Online.\n" \
                       "    The book identifier is the digits that you can find in the URL:\n" \
                       "    `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`"

        else:
            if detail:
                message += "Out-of-Session (%s).\n" % detail
            else:
                message += "Out-of-Session.\n"
            message += Display.SH_YELLOW + "[+]" + Display.SH_DEFAULT + \
                       " Use the `--cred` or `--login` options in order to perform the auth login to Safari."

        return message


class WinQueue(list):  # TODO: error while use `process` in Windows: can't pickle _thread.RLock objects
    def put(self, el):
        self.append(el)

    def qsize(self):
        return self.__len__()


class SafariBooks:
    LOGIN_URL = ORLY_BASE_URL + "/member/auth/login/"
    LOGIN_ENTRY_URL = SAFARI_BASE_URL + "/login/unified/?next=/home/"

    API_TEMPLATE = SAFARI_BASE_URL + "/api/v1/book/{0}/"
    # v1 /api/v1/book/ is deprecated (returns 404 for all books since ~2026).
    # v2 endpoints (working as of Sep 2026):
    API_V2_EPUB_TEMPLATE = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/"
    API_V2_CHAPTERS_TEMPLATE = SAFARI_BASE_URL + "/api/v2/epub-chapters/?epub_identifier=urn:orm:book:{0}"
    API_V2_TOC_TEMPLATE = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/table-of-contents/"
    API_V1_TALENT_TEMPLATE = SAFARI_BASE_URL + "/api/v1/talent/work/urn:orm:book:{0}"

    BASE_01_HTML = "<!DOCTYPE html>\n" \
                   "<html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"" \
                   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" \
                   " xsi:schemaLocation=\"http://www.w3.org/2002/06/xhtml2/" \
                   " http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd\"" \
                   " xmlns:epub=\"http://www.idpf.org/2007/ops\">\n" \
                   "<head>\n" \
                   "{0}\n" \
                   "<style type=\"text/css\">" \
                   "body{{margin:1em;background-color:transparent!important;}}" \
                   "#sbo-rt-content *{{text-indent:0pt!important;}}#sbo-rt-content .bq{{margin-right:1em!important;}}"

    KINDLE_HTML = "#sbo-rt-content *{{word-wrap:break-word!important;" \
                  "word-break:break-word!important;}}#sbo-rt-content table,#sbo-rt-content pre" \
                  "{{overflow-x:unset!important;overflow:unset!important;" \
                  "overflow-y:unset!important;white-space:pre-wrap!important;}}"

    BASE_02_HTML = "</style>" \
                   "</head>\n" \
                   "<body>{1}</body>\n</html>"

    CONTAINER_XML = "<?xml version=\"1.0\"?>" \
                    "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" \
                    "<rootfiles>" \
                    "<rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\" />" \
                    "</rootfiles>" \
                    "</container>"

    # Format: ID, Title, Authors, Description, Subjects, Publisher, Rights, Date, CoverId, MANIFEST, SPINE, CoverUrl
    CONTENT_OPF = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
                  "<package xmlns=\"http://www.idpf.org/2007/opf\" unique-identifier=\"bookid\" version=\"2.0\" >\n" \
                  "<metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\" " \
                  " xmlns:opf=\"http://www.idpf.org/2007/opf\">\n" \
                  "<dc:title>{1}</dc:title>\n" \
                  "{2}\n" \
                  "<dc:description>{3}</dc:description>\n" \
                  "{4}" \
                  "<dc:publisher>{5}</dc:publisher>\n" \
                  "<dc:rights>{6}</dc:rights>\n" \
                  "<dc:language>en-US</dc:language>\n" \
                  "<dc:date>{7}</dc:date>\n" \
                  "<dc:identifier id=\"bookid\">{0}</dc:identifier>\n" \
                  "<meta name=\"cover\" content=\"{8}\"/>\n" \
                  "</metadata>\n" \
                  "<manifest>\n" \
                  "<item id=\"ncx\" href=\"toc.ncx\" media-type=\"application/x-dtbncx+xml\" />\n" \
                  "{9}\n" \
                  "</manifest>\n" \
                  "<spine toc=\"ncx\">\n{10}</spine>\n" \
                  "<guide><reference href=\"{11}\" title=\"Cover\" type=\"cover\" /></guide>\n" \
                  "</package>"

    # Format: ID, Depth, Title, Author, NAVMAP
    TOC_NCX = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>\n" \
              "<!DOCTYPE ncx PUBLIC \"-//NISO//DTD ncx 2005-1//EN\"" \
              " \"http://www.daisy.org/z3986/2005/ncx-2005-1.dtd\">\n" \
              "<ncx xmlns=\"http://www.daisy.org/z3986/2005/ncx/\" version=\"2005-1\">\n" \
              "<head>\n" \
              "<meta content=\"ID:ISBN:{0}\" name=\"dtb:uid\"/>\n" \
              "<meta content=\"{1}\" name=\"dtb:depth\"/>\n" \
              "<meta content=\"0\" name=\"dtb:totalPageCount\"/>\n" \
              "<meta content=\"0\" name=\"dtb:maxPageNumber\"/>\n" \
              "</head>\n" \
              "<docTitle><text>{2}</text></docTitle>\n" \
              "<docAuthor><text>{3}</text></docAuthor>\n" \
              "<navMap>{4}</navMap>\n" \
              "</ncx>"

    HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Referer": LOGIN_ENTRY_URL,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/90.0.4430.212 Safari/537.36"
    }

    COOKIE_FLOAT_MAX_AGE_PATTERN = re.compile(r'(max-age=\d*\.\d*)', re.IGNORECASE)

    def __init__(self, args):
        self.args = args
        self.display = Display("info_%s.log" % escape(args.bookid))
        self.display.intro()

        self.session = requests.Session()
        if USE_PROXY:  # DEBUG
            self.session.proxies = PROXIES
            self.session.verify = False

        self.session.headers.update(self.HEADERS)

        self.jwt = {}

        if not args.cred:
            cookies = merge_fresher_cookies(load_saved_cookies(), load_browser_oreilly_cookies())
            token = cookies.get("orm-jwt", "")
            exp = jwt_expiry(token) if token else None
            self._browser_refresh_exhausted = False
            if not token or (exp and exp < time.time() + JWT_REFRESH_MARGIN_SECONDS):
                refreshed = wait_for_browser_jwt(token)
                if refreshed:
                    cookies = merge_fresher_cookies(cookies, refreshed)
                    token = cookies.get("orm-jwt", "")
                    exp = jwt_expiry(token) if token else None
                else:
                    self._browser_refresh_exhausted = True
            if not token or (exp and exp <= time.time()):
                self.display.error(
                    "Authentication issue: orm-jwt is missing or expired.\n"
                    "    Reload https://learning.oreilly.com in the browser, then retry."
                )
                raise AuthExpired()
            self.session.cookies.update(cookies)
            if not args.no_cookies:
                persist_cookies(cookies)

        else:
            self.display.info("Logging into Safari Books Online...", state=True)
            self.do_login(*args.cred)
            if not args.no_cookies:
                persist_cookies(self.session.cookies.get_dict())

        self.check_login()

        self.book_id = args.bookid
        self.api_url = self.API_TEMPLATE.format(self.book_id)
        self.api_v2_url = self.API_V2_EPUB_TEMPLATE.format(self.book_id)
        self.api_v2_files_base = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/files".format(self.book_id)

        self.display.info("Retrieving book info...")
        self.book_info = self.get_book_info()
        self.display.book_info(self.book_info)

        self.display.info("Retrieving book chapters...")
        self.book_chapters = self.get_book_chapters()

        self.chapters_queue = self.book_chapters[:]

        if len(self.book_chapters) > sys.getrecursionlimit():
            sys.setrecursionlimit(len(self.book_chapters))

        self.book_title = self.book_info["title"]
        self.base_url = self.book_info["web_url"]

        self.clean_book_title = "".join(self.escape_dirname(self.book_title).split(",")[:2]) \
                                + " ({0})".format(self.book_id)

        books_dir = os.path.join(PATH, "Books")
        if not os.path.isdir(books_dir):
            os.mkdir(books_dir)

        self.BOOK_PATH = os.path.join(books_dir, self.clean_book_title)
        self.display.set_output_dir(self.BOOK_PATH)
        self.css_path = ""
        self.images_path = ""
        self.create_dirs()

        self.chapter_title = ""
        self.filename = ""
        self.chapter_stylesheets = []
        self.css = []
        self.images = []

        self.display.info("Downloading book contents... (%s chapters)" % len(self.book_chapters), state=True)
        self.BASE_HTML = self.BASE_01_HTML + (self.KINDLE_HTML if not args.kindle else "") + self.BASE_02_HTML

        self.cover = False
        self.get()
        if not self.cover:
            self.cover = self.get_default_cover() if "cover" in self.book_info else False
            cover_html = self.parse_html(
                html.fromstring("<div id=\"sbo-rt-content\"><img src=\"Images/{0}\"></div>".format(self.cover)), True
            )

            self.book_chapters = [{
                "filename": "default_cover.xhtml",
                "title": "Cover"
            }] + self.book_chapters

            self.filename = self.book_chapters[0]["filename"]
            self.save_page_html(cover_html)

        self.css_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book CSSs... (%s files)" % len(self.css), state=True)
        self.collect_css()
        self.images_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book images... (%s files)" % len(self.images), state=True)
        self.collect_images()

        self.display.info("Creating EPUB file...", state=True)
        self.create_epub()

        if not args.no_cookies:
            persist_cookies(self.session.cookies.get_dict())

        self.display.done(os.path.join(self.BOOK_PATH, self.book_id + ".epub"))
        self.display.unregister()

        if not self.display.in_error and not args.log:
            os.remove(self.display.log_file)

    def handle_cookie_update(self, set_cookie_headers):
        for morsel in set_cookie_headers:
            # Handle Float 'max-age' Cookie
            if self.COOKIE_FLOAT_MAX_AGE_PATTERN.search(morsel):
                cookie_key, cookie_value = morsel.split(";")[0].split("=")
                self.session.cookies.set(cookie_key, cookie_value)

    def requests_provider(self, url, is_post=False, data=None, perform_redirect=True, **kwargs):
        try:
            response = getattr(self.session, "post" if is_post else "get")(
                url,
                data=data,
                allow_redirects=False,
                **kwargs
            )

            self.handle_cookie_update(response.raw.headers.getlist("Set-Cookie"))

            self.display.last_request = (
                url, data, kwargs, response.status_code, "\n".join(
                    ["\t{}: {}".format(*h) for h in response.headers.items()]
                ), response.text
            )

        except (requests.ConnectionError, requests.ConnectTimeout, requests.RequestException) as request_exception:
            self.display.error(str(request_exception))
            return 0

        if response.is_redirect and perform_redirect:
            return self.requests_provider(response.next.url, is_post, None, perform_redirect)
            # TODO How about **kwargs?

        return response

    @staticmethod
    def parse_cred(cred):
        if ":" not in cred:
            return False

        sep = cred.index(":")
        new_cred = ["", ""]
        new_cred[0] = cred[:sep].strip("'").strip('"')
        if "@" not in new_cred[0]:
            return False

        new_cred[1] = cred[sep + 1:]
        return new_cred

    def do_login(self, email, password):
        response = self.requests_provider(self.LOGIN_ENTRY_URL)
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

        next_parameter = None
        try:
            next_parameter = parse_qs(urlparse(response.request.url).query)["next"][0]

        except (AttributeError, ValueError, IndexError):
            self.display.exit("Login: unable to complete login on Safari Books Online. Try again...")

        redirect_uri = API_ORIGIN_URL + quote_plus(next_parameter)

        response = self.requests_provider(
            self.LOGIN_URL,
            is_post=True,
            json={
                "email": email,
                "password": password,
                "redirect_uri": redirect_uri
            },
            perform_redirect=False
        )

        if response == 0:
            self.display.exit("Login: unable to perform auth to Safari Books Online.\n    Try again...")

        if response.status_code != 200:  # TODO To be reviewed
            try:
                error_page = html.fromstring(response.text)
                errors_message = error_page.xpath("//ul[@class='errorlist']//li/text()")
                recaptcha = error_page.xpath("//div[@class='g-recaptcha']")
                messages = (["    `%s`" % error for error in errors_message
                             if "password" in error or "email" in error] if len(errors_message) else []) + \
                           (["    `ReCaptcha required (wait or do logout from the website).`"] if len(
                               recaptcha) else [])
                self.display.exit(
                    "Login: unable to perform auth login to Safari Books Online.\n" + self.display.SH_YELLOW +
                    "[*]" + self.display.SH_DEFAULT + " Details:\n" + "%s" % "\n".join(
                        messages if len(messages) else ["    Unexpected error!"])
                )
            except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                self.display.error(parsing_error)
                self.display.exit(
                    "Login: your login went wrong and it encountered in an error"
                    " trying to parse the login details of Safari Books Online. Try again..."
                )

        self.jwt = response.json()  # TODO: save JWT Tokens and use the refresh_token to restore user session
        response = self.requests_provider(self.jwt["redirect_uri"])
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

    def check_login(self):
        response = self._profile_response()
        if response != 0 and response.status_code == 200 and "user_type\":\"Expired\"" not in response.text:
            self.display.info("Successfully authenticated.", state=True)
            return

        if response != 0 and "user_type\":\"Expired\"" in response.text:
            self.display.exit("Authentication issue: account subscription expired.")

        current = ""
        for cookie in self.session.cookies:
            if cookie.name == "orm-jwt" and cookie.value:
                current = cookie.value
                break
        refreshed = None if getattr(self, "_browser_refresh_exhausted", False) else wait_for_browser_jwt(current)
        if refreshed:
            self.session.cookies.update(refreshed)
            if not self.args.no_cookies:
                persist_cookies(refreshed)
            response = self._profile_response()
            if response != 0 and response.status_code == 200 and "user_type\":\"Expired\"" not in response.text:
                self.display.info("Successfully authenticated.", state=True)
                return

        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")
        self.display.error("Authentication issue: unable to access profile page.")
        raise AuthExpired()

    def _profile_response(self):
        return self.requests_provider(PROFILE_URL, perform_redirect=False)

    @staticmethod
    def _to_xhtml_filename(filename):
        # Normalize .html / .htm / .xhtml to .xhtml, preserving query/fragment handling by caller.
        # e.g. "title.html" -> "title.xhtml", "toc.htm" -> "toc.xhtml"
        base = filename
        # strip query/fragment for extension check, re-attach later if present (caller handles fragments)
        suffix = ""
        for sep in ("#", "?"):
            if sep in base:
                idx = base.index(sep)
                suffix = base[idx:]
                base = base[:idx]
                break
        low = base.lower()
        if low.endswith(".html"):
            base = base[:-5] + ".xhtml"
        elif low.endswith(".htm"):
            base = base[:-4] + ".xhtml"
        elif "." not in base.split("/")[-1]:
            base = base + ".xhtml"
        return base + suffix

    def _enrich_book_info_from_library_page(self, info):
        # Best-effort: fetch library page to get publishers / subjects / canonical web_url.
        # Page URL with "-" slug redirects to the canonical slug and returns 200.
        try:
            lib_url = SAFARI_BASE_URL + "/library/view/-/{0}/".format(self.book_id)
            resp = self.requests_provider(lib_url)
            if resp == 0 or resp.status_code != 200:
                return info
            text = resp.text
            import re as _re
            # publishers: "publishers":[{"uuid":"...","name":"Packt Publishing",...}]
            pub_match = _re.search(r'"publishers"\s*:\s*\[(.*?)\]', text)
            if pub_match:
                names = _re.findall(r'"name"\s*:\s*"([^"]+)"', pub_match.group(1))
                if names:
                    info["publishers"] = [{"name": n} for n in names]
            # topics -> subjects: "topics":[{"id":"...","name":"Artificial Intelligence (AI)",...}]
            topic_match = _re.search(r'"topics"\s*:\s*\[(.*?)\]', text)
            if topic_match:
                # topics block may be large; extract names
                names = _re.findall(r'"name"\s*:\s*"([^"]+)"', topic_match.group(1))
                if names:
                    info["subjects"] = [{"name": n} for n in names]
            # canonical webUrl: "webUrl":"/library/view/-/978.../" or "/library/view/slug/978.../"
            web_match = _re.search(r'"webUrl"\s*:\s*"([^"]+)"', text)
            if web_match:
                w = web_match.group(1)
                if w.startswith("/"):
                    info["web_url"] = SAFARI_BASE_URL + w
                elif w.startswith("http"):
                    info["web_url"] = w
        except Exception as e:
            self.display.log("Could not enrich book info from library page: %s" % e)
        return info

    def get_book_info(self):
        # v1 API (https://learning.oreilly.com/api/v1/book/<id>/) was deprecated
        # and now returns 404 for all books. Use v2 epubs API instead.
        v2_url = self.API_V2_EPUB_TEMPLATE.format(self.book_id)
        response = self.requests_provider(v2_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book info.")

        if response.status_code != 200:
            try:
                err = response.json()
            except Exception:
                err = {"message": "Not Found"}
            self.display.exit(self.display.api_error(err))

        try:
            data = response.json()
        except Exception as e:
            self.display.exit(
                "API: unable to parse book info (expected JSON, got %s). "
                "The book API may have changed. Details: %s" %
                (response.headers.get("Content-Type", "unknown"), e)
            )

        if not isinstance(data, dict) or "title" not in data:
            self.display.exit(self.display.api_error(data if isinstance(data, dict) else {}))

        descriptions = data.get("descriptions") or {}
        description = descriptions.get("text/html") or descriptions.get("text/plain") or ""

        info = {
            "title": data.get("title", ""),
            "identifier": data.get("identifier", self.book_id),
            "isbn": data.get("isbn", self.book_id),
            "issued": data.get("publication_date", "") or data.get("created_time", ""),
            "description": description,
            "rights": "",
            "language": data.get("language", "en"),
            "web_url": SAFARI_BASE_URL + "/library/view/-/{0}/".format(self.book_id),
            "cover": SAFARI_BASE_URL + "/library/cover/{0}/".format(self.book_id),
            "authors": [],
            "publishers": [],
            "subjects": [],
        }

        # Authors via talent API (still v1, still working)
        try:
            talent_url = self.API_V1_TALENT_TEMPLATE.format(self.book_id)
            t_resp = self.requests_provider(talent_url)
            if t_resp != 0 and t_resp.status_code == 200:
                t_data = t_resp.json()
                if isinstance(t_data, list):
                    for c in t_data:
                        name = c.get("name") if isinstance(c, dict) else None
                        if name:
                            info["authors"].append({"name": name})
        except Exception as e:
            self.display.log("Could not retrieve authors: %s" % e)

        # Publishers / subjects / canonical web_url via library page (best-effort)
        info = self._enrich_book_info_from_library_page(info)

        for key, value in info.items():
            if value is None:
                info[key] = 'n/a'

        return info

    def _v2_chapter_to_compat(self, ch):
        content_url = ch.get("content_url", "") or ch.get("url", "")
        reference_id = ch.get("reference_id", "")
        # filename: prefer basename of content_url, fallback to reference_id
        raw_name = ""
        if content_url:
            raw_name = content_url.split("?")[0].split("#")[0].split("/")[-1]
        if not raw_name and reference_id:
            # reference_id like "978...-/Text/Chapter_1.xhtml" or "978...-/xhtml/cover.xhtml"
            if "-/" in reference_id:
                raw_name = reference_id.split("-/", 1)[-1].split("/")[-1]
            else:
                raw_name = reference_id.split("/")[-1]
        if not raw_name:
            raw_name = (ch.get("ourn", "chapter").split(":chapter:")[-1].split("/")[-1] or "chapter.xhtml")
        # URL-decode (ourn parts are percent-encoded, e.g. Text%2f)
        try:
            from urllib.parse import unquote as _unquote
            raw_name = _unquote(raw_name)
        except Exception:
            pass
        filename = self._to_xhtml_filename(raw_name)

        related = ch.get("related_assets", {}) or {}
        images = []
        for img_full in related.get("images", []) or []:
            if "/files/" in img_full:
                rel = img_full.split("/files/", 1)[-1]
            else:
                rel = img_full.split("/")[-1]
            # rel like "Images/B34135_1_1.png" -> keep as-is; basename-only -> prefix Images/
            if "/" not in rel:
                rel = "Images/" + rel
            images.append(rel)

        stylesheets = [{"url": u} for u in (related.get("stylesheets", []) or [])]

        return {
            "filename": filename,
            "title": ch.get("title", "") or filename,
            "content": content_url,
            "asset_base_url": self.api_v2_files_base,
            "images": images,
            "stylesheets": stylesheets,
            "site_styles": [],
        }

    def get_book_chapters(self, page=1):
        # v2 pagination uses limit/offset via `next` URL. Fetch all pages iteratively.
        # `page` arg kept for backward-compat but ignored; we follow `next` links.
        start_url = self.API_V2_CHAPTERS_TEMPLATE.format(self.book_id)
        all_results = []
        url = start_url
        while url:
            response = self.requests_provider(url)
            if response == 0:
                self.display.exit("API: unable to retrieve book chapters.")

            if response.status_code != 200:
                try:
                    err = response.json()
                except Exception:
                    err = {"message": "Not Found"}
                self.display.exit(self.display.api_error(err))

            try:
                data = response.json()
            except Exception as e:
                self.display.exit(
                    "API: unable to parse book chapters (expected JSON). Details: %s" % e
                )

            if not isinstance(data, dict) or "results" not in data or not len(data["results"]):
                if not all_results:
                    self.display.exit("API: unable to retrieve book chapters.")
                break

            if data.get("count", 0) > sys.getrecursionlimit():
                sys.setrecursionlimit(data["count"] + 10)

            all_results.extend(data["results"])
            url = data.get("next")

        # Order by indexed_position when available (spine order), else keep API order
        try:
            if all(isinstance(c, dict) and "indexed_position" in c for c in all_results):
                all_results.sort(key=lambda c: c.get("indexed_position", 0))
        except Exception:
            pass

        compat = [self._v2_chapter_to_compat(c) for c in all_results]
        # Keep cover first (legacy behavior) in case API order changes
        covers = [c for c in compat if "cover" in c["filename"].lower() or "cover" in c["title"].lower()]
        rest = [c for c in compat if c not in covers]
        return covers + rest

    def get_default_cover(self):
        response = self.requests_provider(self.book_info["cover"], stream=True)
        if response == 0:
            self.display.error("Error trying to retrieve the cover: %s" % self.book_info["cover"])
            return False

        file_ext = response.headers["Content-Type"].split("/")[-1]
        with open(os.path.join(self.images_path, "default_cover." + file_ext), 'wb') as i:
            for chunk in response.iter_content(1024):
                i.write(chunk)

        return "default_cover." + file_ext

    def get_html(self, url):
        response = self.requests_provider(url)
        if response == 0 or response.status_code != 200:
            self.display.exit(
                "Crawler: error trying to retrieve this page: %s (%s)\n    From: %s" %
                (self.filename, self.chapter_title, url)
            )

        root = None
        try:
            root = html.fromstring(response.text, base_url=SAFARI_BASE_URL)

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            self.display.error(parsing_error)
            self.display.exit(
                "Crawler: error trying to parse this page: %s (%s)\n    From: %s" %
                (self.filename, self.chapter_title, url)
            )

        return root

    @staticmethod
    def url_is_absolute(url):
        return bool(urlparse(url).netloc)

    @staticmethod
    def is_image_link(url: str):
        try:
            clean = url.split("#")[0].split("?")[0]
            return pathlib.Path(clean).suffix[1:].lower() in ["jpg", "jpeg", "png", "gif", "svg", "webp"]
        except Exception:
            return False

    def link_replace(self, link):
        if not link or link.startswith("mailto") or link.startswith("#") or link.startswith("data:"):
            return link
        if self.url_is_absolute(link):
            if "/files/" in link:
                # v2 absolute file URL, e.g. https://learning.oreilly.com/api/v2/epubs/.../files/Images/foo.png
                # or .../files/Text/Chapter_1.xhtml -> recurse as relative
                after = link.split("/files/", 1)[-1]
                return self.link_replace(after)
            if self.book_id in link:
                return self.link_replace(link.split(self.book_id)[-1])
            return link

        # Relative URL from here (may be "/api/v2/.../files/Images/foo.png",
        # "../Text/forward.htm#C100", "Text/Chapter_1.xhtml", etc.)
        # Split off query/fragment for type detection
        tmp = link
        frag = ""
        query = ""
        if "#" in tmp:
            tmp, frag = tmp.split("#", 1)
            frag = "#" + frag
        if "?" in tmp:
            tmp, query = tmp.split("?", 1)
            query = "?" + query

        if self.is_image_link(tmp) or any(x.lower() in tmp.lower() for x in ["cover", "images", "graphics"]):
            img_base = tmp.split("/")[-1]
            if not img_base:
                return link
            return "Images/" + img_base

        # Chapter links: EPUB is flat (all chapters in OEBPS/), so return basename
        # normalized to .xhtml, preserving query/fragment.
        base = tmp.split("/")[-1]
        if not base:
            return link
        low = base.lower()
        if low.endswith(".html") or low.endswith(".htm"):
            base = self._to_xhtml_filename(base)
        return base + query + frag

    @staticmethod
    def get_cover(html_root):
        lowercase_ns = etree.FunctionNamespace(None)
        lowercase_ns["lower-case"] = lambda _, n: n[0].lower() if n and len(n) else ""

        images = html_root.xpath("//img[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                                 "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover') or"
                                 "contains(lower-case(@alt), 'cover')]")
        if len(images):
            return images[0]

        divs = html_root.xpath("//div[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                               "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(divs):
            return divs[0]

        a = html_root.xpath("//a[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                            "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(a):
            return a[0]

        return None

    def parse_html(self, root, first_page=False):
        if random() > 0.8:
            if len(root.xpath("//div[@class='controls']/a/text()")):
                self.display.exit(self.display.api_error(" "))

        book_content = root.xpath("//div[@id='sbo-rt-content']")
        if not len(book_content):
            self.display.exit(
                "Parser: book content's corrupted or not present: %s (%s)" %
                (self.filename, self.chapter_title)
            )

        page_css = ""
        if len(self.chapter_stylesheets):
            for chapter_css_url in self.chapter_stylesheets:
                if chapter_css_url not in self.css:
                    self.css.append(chapter_css_url)
                    self.display.log("Crawler: found a new CSS at %s" % chapter_css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(chapter_css_url))

        stylesheet_links = root.xpath("//link[@rel='stylesheet']")
        if len(stylesheet_links):
            for s in stylesheet_links:
                css_url = urljoin("https:", s.attrib["href"]) if s.attrib["href"][:2] == "//" \
                    else urljoin(self.base_url, s.attrib["href"])

                if css_url not in self.css:
                    self.css.append(css_url)
                    self.display.log("Crawler: found a new CSS at %s" % css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(css_url))

        stylesheets = root.xpath("//style")
        if len(stylesheets):
            for css in stylesheets:
                if "data-template" in css.attrib and len(css.attrib["data-template"]):
                    css.text = css.attrib["data-template"]
                    del css.attrib["data-template"]

                try:
                    page_css += html.tostring(css, method="xml", encoding='unicode') + "\n"

                except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                    self.display.error(parsing_error)
                    self.display.exit(
                        "Parser: error trying to parse one CSS found in this page: %s (%s)" %
                        (self.filename, self.chapter_title)
                    )

        # TODO: add all not covered tag for `link_replace` function
        svg_image_tags = root.xpath("//image")
        if len(svg_image_tags):
            for img in svg_image_tags:
                image_attr_href = [x for x in img.attrib.keys() if "href" in x]
                if len(image_attr_href):
                    svg_url = img.attrib.get(image_attr_href[0])
                    svg_root = img.getparent().getparent()
                    new_img = svg_root.makeelement("img")
                    new_img.attrib.update({"src": svg_url})
                    svg_root.remove(img.getparent())
                    svg_root.append(new_img)

        book_content = book_content[0]
        book_content.rewrite_links(self.link_replace)

        xhtml = None
        try:
            if first_page:
                is_cover = self.get_cover(book_content)
                if is_cover is not None:
                    page_css = "<style>" \
                               "body{display:table;position:absolute;margin:0!important;height:100%;width:100%;}" \
                               "#Cover{display:table-cell;vertical-align:middle;text-align:center;}" \
                               "img{height:90vh;margin-left:auto;margin-right:auto;}" \
                               "</style>"
                    cover_html = html.fromstring("<div id=\"Cover\"></div>")
                    cover_div = cover_html.xpath("//div")[0]
                    cover_img = cover_div.makeelement("img")
                    cover_img.attrib.update({"src": is_cover.attrib["src"]})
                    cover_div.append(cover_img)
                    book_content = cover_html

                    self.cover = is_cover.attrib["src"]

            xhtml = html.tostring(book_content, method="xml", encoding='unicode')

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            self.display.error(parsing_error)
            self.display.exit(
                "Parser: error trying to parse HTML of this page: %s (%s)" %
                (self.filename, self.chapter_title)
            )

        return page_css, xhtml

    @staticmethod
    def escape_dirname(dirname, clean_space=False):
        if ":" in dirname:
            if dirname.index(":") > 15:
                dirname = dirname.split(":")[0]

            elif "win" in sys.platform:
                dirname = dirname.replace(":", ",")

        for ch in ['~', '#', '%', '&', '*', '{', '}', '\\', '<', '>', '?', '/', '`', '\'', '"', '|', '+', ':']:
            if ch in dirname:
                dirname = dirname.replace(ch, "_")

        return dirname if not clean_space else dirname.replace(" ", "")

    def create_dirs(self):
        if os.path.isdir(self.BOOK_PATH):
            self.display.log("Book directory already exists: %s" % self.BOOK_PATH)

        else:
            os.makedirs(self.BOOK_PATH)

        oebps = os.path.join(self.BOOK_PATH, "OEBPS")
        if not os.path.isdir(oebps):
            self.display.book_ad_info = True
            os.makedirs(oebps)

        self.css_path = os.path.join(oebps, "Styles")
        if os.path.isdir(self.css_path):
            self.display.log("CSSs directory already exists: %s" % self.css_path)

        else:
            os.makedirs(self.css_path)
            self.display.css_ad_info.value = 1

        self.images_path = os.path.join(oebps, "Images")
        if os.path.isdir(self.images_path):
            self.display.log("Images directory already exists: %s" % self.images_path)

        else:
            os.makedirs(self.images_path)
            self.display.images_ad_info.value = 1

    def save_page_html(self, contents):
        self.filename = self._to_xhtml_filename(self.filename)
        open(os.path.join(self.BOOK_PATH, "OEBPS", self.filename), "wb") \
            .write(self.BASE_HTML.format(contents[0], contents[1]).encode("utf-8", 'xmlcharrefreplace'))
        self.display.log("Created: %s" % self.filename)

    def get(self):
        len_books = len(self.book_chapters)

        for _ in range(len_books):
            if not len(self.chapters_queue):
                return

            first_page = len_books == len(self.chapters_queue)

            next_chapter = self.chapters_queue.pop(0)
            self.chapter_title = next_chapter["title"]
            self.filename = next_chapter["filename"]

            asset_base_url = next_chapter['asset_base_url']
            api_v2_detected = False
            if 'v2' in next_chapter['content']:
                asset_base_url = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{}/files".format(self.book_id)
                api_v2_detected = True

            if "images" in next_chapter and len(next_chapter["images"]):
                for img_url in next_chapter['images']:
                    if api_v2_detected:
                        self.images.append(asset_base_url + '/' + img_url)
                    else:
                        self.images.append(urljoin(next_chapter['asset_base_url'], img_url))


            # Stylesheets
            self.chapter_stylesheets = []
            if "stylesheets" in next_chapter and len(next_chapter["stylesheets"]):
                self.chapter_stylesheets.extend(x["url"] for x in next_chapter["stylesheets"])

            if "site_styles" in next_chapter and len(next_chapter["site_styles"]):
                self.chapter_stylesheets.extend(next_chapter["site_styles"])

            if os.path.isfile(os.path.join(self.BOOK_PATH, "OEBPS", self._to_xhtml_filename(self.filename))):
                if not self.display.book_ad_info and \
                        next_chapter not in self.book_chapters[:self.book_chapters.index(next_chapter)]:
                    self.display.info(
                        ("File `%s` already exists.\n"
                         "    If you want to download again all the book,\n"
                         "    please delete the output directory '" + self.BOOK_PATH + "' and restart the program.")
                         % self._to_xhtml_filename(self.filename)
                    )
                    self.display.book_ad_info = 2

            else:
                self.save_page_html(self.parse_html(self.get_html(next_chapter["content"]), first_page))

            self.display.state(len_books, len_books - len(self.chapters_queue))

    def _thread_download_css(self, url):
        css_file = os.path.join(self.css_path, "Style{0:0>2}.css".format(self.css.index(url)))
        if os.path.isfile(css_file):
            if not self.display.css_ad_info.value and url not in self.css[:self.css.index(url)]:
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the CSSs,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  css_file)
                self.display.css_ad_info.value = 1

        else:
            response = self.requests_provider(url)
            if response == 0:
                self.display.error("Error trying to retrieve this CSS: %s\n    From: %s" % (css_file, url))

            with open(css_file, 'wb') as s:
                s.write(response.content)

        self.css_done_queue.put(1)
        self.display.state(len(self.css), self.css_done_queue.qsize())


    def _thread_download_images(self, url):
        image_name = url.split("/")[-1]
        image_path = os.path.join(self.images_path, image_name)
        if os.path.isfile(image_path):
            if not self.display.images_ad_info.value and url not in self.images[:self.images.index(url)]:
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the images,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  image_name)
                self.display.images_ad_info.value = 1

        else:
            response = self.requests_provider(urljoin(SAFARI_BASE_URL, url), stream=True)
            if response == 0:
                self.display.error("Error trying to retrieve this image: %s\n    From: %s" % (image_name, url))
                return

            with open(image_path, 'wb') as img:
                for chunk in response.iter_content(1024):
                    img.write(chunk)

        self.images_done_queue.put(1)
        self.display.state(len(self.images), self.images_done_queue.qsize())

    def _start_multiprocessing(self, operation, full_queue):
        if len(full_queue) > 5:
            for i in range(0, len(full_queue), 5):
                self._start_multiprocessing(operation, full_queue[i:i + 5])

        else:
            process_queue = [Process(target=operation, args=(arg,)) for arg in full_queue]
            for proc in process_queue:
                proc.start()

            for proc in process_queue:
                proc.join()

    def collect_css(self):
        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for css_url in self.css:
            self._thread_download_css(css_url)

    def collect_images(self):
        if self.display.book_ad_info == 2:
            self.display.info("Some of the book contents were already downloaded.\n"
                              "    If you want to be sure that all the images will be downloaded,\n"
                              "    please delete the output directory '" + self.BOOK_PATH +
                              "' and restart the program.")

        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for image_url in self.images:
            self._thread_download_images(image_url)

    def create_content_opf(self):
        self.css = next(os.walk(self.css_path))[2]
        self.images = next(os.walk(self.images_path))[2]

        manifest = []
        spine = []
        for c in self.book_chapters:
            c["filename"] = self._to_xhtml_filename(c["filename"])
            item_id = escape("".join(c["filename"].split(".")[:-1]))
            manifest.append("<item id=\"{0}\" href=\"{1}\" media-type=\"application/xhtml+xml\" />".format(
                item_id, c["filename"]
            ))
            spine.append("<itemref idref=\"{0}\"/>".format(item_id))

        for i in set(self.images):
            dot_split = i.split(".")
            head = "img_" + escape("".join(dot_split[:-1]))
            extension = dot_split[-1]
            manifest.append("<item id=\"{0}\" href=\"Images/{1}\" media-type=\"image/{2}\" />".format(
                head, i, "jpeg" if "jp" in extension else extension
            ))

        for i in range(len(self.css)):
            manifest.append("<item id=\"style_{0:0>2}\" href=\"Styles/Style{0:0>2}.css\" "
                            "media-type=\"text/css\" />".format(i))

        authors = "\n".join("<dc:creator opf:file-as=\"{0}\" opf:role=\"aut\">{0}</dc:creator>".format(
            escape(aut.get("name", "n/d"))
        ) for aut in self.book_info.get("authors", []))

        subjects = "\n".join("<dc:subject>{0}</dc:subject>".format(escape(sub.get("name", "n/d")))
                             for sub in self.book_info.get("subjects", []))

        return self.CONTENT_OPF.format(
            (self.book_info.get("isbn",  self.book_id)),
            escape(self.book_title),
            authors,
            escape(self.book_info.get("description", "")),
            subjects,
            ", ".join(escape(pub.get("name", "")) for pub in self.book_info.get("publishers", [])),
            escape(self.book_info.get("rights", "")),
            self.book_info.get("issued", ""),
            self.cover,
            "\n".join(manifest),
            "\n".join(spine),
            self._to_xhtml_filename(self.book_chapters[0]["filename"])
        )

    @staticmethod
    def _toc_entry_to_compat(cc):
        # Translate v2 TOC entry (title/reference_id/ourn/url) to legacy
        # shape (label/href/id/fragment) so parse_toc works for both.
        if "label" in cc and "href" in cc:
            return cc
        title = cc.get("title", "") or cc.get("label", "")
        fragment = cc.get("fragment", "") or ""
        ref = cc.get("reference_id", "") or cc.get("ourn", "") or cc.get("id", "")
        # reference_id like "978...-/Text/Preface.xhtml" -> "Text/Preface.xhtml"
        href_path = ""
        if "-/" in ref:
            href_path = ref.split("-/", 1)[-1]
        elif "/" in ref and "." in ref.split("/")[-1]:
            href_path = ref.split("/")[-1]
            # ourn case: urn:orm:book:...:chapter:Text%2fPreface.xhtml
            try:
                from urllib.parse import unquote as _unquote
                href_path = _unquote(href_path)
                # ourn chapter part may still contain prefix like "Text%2f..." decoded above
                if "/" not in href_path and "%" in ref:
                    # fallback: decode full ourn tail
                    tail = ref.split(":chapter:")[-1]
                    href_path = _unquote(tail)
            except Exception:
                pass
        else:
            href_path = cc.get("href", "") or cc.get("url", "").split("/")[-1]
        # href_path may be "Text/Preface.xhtml" -> basename for flat EPUB + fragment
        base = href_path.split("/")[-1] if href_path else "chapter.xhtml"
        # Normalize extension to .xhtml
        low = base.lower()
        if low.endswith(".html") or low.endswith(".htm"):
            # reuse logic without self: simple replace
            if low.endswith(".html"):
                base = base[:-5] + ".xhtml"
            else:
                base = base[:-4] + ".xhtml"
        if fragment and "#" not in base:
            href = base + "#" + fragment
        else:
            href = base
        compat = dict(cc)
        compat["label"] = title
        compat["href"] = href
        compat["fragment"] = fragment
        if "id" not in compat:
            compat["id"] = ref or fragment or base
        if "children" not in compat:
            compat["children"] = []
        return compat

    @staticmethod
    def parse_toc(l, c=0, mx=0):
        r = ""
        for _cc in l:
            cc = SafariBooks._toc_entry_to_compat(_cc)
            c += 1
            try:
                depth = int(cc.get("depth", 1))
            except Exception:
                depth = 1
            if depth > mx:
                mx = depth

            fragment = cc.get("fragment", "") or ""
            cid = cc.get("id", "") or fragment or "ch%d" % c
            nav_id = fragment if len(fragment) else cid
            label = cc.get("label", "") or cc.get("title", "")
            href = cc.get("href", "")
            # Normalize href to basename.xhtml[#fragment]
            if href:
                # keep fragment
                frag_part = ""
                if "#" in href:
                    href, frag_part = href.split("#", 1)
                    frag_part = "#" + frag_part
                href_base = href.split("/")[-1]
                low = href_base.lower()
                if low.endswith(".html"):
                    href_base = href_base[:-5] + ".xhtml"
                elif low.endswith(".htm"):
                    href_base = href_base[:-4] + ".xhtml"
                href = href_base + frag_part
            else:
                href = "chapter.xhtml"

            r += "<navPoint id=\"{0}\" playOrder=\"{1}\">" \
                 "<navLabel><text>{2}</text></navLabel>" \
                 "<content src=\"{3}\"/>".format(
                    escape(str(nav_id), quote=True), c,
                    escape(str(label)), escape(str(href), quote=True)
                 )

            children = cc.get("children", []) or []
            if children:
                sr, c, mx = SafariBooks.parse_toc(children, c, mx)
                r += sr

            r += "</navPoint>\n"

        return r, c, mx

    def create_toc(self):
        toc_url = self.API_V2_TOC_TEMPLATE.format(self.book_id)
        response = self.requests_provider(toc_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book chapters. "
                              "Don't delete any files, just run again this program"
                              " in order to complete the `.epub` creation!")

        if response.status_code != 200:
            try:
                err = response.json()
            except Exception:
                err = {}
            self.display.exit(
                self.display.api_error(err if isinstance(err, dict) else {}) +
                " Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!"
            )

        try:
            data = response.json()
        except Exception as e:
            self.display.exit(
                "API: unable to parse table of contents. Details: %s "
                "Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!" % e
            )

        if isinstance(data, dict):
            # v2 error shape {"message": "Not Found"}
            self.display.exit(
                self.display.api_error(data) +
                " Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!"
            )

        if not isinstance(data, list):
            self.display.exit(
                "API: unable to retrieve book chapters. "
                "Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!"
            )

        navmap, _, max_depth = self.parse_toc(data)
        return self.TOC_NCX.format(
            (self.book_info["isbn"] if self.book_info["isbn"] else self.book_id),
            max_depth,
            self.book_title,
            ", ".join(aut.get("name", "") for aut in self.book_info.get("authors", [])),
            navmap
        )

    def create_epub(self):
        open(os.path.join(self.BOOK_PATH, "mimetype"), "w").write("application/epub+zip")
        meta_info = os.path.join(self.BOOK_PATH, "META-INF")
        if os.path.isdir(meta_info):
            self.display.log("META-INF directory already exists: %s" % meta_info)

        else:
            os.makedirs(meta_info)

        open(os.path.join(meta_info, "container.xml"), "wb").write(
            self.CONTAINER_XML.encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "content.opf"), "wb").write(
            self.create_content_opf().encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "toc.ncx"), "wb").write(
            self.create_toc().encode("utf-8", "xmlcharrefreplace")
        )

        zip_file = os.path.join(PATH, "Books", self.book_id)
        if os.path.isfile(zip_file + ".zip"):
            os.remove(zip_file + ".zip")

        shutil.make_archive(zip_file, 'zip', self.BOOK_PATH)
        os.rename(zip_file + ".zip", os.path.join(self.BOOK_PATH, self.book_id) + ".epub")


# MAIN
if __name__ == "__main__":
    arguments = argparse.ArgumentParser(prog="safaribooks.py",
                                        description="Download and generate an EPUB of your favorite books"
                                                    " from Safari Books Online.",
                                        add_help=False,
                                        allow_abbrev=False)

    login_arg_group = arguments.add_mutually_exclusive_group()
    login_arg_group.add_argument(
        "--cred", metavar="<EMAIL:PASS>", default=False,
        help="Credentials used to perform the auth login on Safari Books Online."
             " Es. ` --cred \"account_mail@mail.com:password01\" `."
    )
    login_arg_group.add_argument(
        "--login", action='store_true',
        help="Prompt for credentials used to perform the auth login on Safari Books Online."
    )

    arguments.add_argument(
        "--no-cookies", dest="no_cookies", action='store_true',
        help="Prevent your session data to be saved into `cookies.json` file."
    )
    arguments.add_argument(
        "--kindle", dest="kindle", action='store_true',
        help="Add some CSS rules that block overflow on `table` and `pre` elements."
             " Use this option if you're going to export the EPUB to E-Readers like Amazon Kindle."
    )
    arguments.add_argument(
        "--preserve-log", dest="log", action='store_true', help="Leave the `info_XXXXXXXXXXXXX.log`"
                                                                " file even if there isn't any error."
    )
    arguments.add_argument("--help", action="help", default=argparse.SUPPRESS, help='Show this help message.')
    arguments.add_argument(
        "bookid", metavar='<BOOK ID>', nargs='*', default=[],
        help="Book digits ID that you want to download. You can find it in the URL (X-es):"
             " `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`"
             " You can specify multiple book IDs separated by space."
    )
    arguments.add_argument(
        "--file", metavar='<FILE>', default=None,
        help="Path to a text file containing book IDs (one per line)."
    )

    args_parsed = arguments.parse_args()
    if args_parsed.cred or args_parsed.login:
        print("WARNING: Due to recent changes on ORLY website, \n" \
                "the `--cred` and `--login` options are temporarily disabled.\n"
                "    Please use the `cookies.json` file to authenticate your account.\n"
                "    See: https://github.com/lorenzodifuccia/safaribooks/issues/358")
        arguments.exit()
        
        # user_email = ""
        # pre_cred = ""

        # if args_parsed.cred:
        #     pre_cred = args_parsed.cred

        # else:
        #     user_email = input("Email: ")
        #     passwd = getpass.getpass("Password: ")
        #     pre_cred = user_email + ":" + passwd

        # parsed_cred = SafariBooks.parse_cred(pre_cred)

        # if not parsed_cred:
        #     arguments.error("invalid credential: %s" % (
        #         args_parsed.cred if args_parsed.cred else (user_email + ":*******")
        #     ))

        # args_parsed.cred = parsed_cred

    else:
        if args_parsed.no_cookies:
            arguments.error("invalid option: `--no-cookies` is valid only if you use the `--cred` option")

    # Collect all book IDs from arguments and file
    book_ids = args_parsed.bookid[:]
    
    if args_parsed.file:
        try:
            with open(args_parsed.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        book_ids.append(line)
        except FileNotFoundError:
            arguments.error("File not found: %s" % args_parsed.file)
        except Exception as e:
            arguments.error("Error reading file: %s" % str(e))
    
    if not book_ids:
        arguments.error("at least one book ID is required (via argument or --file)")
    
    # Download each book
    total_books = len(book_ids)
    for idx, book_id in enumerate(book_ids, 1):
        print("\n" + "=" * 50)
        print("[%d/%d] Downloading book: %s" % (idx, total_books, book_id))
        print("=" * 50)
        try:
            args_parsed.bookid = book_id
            SafariBooks(args_parsed)
        except AuthExpired:
            print("Session expired. Stopped the queue so the remaining books are not requested with a dead cookie.")
            print("Reload https://learning.oreilly.com in the browser, then run the remaining ids.")
            break
        except SystemExit as e:
            if e.code != 0:
                print("Error downloading book %s, continuing with next book..." % book_id)
                continue
        except Exception as e:
            print("Error downloading book %s: %s" % (book_id, str(e)))
            print("Continuing with next book...")
            continue
    
    # Hint: do you want to download more then one book once, initialized more than one instance of `SafariBooks`...
    sys.exit(0)
