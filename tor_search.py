"""
tor_search.py — Tor .onion search engine, fully self-contained.

HOW TO USE:
  1. Put tor_search.py and the tor bundle .tar.gz in the same folder
  2. Run:  python tor_search.py
  3. That's it — the script extracts Tor, starts it, and shuts it down for you.

Install Python deps once:
  pip install requests[socks] beautifulsoup4 PySocks
"""

import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import sys
import time
import subprocess
import shutil
import tarfile
import glob
import re
from collections import deque
from urllib.parse import urljoin, urlparse

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(SCRIPT_DIR, "tor_index.db")
TOR_DIR    = os.path.join(SCRIPT_DIR, "tor_bundle")   # extracted here
TOR_EXE    = os.path.join(TOR_DIR, "tor", "tor.exe")
import uuid
import tempfile

TOR_DATA = os.path.join(
    tempfile.gettempdir(),
    f"torsearch_{uuid.uuid4().hex}"
)
TOR_RC     = os.path.join(TOR_DIR, "torrc")
TOR_GEOIP  = os.path.join(TOR_DIR, "data", "geoip")
TOR_GEOIP6 = os.path.join(TOR_DIR, "data", "geoip6")

TOR_SOCKS_PORT = 9150   # default; auto-bumped if busy
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150",
}

REQUEST_TIMEOUT = 40
CRAWL_DELAY     = 2
MAX_PAGES       = 500
MAX_QUEUE = 2000


def find_free_port(start=9050, end=9200):
    """Return first actually unused TCP port."""

    import socket

    for port in range(start, end):

        test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            result = test.connect_ex(("127.0.0.1", port))

            if result != 0:
                test.close()
                return port

        except Exception:
            pass

        finally:
            test.close()

    return 9150


def set_tor_port(port):
    """Update global proxy to use chosen port."""

    global TOR_SOCKS_PORT, TOR_PROXY

    TOR_SOCKS_PORT = port

    TOR_PROXY = {
        "http":  f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
# ── Tor bundle setup ──────────────────────────────────────────────────────────

def find_bundle():
    """Return path to the first .tar.gz tor bundle found next to the script."""
    patterns = [
        os.path.join(SCRIPT_DIR, "tor-expert-bundle*.tar.gz"),
        os.path.join(SCRIPT_DIR, "tor*.tar.gz"),
    ]
    for pat in patterns:
        matches = glob.glob(pat)
        if matches:
            return matches[0]
    return None


def extract_bundle(bundle_path, log=None):
    """
    Extract the Tor bundle tar.gz into TOR_DIR.
    Returns (ok: bool, message: str).
    """
    def say(msg):
        if log:
            log(msg, "dim")

    say("Extracting Tor bundle — please wait...")
    try:
        os.makedirs(TOR_DIR, exist_ok=True)
        with tarfile.open(bundle_path, "r:gz") as tf:
            tf.extractall(TOR_DIR)
        say("Extraction complete.")
        return True, "OK"
    except Exception as e:
        return False, str(e)


def write_torrc():

    global TOR_SOCKS_PORT

    TOR_SOCKS_PORT = find_free_port(9050, 9200)

    set_tor_port(TOR_SOCKS_PORT)

    os.makedirs(TOR_DATA, exist_ok=True)

    rc = (
        f"SocksPort {TOR_SOCKS_PORT}\n"
        f"DataDirectory {TOR_DATA}\n"
        f"GeoIPFile {TOR_GEOIP}\n"
        f"GeoIPv6File {TOR_GEOIP6}\n"
        "Log notice stdout\n"
        "ExitPolicy reject *:*\n"
    )

    with open(TOR_RC, "w") as f:
        f.write(rc)


def is_tor_ready():
    """True if tor.exe exists and is extracted."""
    return os.path.isfile(TOR_EXE)


# ── Tor process manager ───────────────────────────────────────────────────────

class TorProcess:
    """Starts, monitors, and stops the tor.exe subprocess."""

    def __init__(self, log_callback=None):
        self._proc    = None
        self._log     = log_callback or (lambda m, t="info": None)
        self._lock    = threading.Lock()
        self.ready    = False        # True once bootstrap 100% seen
        self._thread  = None

    def start(self, on_ready=None, on_line=None):
        """
        Launch tor.exe in background. Calls on_ready() once bootstrapped.
        on_line(line, tag) receives each stdout line for the console.
        """
        if self._proc and self._proc.poll() is None:
            self._log("Tor is already running.", "dim")
            return

        self.ready = False

        if not is_tor_ready():
            self._log("tor.exe not found — bundle not extracted yet.", "error")
            return

        write_torrc()

        def run():
            try:
                self._proc = subprocess.Popen(
                    [TOR_EXE, "-f", TOR_RC],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=(subprocess.CREATE_NO_WINDOW
                                   if sys.platform == "win32" else 0),
                )
                self._log("tor.exe started (PID " + str(self._proc.pid) + ")", "good")

                for raw in self._proc.stdout:
                    line = raw.rstrip()
                    if not line:
                        continue

                    # Pick a log tag
                    tag = "dim"
                    if "err" in line.lower() or "warn" in line.lower():
                        tag = "error"
                    elif "notice" in line.lower():
                        tag = "info"

                    if on_line:
                        on_line(line, tag)

                    # Detect full bootstrap
                    if "Bootstrapped 100%" in line and not self.ready:
                        self.ready = True
                        self._log("✓ Tor ready — connected to network!", "good")
                        if on_ready:
                            on_ready()

                    # Detect startup errors
                    if "[err]" in line.lower():
                        self._log("Tor error: " + line, "error")

                self._log("tor.exe exited.", "dim")

            except FileNotFoundError:
                self._log("Cannot find tor.exe at: " + TOR_EXE, "error")
            except Exception as e:
                self._log("Tor process error: " + str(e), "error")

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._log("Stopping Tor...", "dim")
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()
            self.ready = False
            self._log("Tor stopped.", "dim")

    def is_running(self):
        return self._proc is not None and self._proc.poll() is None


# ── Tor connectivity check ────────────────────────────────────────────────────

def check_tor(log=None):
    """Return (ok: bool, message: str) — hits torproject.org check API."""
    try:
        import requests
        r = requests.get(
            "http://check.torproject.org/api/ip",
            proxies=TOR_PROXY,
            timeout=15,
        )
        data = r.json()
        if data.get("IsTor"):
            return True, "Tor active — exit IP: " + data.get("IP", "unknown")
        return False, "Proxy reachable but Tor exit not confirmed"
    except ImportError:
        return False, "requests not installed — run: pip install requests[socks] PySocks"
    except Exception as e:
        return False, "Tor proxy not reachable: " + str(e)


# ── Crawler ───────────────────────────────────────────────────────────────────

def is_onion(url):
    host = urlparse(url).netloc.lower()
    return host.endswith(".onion") or ".onion:" in host


def clean_text(soup):
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


def extract_links(soup, base_url):
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("javascript:", "mailto:", "#")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme in ("http", "https") and is_onion(full):
            links.append(parsed._replace(fragment="").geturl())
    return links


def crawl(seed_urls, db_path, status_callback=None, should_stop=None):
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        if status_callback:
            status_callback(
                "ERROR: Run: pip install requests[socks] beautifulsoup4 PySocks",
                "error",
            )
        return

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    _ensure_tables(conn)

    def is_visited(url):
        return conn.execute(
            "SELECT 1 FROM visited WHERE url=?", (url,)
        ).fetchone() is not None

    def mark_visited(url):
        conn.execute("INSERT OR IGNORE INTO visited (url) VALUES (?)", (url,))
        conn.commit()

    def save_page(url, title, body):
        conn.execute("DELETE FROM pages WHERE url=?", (url,))
        conn.execute(
            "INSERT INTO pages (url, title, body) VALUES (?, ?, ?)",
            (url, title, body[:50000]),
        )
        conn.commit()

    def page_count():
        return conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]

    def log(msg, tag="info"):
        if status_callback:
            status_callback(msg, tag)

    queue      = deque(seed_urls)
    queued_set = set(seed_urls)

    session = requests.Session()
    session.proxies.update(TOR_PROXY)
    session.headers.update({"User-Agent": "Mozilla/5.0 (TorSearchBot/2.0)"})

    log("Crawl started — " + str(len(seed_urls)) + " seed(s)", "good")

    while queue:
        if should_stop and should_stop():
            log("Stopped by user.", "dim")
            break

        url = queue.popleft()
        if is_visited(url):
            continue

        n = page_count()
        if n >= MAX_PAGES:
            log("Reached max pages (" + str(MAX_PAGES) + ").", "dim")
            break

        log("[" + str(n) + "/" + str(MAX_PAGES) + "] " + url)
        mark_visited(url)

        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            ct   = resp.headers.get("Content-Type", "")
            if "text/html" not in ct:
                log("  Skipped (not HTML)", "dim")
                continue

            soup  = BeautifulSoup(resp.text, "html.parser")
            title = (
                soup.title.string.strip()
                if soup.title and soup.title.string
                else url
            )
            body = clean_text(soup)

            if len(body) < 50:
                log("  Skipped (too short)", "dim")
                continue

            save_page(url, title, body)
            log("  Indexed: " + title[:70], "good")

            added = 0
            for link in extract_links(soup, url):
                if link not in queued_set and not is_visited(link):
                    if len(queue) < MAX_QUEUE:
                        queue.append(link)
                        queued_set.add(link)
                        added += 1
            if added:
                log("  +" + str(added) + " links (queue " + str(len(queue)) + ")", "dim")

        except Exception as e:
            log("  Error: " + str(e), "error")

        time.sleep(CRAWL_DELAY)

    conn.close()
    log("Crawl complete.", "good")


# ── Page fetcher ─────────────────────────────────────────────────────────────

def fetch_page(url):
    """
    Fetch a page through Tor. Returns (html: str, final_url: str, error: str|None).
    """
    try:
        import requests
        from bs4 import BeautifulSoup
        session = requests.Session()
        session.proxies.update(TOR_PROXY)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
        })
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return resp.text, resp.url, None
    except Exception as e:
        return None, url, str(e)


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_tables(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS visited (url TEXT PRIMARY KEY)")
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS pages USING fts5(
            url, title, body, tokenize='porter ascii'
        )
    """)
    conn.commit()


def ensure_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    _ensure_tables(conn)
    conn.close()


def search_index(query, limit=50):
    if not query.strip():
        return []
    safe = query.replace('"', '""')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("""
            SELECT url, title,
                   snippet(pages, 2, '[', ']', '...', 32) AS snippet,
                   rank
            FROM pages WHERE pages MATCH ?
            ORDER BY rank LIMIT ?
        """, (safe, limit)).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        try:
            like = "%" + query + "%"
            rows = conn.execute("""
                SELECT url, title, substr(body,1,200) AS snippet, 0 AS rank
                FROM pages WHERE title LIKE ? OR body LIKE ?
                LIMIT ?
            """, (like, like, limit)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
    finally:
        conn.close()


def indexed_count():
    try:
        conn = sqlite3.connect(DB_PATH)
        n = conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


def delete_index():
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        ensure_db()
        return True
    except Exception as e:
        return str(e)


# ── Colours & fonts ───────────────────────────────────────────────────────────

C_WIN        = "#0b0f1a"
C_TOOLBAR    = "#111827"
C_TOOLBAR_B  = "#1e293b"
C_ADDRBAR    = "#0d1526"
C_ADDRBAR_BD = "#1e3a5f"
C_ADDRBAR_FO = "#00aaff"
C_PAGE       = "#0b0f1a"
C_TAB_ACT    = "#0d1526"
C_TAB_IN     = "#080c14"
C_TAB_TXT    = "#c8e4ff"
C_TITLE      = "#38bdf8"
C_URL        = "#4ade80"
C_SNIPPET    = "#94a3b8"
C_DIM        = "#475569"
C_BTN        = "#0284c7"
C_BTN_HOV    = "#0369a1"
C_LOG_BG     = "#060912"
C_LOG_TXT    = "#cbd5e1"
C_GREEN      = "#22c55e"
C_RED        = "#ef4444"
C_ORANGE     = "#f97316"
C_BORDER     = "#1e293b"

FONT_UI      = ("Segoe UI", 10)
FONT_SMALL   = ("Segoe UI", 9)
FONT_ADDR    = ("Segoe UI", 11)
FONT_TITLE   = ("Segoe UI", 11, "bold")
FONT_SNIPPET = ("Segoe UI", 10)
FONT_URL     = ("Segoe UI", 9)
FONT_MONO    = ("Consolas", 9)
FONT_CHROME  = ("Segoe UI", 9)


TOR_BROWSER_SHORTCUT = r"C:\Users\BradJ\AppData\Roaming\Microsoft\Network\Tor Browser.lnk"


def open_in_tor_browser(url):
    """
    Open a URL inside the installed Tor Browser shortcut.
    """

    try:
        if not os.path.exists(TOR_BROWSER_SHORTCUT):
            return False, (
                "Tor Browser shortcut not found:\n\n"
                + TOR_BROWSER_SHORTCUT
            )

        subprocess.Popen([
            "cmd",
            "/c",
            "start",
            "",
            TOR_BROWSER_SHORTCUT,
            url
        ])

        return True, None

    except Exception as e:
        return False, str(e)

# ── Built-in browser window ───────────────────────────────────────────────────

class BrowserWindow(tk.Toplevel):
    """
    A simple in-app browser that fetches pages through Tor and renders them.
    Displays images as [img], renders text content, and lets you click links.
    """

    def __init__(self, master, url):
        super().__init__(master)
        self.configure(bg=C_WIN)
        self.geometry("1000x760")
        self.minsize(700, 400)
        self._history  = []          # list of URLs visited
        self._current  = ""
        self._loading  = False

        self._build_ui()
        self.navigate(url)

    # ── UI ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.title("TorSearch Browser")

        # ── Toolbar ───────────────────────────────────────────────────────
        bar = tk.Frame(self, bg=C_TOOLBAR,
                       highlightbackground=C_TOOLBAR_B, highlightthickness=1)
        bar.pack(fill="x", ipady=4)

        self._back_btn = tk.Button(
            bar, text="‹", font=("Segoe UI", 14),
            bg=C_TOOLBAR, fg=C_DIM, activebackground=C_TOOLBAR_B,
            relief="flat", width=2, cursor="hand2",
            command=self._go_back,
        )
        self._back_btn.pack(side="left", padx=4)

        self._reload_btn = tk.Button(
            bar, text="↺", font=("Segoe UI", 14),
            bg=C_TOOLBAR, fg=C_DIM, activebackground=C_TOOLBAR_B,
            relief="flat", width=2, cursor="hand2",
            command=self._reload,
        )
        self._reload_btn.pack(side="left", padx=(0, 4))

        addr_outer = tk.Frame(
            bar, bg=C_ADDRBAR,
            highlightbackground=C_ADDRBAR_BD, highlightthickness=1,
        )
        addr_outer.pack(side="left", fill="x", expand=True, padx=6, pady=3)

        tk.Label(
            addr_outer, text="[tor]", font=("Segoe UI", 8),
            bg=C_ADDRBAR, fg=C_GREEN,
        ).pack(side="left", padx=(6, 2))

        self._url_var = tk.StringVar()
        self._url_entry = tk.Entry(
            addr_outer, textvariable=self._url_var,
            font=FONT_ADDR, bg=C_ADDRBAR, fg="#e2e8f0",
            insertbackground="#e2e8f0", relief="flat", bd=0,
        )
        self._url_entry.pack(side="left", fill="x", expand=True, ipady=4)
        self._url_entry.bind("<Return>", lambda _: self.navigate(self._url_var.get().strip()))
        self._url_entry.bind("<FocusIn>", lambda _: addr_outer.config(
            highlightbackground=C_ADDRBAR_FO, highlightthickness=2))
        self._url_entry.bind("<FocusOut>", lambda _: addr_outer.config(
            highlightbackground=C_ADDRBAR_BD, highlightthickness=1))

        tk.Button(
            addr_outer, text="Go", command=lambda: self.navigate(self._url_var.get().strip()),
            font=FONT_CHROME, bg=C_BTN, fg="white",
            activebackground=C_BTN_HOV, relief="flat",
            padx=10, pady=3, cursor="hand2", bd=0,
        ).pack(side="right", padx=4, pady=2)

        # ── Status bar ────────────────────────────────────────────────────
        self._status = tk.Label(
            self, text="", font=("Segoe UI", 8),
            fg=C_DIM, bg=C_TOOLBAR, anchor="w",
            highlightbackground=C_TOOLBAR_B, highlightthickness=1,
        )
        self._status.pack(fill="x", side="bottom", ipady=2)

        # ── Page area ─────────────────────────────────────────────────────
        page_outer = tk.Frame(self, bg=C_PAGE)
        page_outer.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(page_outer, bg=C_PAGE, highlightthickness=0)
        sb_y = ttk.Scrollbar(page_outer, orient="vertical",   command=self._canvas.yview)
        sb_x = ttk.Scrollbar(page_outer, orient="horizontal", command=self._canvas.xview)

        self._page_frame = tk.Frame(self._canvas, bg=C_PAGE, padx=30, pady=20)
        self._page_frame.bind(
            "<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")),
        )
        self._canvas.create_window((0, 0), window=self._page_frame, anchor="nw")
        self._canvas.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)

        sb_y.pack(side="right",  fill="y")
        sb_x.pack(side="bottom", fill="x")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._canvas.bind_all("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(-1*(e.delta//120), "units"))
        self._canvas.bind_all("<Button-4>",
            lambda e: self._canvas.yview_scroll(-1, "units"))
        self._canvas.bind_all("<Button-5>",
            lambda e: self._canvas.yview_scroll(1, "units"))

    # ── Navigation ────────────────────────────────────────────────────────

    def navigate(self, url):
        if not url:
            return
        if not url.startswith("http"):
            url = "http://" + url
        self._url_var.set(url)
        self.title("Loading… — TorSearch Browser")
        self._set_status("Fetching " + url + " through Tor…")
        self._show_loading()

        if self._current:
            self._history.append(self._current)
        self._current = url
        self._loading = True

        def run():
            html, final_url, err = fetch_page(url)
            self.after(0, lambda: self._on_loaded(html, final_url, err))

        threading.Thread(target=run, daemon=True).start()

    def _go_back(self):
        if self._history:
            url = self._history.pop()
            self._current = ""   # prevent re-push
            self.navigate(url)

    def _reload(self):
        if self._current:
            url = self._current
            self._current = ""
            if self._history and self._history[-1] == url:
                self._history.pop()
            self.navigate(url)

    def _on_loaded(self, html, final_url, err):
        self._loading = False
        self._url_var.set(final_url)
        self._current = final_url

        if err:
            self._render_error(final_url, err)
            self.title("Error — TorSearch Browser")
            self._set_status("Error: " + err)
            return

        self.title(final_url[:80] + " — TorSearch Browser")
        self._set_status("Loaded: " + final_url)
        self._render_html(html, final_url)

    # ── Rendering ─────────────────────────────────────────────────────────

    def _clear(self):
        for w in self._page_frame.winfo_children():
            w.destroy()

    def _show_loading(self):
        self._clear()
        tk.Label(
            self._page_frame,
            text="⏳  Connecting through Tor…\n\n"
                 "This may take 10–30 seconds for .onion sites.",
            font=("Segoe UI", 12), fg=C_DIM, bg=C_PAGE, justify="center",
        ).pack(pady=80)

    def _render_error(self, url, err):
        self._clear()
        tk.Label(self._page_frame,
                 text="Could not load page",
                 font=("Segoe UI", 14, "bold"), fg=C_RED, bg=C_PAGE,
                 ).pack(anchor="w", pady=(0, 6))
        tk.Label(self._page_frame, text=url,
                 font=FONT_URL, fg=C_DIM, bg=C_PAGE).pack(anchor="w")
        tk.Frame(self._page_frame, bg=C_BORDER, height=1
                 ).pack(fill="x", pady=10)
        tk.Label(self._page_frame, text=err,
                 font=FONT_MONO, fg=C_RED, bg=C_PAGE,
                 wraplength=860, justify="left").pack(anchor="w")

    def _render_html(self, html, base_url):
        """Parse HTML and render it as styled Tkinter widgets."""
        self._clear()
        self._canvas.yview_moveto(0)

        try:
            from bs4 import BeautifulSoup, NavigableString, Tag
        except ImportError:
            tk.Label(self._page_frame,
                     text="beautifulsoup4 not installed.\nRun: pip install beautifulsoup4",
                     font=FONT_MONO, fg=C_RED, bg=C_PAGE).pack()
            return

        soup = BeautifulSoup(html, "html.parser")

        # Page title in window bar
        if soup.title and soup.title.string:
            self.title(soup.title.string.strip()[:80] + " — TorSearch Browser")

        # Remove unwanted tags
        for tag in soup(["script", "style", "head", "noscript", "svg"]):
            tag.decompose()

        # We walk the body and emit widgets block by block
        body = soup.body or soup

        def make_link(widget, href):
            full = urljoin(base_url, href)
            widget.config(cursor="hand2", fg=C_TITLE)
            widget.bind("<Enter>", lambda e: e.widget.config(fg="#7dd3fc",
                        font=(*e.widget.cget("font").split()[:2], "underline")
                        if isinstance(e.widget.cget("font"), str) else FONT_SNIPPET))
            widget.bind("<Leave>", lambda e: e.widget.config(fg=C_TITLE))
            widget.bind("<Button-1>", lambda _, u=full: self.navigate(u))
            self._set_status_hover(widget, full)

        def set_status_on_hover(w, text):
            w.bind("<Enter>", lambda e: self._set_status(text))
            w.bind("<Leave>", lambda e: self._set_status(""))

        def emit_block(node, indent=0):
            """Recursively walk nodes and emit widgets."""
            if isinstance(node, NavigableString):
                text = str(node).strip()
                if text:
                    tk.Label(
                        self._page_frame, text=text,
                        font=FONT_SNIPPET, fg=C_SNIPPET, bg=C_PAGE,
                        wraplength=860, justify="left", anchor="w",
                    ).pack(fill="x", padx=(indent*20, 0))
                return

            name = node.name.lower() if node.name else ""

            # Headings
            if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
                size  = {"h1": 18, "h2": 16, "h3": 14, "h4": 12, "h5": 11, "h6": 10}.get(name, 11)
                color = {"h1": "#f0f9ff", "h2": C_TITLE, "h3": "#93c5fd"}.get(name, C_TAB_TXT)
                text  = node.get_text(" ", strip=True)
                if text:
                    pady = (16, 4) if name in ("h1", "h2") else (10, 2)
                    tk.Label(
                        self._page_frame, text=text,
                        font=("Segoe UI", size, "bold"), fg=color, bg=C_PAGE,
                        wraplength=860, justify="left", anchor="w",
                    ).pack(fill="x", pady=pady)
                    if name == "h1":
                        tk.Frame(self._page_frame, bg=C_BORDER, height=1).pack(fill="x", pady=(0,6))
                return

            # Paragraph
            if name == "p":
                text = node.get_text(" ", strip=True)
                if text:
                    tk.Label(
                        self._page_frame, text=text,
                        font=FONT_SNIPPET, fg=C_SNIPPET, bg=C_PAGE,
                        wraplength=860, justify="left", anchor="w",
                    ).pack(fill="x", pady=(0, 6))
                return

            # Anchor / link
            if name == "a":
                href = node.get("href", "").strip()
                text = node.get_text(" ", strip=True) or href
                if text and href and not href.startswith(("javascript:", "mailto:")):
                    full = urljoin(base_url, href)
                    lbl  = tk.Label(
                        self._page_frame, text=text,
                        font=FONT_SNIPPET, fg=C_TITLE, bg=C_PAGE,
                        wraplength=860, justify="left", anchor="w",
                        cursor="hand2",
                    )
                    lbl.pack(fill="x")
                    lbl.bind("<Enter>", lambda e: e.widget.config(fg="#7dd3fc"))
                    lbl.bind("<Leave>", lambda e: e.widget.config(fg=C_TITLE))
                    lbl.bind("<Button-1>", lambda _, u=full: self.navigate(u))
                    set_status_on_hover(lbl, full)
                return

            # Horizontal rule
            if name == "hr":
                tk.Frame(self._page_frame, bg=C_BORDER, height=1).pack(fill="x", pady=8)
                return

            # Lists
            if name in ("ul", "ol"):
                for i, li in enumerate(node.find_all("li", recursive=False)):
                    bullet = ("• " if name == "ul" else str(i+1) + ". ")
                    text   = li.get_text(" ", strip=True)
                    if text:
                        row = tk.Frame(self._page_frame, bg=C_PAGE)
                        row.pack(fill="x", padx=(indent*20 + 10, 0), pady=1)
                        tk.Label(row, text=bullet, font=FONT_SNIPPET,
                                 fg=C_DIM, bg=C_PAGE, width=3, anchor="e"
                                 ).pack(side="left")
                        tk.Label(row, text=text, font=FONT_SNIPPET,
                                 fg=C_SNIPPET, bg=C_PAGE,
                                 wraplength=820, justify="left", anchor="w",
                                 ).pack(side="left", fill="x")
                return

            # Blockquote / pre / code
            if name in ("blockquote", "pre", "code"):
                text = node.get_text()
                if text.strip():
                    tk.Label(
                        self._page_frame, text=text,
                        font=FONT_MONO, fg="#94a3b8", bg="#0d1a2e",
                        wraplength=840, justify="left", anchor="w",
                        relief="flat", padx=10, pady=6,
                    ).pack(fill="x", pady=4, padx=10)
                return

            # Image placeholder
            if name == "img":
                alt = node.get("alt", "") or node.get("src", "image")
                tk.Label(
                    self._page_frame, text="[img: " + alt[:60] + "]",
                    font=FONT_SMALL, fg=C_DIM, bg="#0d1a2e",
                    relief="flat", padx=6, pady=4,
                ).pack(anchor="w", pady=2)
                return

            # Table — render as plain text rows
            if name == "table":
                for row in node.find_all("tr"):
                    cells = [td.get_text(" ", strip=True)
                             for td in row.find_all(["td", "th"])]
                    if cells:
                        tk.Label(
                            self._page_frame,
                            text="  │  ".join(cells),
                            font=FONT_MONO, fg=C_SNIPPET, bg=C_PAGE,
                            anchor="w",
                        ).pack(fill="x", pady=1)
                return

            # div / section / article / main / aside — recurse into children
            if name in ("div", "section", "article", "main", "aside",
                        "header", "footer", "nav", "span", "body",
                        "form", "label", "strong", "b", "em", "i",
                        "small", "center", "td", "th", "tr", "tbody",
                        "thead", "tfoot", "figure", "figcaption"):
                for child in node.children:
                    emit_block(child, indent)
                return

            # br → small spacer
            if name == "br":
                tk.Frame(self._page_frame, bg=C_PAGE, height=4).pack(fill="x")
                return

            # Anything else: just grab its text
            text = node.get_text(" ", strip=True)
            if text:
                tk.Label(
                    self._page_frame, text=text,
                    font=FONT_SNIPPET, fg=C_SNIPPET, bg=C_PAGE,
                    wraplength=860, justify="left", anchor="w",
                ).pack(fill="x")

        for child in body.children:
            emit_block(child)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _set_status(self, msg):
        self._status.config(text="  " + msg if msg else "")

    def _set_status_hover(self, widget, url):
        widget.bind("<Enter>", lambda e: self._set_status(url))
        widget.bind("<Leave>", lambda e: self._set_status(""))


# ── Main app ──────────────────────────────────────────────────────────────────

class TorSearchApp(tk.Tk):

    def __init__(self):
        super().__init__()
        ensure_db()
        self.title("TorSearch")
        self.configure(bg=C_WIN)
        self.geometry("980x740")
        self.minsize(760, 520)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._crawler_running = False
        self._tor_ok          = False
        self._tor_proc        = TorProcess(log_callback=self._log_ts)

        self._build_ui()
        self._refresh_count()

        # Auto-setup Tor after window draws
        self.after(300, self._auto_setup_tor)

    # ── Window close ──────────────────────────────────────────────────────

    def _on_close(self):
        self._crawler_running = False
        self._tor_proc.stop()
        self.destroy()

    # ── Auto Tor setup ────────────────────────────────────────────────────

    def _auto_setup_tor(self):
        """
        Called once on startup.
        1. If tor.exe already extracted → start it.
        2. Else look for a .tar.gz bundle next to the script → extract then start.
        3. Else show instructions in the console.
        """
        if is_tor_ready():
            self._log("tor.exe found — starting Tor...", "good")
            self._start_tor()
            return

        bundle = find_bundle()
        if bundle:
            self._log("Found bundle: " + os.path.basename(bundle), "good")
            self._log("Extracting — this takes a few seconds...", "dim")

            def do_extract():
                ok, msg = extract_bundle(bundle, log=self._log_ts)
                if ok:
                    self.after(0, self._start_tor)
                else:
                    self._log_ts("Extraction failed: " + msg, "error")

            threading.Thread(target=do_extract, daemon=True).start()
        else:
            self._log(
                "No Tor bundle found next to the script.", "error"
            )
            self._log(
                "Put tor-expert-bundle-*.tar.gz in the same folder as tor_search.py",
                "warn",
            )
            self._log(
                "Download from: https://www.torproject.org/download/tor/",
                "dim",
            )
            self._set_tor_status("no bundle", C_RED)

    def _start_tor(self):
        """Start tor.exe and wire up callbacks."""
        self._set_tor_status("starting...", C_ORANGE)

        self._tor_proc.start(
            on_ready=lambda: self.after(0, self._on_tor_ready),
            on_line=self._log_ts,
        )

        # Timeout: if not ready in 90 s, warn
        def timeout_check():
            if not self._tor_proc.ready:
                self._log(
                    "Tor is taking a long time — check console for errors.", "warn"
                )
        self.after(90_000, timeout_check)

    def _on_tor_ready(self):
        self._tor_ok = True
        self._set_tor_status("● Tor ON", C_GREEN)
        self._tor_badge.config(fg=C_GREEN, text="[tor ✓]")
        self._set_status("Tor connected — ready to crawl!", 5000)
        # Run connectivity confirm in background
        threading.Thread(
            target=lambda: self.after(
                0,
                lambda: self._on_tor_check(*check_tor()),
            ),
            daemon=True,
        ).start()

    # ── UI build ──────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._build_toolbar()
        self._build_pages()
        self._build_results_area()
        self._build_crawler_area()
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self, bg=C_TOOLBAR, height=38)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self._tab_results = tk.Label(
            bar, text="  🔍 Search  ", font=FONT_CHROME,
            bg=C_TAB_ACT, fg=C_TAB_TXT, relief="flat", padx=4, pady=8,
            cursor="hand2",
        )
        self._tab_results.pack(side="left", padx=(8, 0), pady=(4, 0), ipady=2)
        self._tab_results.bind("<Button-1>", lambda _: self._show_results())

        self._tab_crawler = tk.Label(
            bar, text="  🕷 Crawler  ", font=FONT_CHROME,
            bg=C_TAB_IN, fg=C_DIM, relief="flat", padx=4, pady=8,
            cursor="hand2",
        )
        self._tab_crawler.pack(side="left", padx=(2, 0), pady=(4, 0), ipady=2)
        self._tab_crawler.bind("<Button-1>", lambda _: self._show_crawler())

        self._count_lbl = tk.Label(
            bar, text="", font=FONT_CHROME, bg=C_TOOLBAR, fg=C_DIM,
        )
        self._count_lbl.pack(side="right", padx=12)

        self._tor_indicator = tk.Label(
            bar, text="● Tor starting...", font=("Segoe UI", 8),
            bg=C_TOOLBAR, fg=C_ORANGE,
        )
        self._tor_indicator.pack(side="right", padx=(0, 8))

    def _build_toolbar(self):
        bar = tk.Frame(
            self, bg=C_TOOLBAR,
            highlightbackground=C_TOOLBAR_B, highlightthickness=1,
        )
        bar.pack(fill="x", ipady=5)

        for sym in ["‹", "›", "↺"]:
            tk.Label(
                bar, text=sym, font=("Segoe UI", 14),
                bg=C_TOOLBAR, fg=C_DIM, width=2,
            ).pack(side="left", padx=4)

        addr_outer = tk.Frame(
            bar, bg=C_ADDRBAR,
            highlightbackground=C_ADDRBAR_BD, highlightthickness=1,
        )
        addr_outer.pack(side="left", fill="x", expand=True, padx=8, pady=3)

        self._tor_badge = tk.Label(
            addr_outer, text="[tor]", font=("Segoe UI", 8),
            bg=C_ADDRBAR, fg=C_ORANGE, cursor="hand2",
        )
        self._tor_badge.pack(side="left", padx=(6, 2))
        self._tor_badge.bind("<Button-1>", lambda _: self._check_tor_async())

        self._query_var = tk.StringVar()
        entry = tk.Entry(
            addr_outer, textvariable=self._query_var,
            font=FONT_ADDR, bg=C_ADDRBAR, fg="#e2e8f0",
            insertbackground="#e2e8f0", relief="flat", bd=0,
        )
        entry.pack(side="left", fill="x", expand=True, ipady=4)
        entry.bind("<Return>", lambda _: self._do_search())
        entry.bind("<FocusIn>", lambda _: addr_outer.config(
            highlightbackground=C_ADDRBAR_FO, highlightthickness=2))
        entry.bind("<FocusOut>", lambda _: addr_outer.config(
            highlightbackground=C_ADDRBAR_BD, highlightthickness=1))
        entry.focus()

        tk.Button(
            addr_outer, text="Search", command=self._do_search,
            font=FONT_CHROME, bg=C_BTN, fg="white",
            activebackground=C_BTN_HOV, relief="flat",
            padx=12, pady=3, cursor="hand2", bd=0,
        ).pack(side="right", padx=4, pady=2)

        tk.Label(
            bar, text="···", font=("Segoe UI", 14),
            bg=C_TOOLBAR, fg=C_DIM, cursor="hand2",
        ).pack(side="right", padx=8)

    def _build_pages(self):
        self._page_container = tk.Frame(self, bg=C_PAGE)
        self._page_container.pack(fill="both", expand=True)
        self._results_page = tk.Frame(self._page_container, bg=C_PAGE)
        self._crawler_page = tk.Frame(self._page_container, bg=C_WIN)
        self._results_page.place(relwidth=1, relheight=1)

    def _build_results_area(self):
        p = self._results_page
        tk.Frame(p, bg=C_BORDER, height=1).pack(fill="x")

        self._info_lbl = tk.Label(
            p,
            text="Search the indexed .onion pages above  •  "
                 "Use Crawler tab to index pages first",
            font=FONT_SMALL, fg=C_DIM, bg=C_PAGE, anchor="w",
        )
        self._info_lbl.pack(fill="x", padx=20, pady=(6, 2))
        tk.Frame(p, bg=C_BORDER, height=1).pack(fill="x")

        outer = tk.Frame(p, bg=C_PAGE)
        outer.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(outer, bg=C_PAGE, highlightthickness=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=C_PAGE)
        self._inner.bind(
            "<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")
            ),
        )
        self._canvas.create_window((0, 0), window=self._inner, anchor="nw")
        self._canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self._canvas.bind_all("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(-1*(e.delta//120), "units"))
        self._canvas.bind_all("<Button-4>",
            lambda e: self._canvas.yview_scroll(-1, "units"))
        self._canvas.bind_all("<Button-5>",
            lambda e: self._canvas.yview_scroll(1, "units"))

    def _build_crawler_area(self):
        p = self._crawler_page
        tk.Frame(p, bg=C_BORDER, height=1).pack(fill="x")

        # ── Tor status panel ──────────────────────────────────────────────
        tor_panel = tk.Frame(p, bg="#0d1a2e", relief="flat")
        tor_panel.pack(fill="x", padx=20, pady=(12, 4))

        tk.Label(
            tor_panel, text="  TOR STATUS", font=("Segoe UI", 8, "bold"),
            fg=C_DIM, bg="#0d1a2e",
        ).pack(side="left", padx=(8, 0), pady=6)

        self._tor_detail_lbl = tk.Label(
            tor_panel, text="Initialising...",
            font=("Segoe UI", 8), fg=C_ORANGE, bg="#0d1a2e",
        )
        self._tor_detail_lbl.pack(side="left", padx=8, pady=6)

        btn_frame_tor = tk.Frame(tor_panel, bg="#0d1a2e")
        btn_frame_tor.pack(side="right", padx=8)

        tk.Button(
            btn_frame_tor, text="Check", command=self._check_tor_async,
            font=FONT_SMALL, bg=C_TOOLBAR, fg=C_TAB_TXT,
            activebackground=C_TOOLBAR_B, relief="flat",
            padx=8, pady=2, cursor="hand2",
        ).pack(side="left", padx=2)

        tk.Button(
            btn_frame_tor, text="Restart Tor", command=self._restart_tor,
            font=FONT_SMALL, bg=C_TOOLBAR, fg=C_TAB_TXT,
            activebackground=C_TOOLBAR_B, relief="flat",
            padx=8, pady=2, cursor="hand2",
        ).pack(side="left", padx=2)

        # ── Crawler panel ─────────────────────────────────────────────────
        hdr = tk.Frame(p, bg=C_WIN)
        hdr.pack(fill="x", padx=20, pady=(12, 4))
        tk.Label(
            hdr, text="Crawler", font=("Segoe UI", 12, "bold"),
            fg=C_TAB_TXT, bg=C_WIN,
        ).pack(side="left")
        tk.Button(
            hdr, text="Clear Index", command=self._clear_index,
            font=FONT_SMALL, bg="#450a0a", fg=C_RED,
            activebackground="#7f1d1d", relief="flat",
            padx=8, pady=2, cursor="hand2",
        ).pack(side="right")

        seed_frame = tk.Frame(p, bg=C_WIN)
        seed_frame.pack(fill="x", padx=20, pady=(0, 6))
        tk.Label(
            seed_frame, text="Seed .onion URLs (one per line):",
            font=FONT_SMALL, fg=C_DIM, bg=C_WIN,
        ).pack(anchor="w")
        self._seed_box = scrolledtext.ScrolledText(
            seed_frame, font=FONT_MONO, bg=C_ADDRBAR, fg="#e2e8f0",
            relief="flat", bd=0, height=5, wrap="none",
            highlightbackground=C_BORDER, highlightthickness=1,
        )
        self._seed_box.pack(fill="x", pady=(2, 0))
        self._seed_box.insert(
            "1.0",
            "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion\n"
            "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion\n",
        )

        btn_row = tk.Frame(p, bg=C_WIN)
        btn_row.pack(fill="x", padx=20, pady=8)

        self._crawl_btn = tk.Button(
            btn_row, text="▶  Start Crawl",
            command=self._start_crawl, font=FONT_UI, bg=C_BTN, fg="white",
            activebackground=C_BTN_HOV, relief="flat",
            padx=14, pady=5, cursor="hand2",
        )
        self._crawl_btn.pack(side="left")

        self._stop_btn = tk.Button(
            btn_row, text="■  Stop",
            command=self._stop_crawl, font=FONT_UI,
            bg=C_TOOLBAR, fg=C_DIM,
            relief="flat", padx=14, pady=5, cursor="hand2", state="disabled",
        )
        self._stop_btn.pack(side="left", padx=(8, 0))

        self._crawl_status = tk.Label(
            btn_row, text="", font=FONT_SMALL, fg=C_DIM, bg=C_WIN,
        )
        self._crawl_status.pack(side="left", padx=12)

        tk.Label(p, text="Console", font=FONT_SMALL, fg=C_DIM,
                 bg=C_WIN).pack(anchor="w", padx=20)

        self._log_box = scrolledtext.ScrolledText(
            p, font=FONT_MONO, bg=C_LOG_BG, fg=C_LOG_TXT,
            state="disabled", relief="flat", bd=0,
            highlightbackground=C_BORDER, highlightthickness=1,
        )
        self._log_box.pack(fill="both", expand=True, padx=20, pady=(2, 12))
        self._log_box.tag_config("good",  foreground="#4ade80")
        self._log_box.tag_config("error", foreground="#f87171")
        self._log_box.tag_config("warn",  foreground="#fb923c")
        self._log_box.tag_config("dim",   foreground="#475569")

    def _build_statusbar(self):
        sb = tk.Frame(
            self, bg=C_TOOLBAR,
            highlightbackground=C_TOOLBAR_B, highlightthickness=1, height=22,
        )
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._status_lbl = tk.Label(
            sb, text="", font=("Segoe UI", 8),
            fg=C_DIM, bg=C_TOOLBAR, anchor="w",
        )
        self._status_lbl.pack(side="left", padx=8)

    # ── Tab navigation ────────────────────────────────────────────────────

    def _show_results(self):
        self._crawler_page.place_forget()
        self._results_page.place(relwidth=1, relheight=1)
        self._tab_results.config(bg=C_TAB_ACT, fg=C_TAB_TXT)
        self._tab_crawler.config(bg=C_TAB_IN, fg=C_DIM)

    def _show_crawler(self):
        self._results_page.place_forget()
        self._crawler_page.place(relwidth=1, relheight=1)
        self._tab_crawler.config(bg=C_TAB_ACT, fg=C_TAB_TXT)
        self._tab_results.config(bg=C_TAB_IN, fg=C_DIM)

    # ── Search ────────────────────────────────────────────────────────────

    def _do_search(self):
        query = self._query_var.get().strip()
        if not query:
            return
        self._show_results()
        self._info_lbl.config(text="Searching...")
        self.update_idletasks()
        self._render_results(query, search_index(query))

    def _render_results(self, query, results):
        for w in self._inner.winfo_children():
            w.destroy()

        if not results:
            tk.Label(
                self._inner,
                text='No results for "' + query + '"\n\n'
                     'Use the Crawler tab to index .onion pages first.',
                font=FONT_SNIPPET, fg=C_DIM, bg=C_PAGE, justify="center",
            ).pack(pady=60, padx=40)
            self._info_lbl.config(text="No results found")
            return

        self._info_lbl.config(
            text=str(len(results)) + " result(s) — local .onion index"
        )

        for r in results:
            card = tk.Frame(self._inner, bg=C_PAGE)
            card.pack(fill="x", padx=40, pady=(14, 0))

            url_row = tk.Frame(card, bg=C_PAGE)
            url_row.pack(fill="x")
            tk.Label(
                url_row, text=r["url"][:90], font=FONT_URL,
                fg=C_URL, bg=C_PAGE, anchor="w",
            ).pack(side="left")
            tk.Button(
                url_row, text="Open",
                command=lambda u=r["url"]: self._open_page(u),
                font=("Segoe UI", 8), bg=C_BTN, fg="white",
                activebackground=C_BTN_HOV, relief="flat",
                padx=8, cursor="hand2", bd=0,
            ).pack(side="left", padx=(6, 2))
            tk.Button(
                url_row, text="Copy URL",
                command=lambda u=r["url"]: self._copy(u),
                font=("Segoe UI", 8), bg=C_TOOLBAR, fg=C_DIM,
                activebackground=C_TOOLBAR_B, relief="flat",
                padx=6, cursor="hand2", bd=0,
            ).pack(side="left", padx=(0, 0))

            title = (r.get("title") or r["url"])[:120]
            lbl = tk.Label(
                card, text=title, font=FONT_TITLE,
                fg=C_TITLE, bg=C_PAGE, anchor="w", cursor="hand2",
            )
            lbl.pack(fill="x")
            lbl.bind("<Button-1>", lambda _, u=r["url"]: self._open_page(u))
            lbl.bind("<Enter>", lambda e: e.widget.config(fg="#7dd3fc"))
            lbl.bind("<Leave>", lambda e: e.widget.config(fg=C_TITLE))

            snippet = (r.get("snippet") or "")[:300]
            if snippet:
                tk.Label(
                    card, text=snippet, font=FONT_SNIPPET,
                    fg=C_SNIPPET, bg=C_PAGE, anchor="w",
                    wraplength=800, justify="left",
                ).pack(fill="x", pady=(2, 0))

            tk.Frame(self._inner, bg=C_BORDER, height=1).pack(
                fill="x", padx=40, pady=(10, 0)
            )

        self._canvas.yview_moveto(0)

    # ── Actions ───────────────────────────────────────────────────────────

    def _copy(self, url):
        self.clipboard_clear()
        self.clipboard_append(url)
        self._set_status("Copied: " + url, 3000)

    def _open_page(self, url):
        if not self._tor_proc.is_running():
            if not messagebox.askyesno(
                "Tor not running",
                "Tor isn't running yet. Open the page anyway?\n"
                "(Your real IP may be exposed)",
            ):
                return
        win = BrowserWindow(self, url)
        win.focus()

    def _set_status(self, msg, clear_ms=0):
        self._status_lbl.config(text=msg)
        if clear_ms:
            self.after(clear_ms, lambda: self._status_lbl.config(text=""))

    def _set_tor_status(self, text, color):
        self._tor_indicator.config(text=text, fg=color)
        if hasattr(self, "_tor_detail_lbl"):
            self._tor_detail_lbl.config(text=text, fg=color)

    def _check_tor_async(self):
        self._set_tor_status("checking...", C_ORANGE)

        def run():
            ok, msg = check_tor()
            self.after(0, lambda: self._on_tor_check(ok, msg))

        threading.Thread(target=run, daemon=True).start()

    def _on_tor_check(self, ok, msg):
        self._tor_ok = ok
        if ok:
            self._set_tor_status("● Connected — " + msg.split("IP: ")[-1], C_GREEN)
            self._tor_badge.config(fg=C_GREEN, text="[tor ✓]")
        else:
            self._set_tor_status("● " + msg, C_RED)
            self._tor_badge.config(fg=C_RED, text="[tor ✗]")
        self._log(msg, "good" if ok else "error")

    def _restart_tor(self):
        self._tor_proc.stop()
        self._set_tor_status("restarting...", C_ORANGE)
        self.after(1500, self._start_tor)

    def _clear_index(self):
        if not messagebox.askyesno(
            "Clear Index",
            "Delete all indexed pages?\nThis cannot be undone.",
        ):
            return
        r = delete_index()
        if r is True:
            self._log("Index cleared.", "warn")
            self._refresh_count()
        else:
            messagebox.showerror("Error", str(r))

    # ── Crawler ───────────────────────────────────────────────────────────

    def _start_crawl(self):
        if self._crawler_running:
            return

        raw   = self._seed_box.get("1.0", "end")
        seeds = [s.strip() for s in raw.splitlines() if s.strip()]
        if not seeds:
            messagebox.showwarning("No seeds", "Enter at least one .onion URL.")
            return

        bad = [s for s in seeds if not is_onion(s)]
        if bad:
            messagebox.showwarning(
                "Bad URL", "Not .onion addresses:\n" + "\n".join(bad[:5])
            )
            return

        if not self._tor_ok:
            if not messagebox.askyesno(
                "Tor not confirmed",
                "Tor isn't confirmed active yet.\n"
                "Crawling without Tor exposes your real IP!\n\n"
                "Continue anyway?",
            ):
                return

        self._crawler_running = True
        self._crawl_btn.config(state="disabled")
        self._stop_btn.config(state="normal", bg="#450a0a", fg=C_RED)
        self._crawl_status.config(text="Crawling...", fg=C_BTN)
        self._log("─" * 60, "dim")

        def run():
            crawl(
                seeds, DB_PATH,
                status_callback=self._log_ts,
                should_stop=lambda: not self._crawler_running,
            )
            self._crawler_running = False
            self.after(0, self._crawl_done)

        threading.Thread(target=run, daemon=True).start()

    def _stop_crawl(self):
        self._crawler_running = False
        self._log("Stop requested...", "dim")

    def _crawl_done(self):
        self._crawler_running = False
        self._crawl_btn.config(state="normal")
        self._stop_btn.config(state="disabled", bg=C_TOOLBAR, fg=C_DIM)
        self._crawl_status.config(text="Done ✓", fg=C_GREEN)
        self._refresh_count()

    # ── Logging ───────────────────────────────────────────────────────────

    def _log(self, msg, tag="info"):
        ts = time.strftime("%H:%M:%S")
        self._log_box.config(state="normal")
        self._log_box.insert("end", "[" + ts + "] " + msg + "\n", tag)
        self._log_box.see("end")
        self._log_box.config(state="disabled")

    def _log_ts(self, msg, tag="info"):
        self.after(0, lambda: self._log(msg, tag))

    def _refresh_count(self):
        n = indexed_count()
        self._count_lbl.config(
            text=str(n) + " pages indexed",
            fg=C_GREEN if n > 0 else C_DIM,
        )
        self.after(5000, self._refresh_count)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = TorSearchApp()
    app.mainloop()
