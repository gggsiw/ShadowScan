import json
import html
import threading
import random
import time
import socket
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote_plus

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

try:
    import customtkinter as ctk
    from tkinter import messagebox, filedialog
except Exception as exc:
    raise SystemExit("Missing dependency: customtkinter. Install it with 'pip install customtkinter'.") from exc

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
]

DEFAULT_TIMEOUT = (5, 12)

CRAWL_DEPTH = 1
MAX_PAGES = 30
REQUEST_DELAY_MS = 150

STRICT_MODE = True

COMMON_DIRS = [
    "admin", "login", "dashboard", "config", "uploads", "static",
    "backup", "backups", "api", "server-status", ".git", "robots.txt",
    "sitemap.xml", "phpinfo.php", ".env", "wp-admin", "wp-login.php",
    "db.sql", "dump.sql", "backup.zip", "backup.tar.gz", "config.php",
    "assets", "images", "js", "css"
]

OPEN_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "dest"]

SENSITIVE_FILES = [
    ".env", ".git/config", ".htaccess", "config.php", "wp-config.php",
    "config.yml", "config.json", "database.yml", "db.sql", "dump.sql",
    "backup.zip", "backup.tar.gz", "composer.lock", "package-lock.json",
    "yarn.lock", "id_rsa", "id_rsa.pub", "server-status", "phpinfo.php"
]

PATH_PROBES = {
    "admin_panels": ["admin", "admin/login", "administrator", "wp-admin", "cpanel", "login", "user/login"],
    "backup_files": ["backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "site.bak", "backup/"],
    "log_files": ["error.log", "access.log", "debug.log", "logs/"],
    "config_files": ["config.php", "config.yml", "config.json", "settings.py", "web.config"],
    "env_files": [".env", ".env.backup", ".env.prod"],
    "git_exposed": [".git/HEAD", ".git/config"],
    "docker_files": ["Dockerfile", "docker-compose.yml"],
    "k8s_files": ["k8s.yml", "kubernetes.yml"],
    "cloud_files": [".aws/credentials", "gcp.json", "azure.json"],
    "swagger": ["swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml", "api-docs", "docs"],
    "well_known": [".well-known/security.txt", ".well-known/assetlinks.json", ".well-known/apple-app-site-association"],
    "phpmyadmin": ["phpmyadmin", "pma", "phpmyadmin/index.php"],
    "adminer": ["adminer.php", "adminer/index.php"],
    "wp_endpoints": ["wp-login.php", "wp-admin", "wp-json", "xmlrpc.php"],
    "drupal_endpoints": ["user/login", "user/register", "core/install.php"],
    "joomla_endpoints": ["administrator", "administrator/index.php"],
    "cgi_bin": ["cgi-bin/", "cgi-bin/test.cgi"],
    "status_endpoints": ["status", "health", "healthz", "ping"],
    "metrics_endpoints": ["metrics", "prometheus", "actuator", "actuator/health"],
    "test_endpoints": ["test", "debug", "dev", "staging"],
    "upload_dirs": ["uploads", "upload", "files", "fileupload"],
    "temp_dirs": ["tmp", "temp", "cache"],
    "old_dirs": ["old", "backup_old", "archive", "legacy"],
    "ci_cd_files": [".github", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"],
    "vcs_svn": [".svn/entries", ".svn/wc.db"],
    "vcs_hg": [".hg/"],
    "idea_files": [".idea/workspace.xml"],
    "vscode_files": [".vscode/settings.json"],
}

MODULE_CATALOG = [
    ("Injection", [
        ("sql_injection", "SQLi (Error/Blind/Time)"),
        ("xss", "XSS (Advanced)"),
        ("ssti", "SSTI (Template)"),
        ("xxe", "XXE Injection"),
        ("lfi", "LFI (File Inclusion)"),
        ("rfi", "RFI (Remote)"),
        ("ssrf", "SSRF (Server Side)"),
        ("open_redirect", "Open Redirect"),
        ("header_injection", "Header Injection"),
        ("path_traversal", "Path Traversal"),
    ]),
    ("Misconfig & Headers", [
        ("headers", "Security Headers (Core)"),
        ("cors", "CORS Audit"),
        ("cookies", "Cookie Flags"),
        ("methods", "HTTP Methods"),
        ("csrf_forms", "CSRF Form Check"),
        ("host_header", "Host Header Check"),
        ("cache_control", "Cache-Control Header"),
        ("cache_control_weak", "Cache-Control Weak"),
        ("pragma", "Pragma Header"),
        ("expires", "Expires Header"),
        ("hsts", "HSTS Header"),
        ("csp", "Content-Security-Policy"),
        ("csp_report_only", "CSP Report-Only"),
        ("x_frame_options", "X-Frame-Options"),
        ("x_content_type", "X-Content-Type-Options"),
        ("referrer_policy", "Referrer-Policy"),
        ("referrer_policy_unsafe", "Referrer-Policy Unsafe"),
        ("permissions_policy", "Permissions-Policy"),
        ("x_xss_protection", "X-XSS-Protection"),
        ("expect_ct", "Expect-CT Header"),
        ("feature_policy", "Feature-Policy Header"),
        ("clear_site_data", "Clear-Site-Data Header"),
        ("x_download_options", "X-Download-Options"),
        ("x_dns_prefetch", "X-DNS-Prefetch-Control"),
        ("report_to", "Report-To Header"),
        ("nel", "NEL Header"),
        ("coop", "Cross-Origin-Opener-Policy"),
        ("coep", "Cross-Origin-Embedder-Policy"),
        ("corp", "Cross-Origin-Resource-Policy"),
        ("server_banner", "Server Banner Leak"),
        ("waf_detect", "WAF Detection"),
        ("waf_curl", "WAF Bypass"),
        ("powered_by", "X-Powered-By Leak"),
        ("server_date", "Date Header"),
        ("cookie_prefixes", "Cookie Prefixes"),
        ("cookie_path", "Cookie Path"),
        ("cookie_domain", "Cookie Domain"),
        ("set_cookie_multiple", "Multiple Set-Cookie"),
        ("rate_limit", "Rate Limit (429)")
    ]),
    ("Discovery", [
        ("directory_brute", "Dir Brute Force"),
        ("sensitive_files", "Sensitive Files"),
        ("robots", "Robots.txt"),
        ("sitemap", "Sitemap.xml"),
        ("security_txt", "Security.txt"),
        ("tech_fingerprint", "Tech Fingerprint"),
        ("graphql", "GraphQL Discovery"),
        ("js_files", "JavaScript Files"),
        ("api_endpoints", "API Endpoints"),
        ("admin_panels", "Admin Panels"),
        ("backup_files", "Backup Files"),
        ("log_files", "Log Files"),
        ("config_files", "Config Files"),
        ("env_files", "Environment Files"),
        ("git_exposed", "Git Exposure"),
        ("docker_files", "Docker Files"),
        ("k8s_files", "K8s Files"),
        ("cloud_files", "Cloud Files"),
        ("swagger", "Swagger/OpenAPI"),
        ("well_known", "Well-Known Paths"),
        ("directory_listing", "Directory Listing"),
        ("crawl_discovery", "Crawl Discovery"),
        ("param_discovery", "Parameter Discovery"),
        ("js_endpoints", "JS Endpoint Hints")
    ]),
    ("Transport", [
        ("tls", "TLS/SSL Health"),
        ("weak_tls", "Weak TLS Protocol"),
        ("cert_expiry", "Cert Expiry"),
        ("mixed_content", "Mixed Content"),
        ("http_to_https", "HTTP->HTTPS Redirect"),
        ("https_redirect_chain", "HTTPS Redirect Chain"),
    ]),
    ("HTML & Client", [
        ("inline_scripts", "Inline Scripts"),
        ("inline_styles", "Inline Styles"),
        ("sri_missing", "SRI Missing"),
        ("form_autocomplete", "Form Autocomplete"),
        ("password_autocomplete", "Password Autocomplete"),
        ("insecure_form_action", "Insecure Form Action"),
        ("external_resources", "External Resources"),
        ("exposed_comments", "Exposed Comments"),
        ("error_disclosure", "Error Disclosure"),
        ("meta_generator", "Meta Generator"),
        ("debug_params", "Debug Parameters"),
        ("password_inputs", "Password Inputs"),
        ("email_inputs", "Email Inputs"),
        ("inline_event_handlers", "Inline Event Handlers"),
        ("js_map_files", "JS Source Maps"),
        ("input_autofocus", "Autofocus Inputs"),
        ("iframe_present", "Iframes Present"),
        ("iframe_sandbox_missing", "Iframes Without Sandbox"),
        ("form_method_get", "Forms Using GET"),
        ("form_action_blank", "Form Action Blank"),
        ("input_type_file", "File Inputs"),
        ("input_type_hidden", "Hidden Inputs"),
        ("autocomplete_off_missing", "Autocomplete Not Disabled"),
        ("meta_referrer", "Meta Referrer Tag"),
        ("meta_robots", "Meta Robots Tag"),
        ("meta_viewport", "Meta Viewport Tag"),
        ("external_links", "External Links"),
        ("js_secrets", "Possible Secrets in HTML"),
        ("jwt_in_page", "JWT Token in Page"),
        ("link_preload", "Preload Links"),
        ("deprecated_tags", "Deprecated HTML Tags"),
        ("favicon_missing", "Favicon Missing"),
        ("manifest_present", "Web Manifest"),
        ("service_worker", "Service Worker"),
        ("canonical_missing", "Canonical Missing"),
        ("lang_missing", "Lang Attribute Missing"),
        ("og_tags", "OpenGraph Tags"),
        ("twitter_card", "Twitter Card"),
        ("meta_charset", "Meta Charset"),
        ("content_language", "Content-Language Header"),
        ("x_robots_tag", "X-Robots-Tag Header"),
    ]),
    ("Exposure Paths", [
        ("phpmyadmin", "phpMyAdmin"),
        ("adminer", "Adminer"),
        ("wp_endpoints", "WordPress Endpoints"),
        ("drupal_endpoints", "Drupal Endpoints"),
        ("joomla_endpoints", "Joomla Endpoints"),
        ("cgi_bin", "CGI-Bin"),
        ("status_endpoints", "Status Endpoints"),
        ("metrics_endpoints", "Metrics Endpoints"),
        ("test_endpoints", "Test/Debug Endpoints"),
        ("upload_dirs", "Upload Directories"),
        ("temp_dirs", "Temp/Cache Directories"),
        ("old_dirs", "Old/Archive Directories"),
        ("ci_cd_files", "CI/CD Files"),
        ("vcs_svn", "SVN Exposure"),
        ("vcs_hg", "Mercurial Exposure"),
        ("idea_files", "IDEA Files"),
        ("vscode_files", "VSCode Files"),
    ]),
    ("Auth & Session", [
        ("login_form", "Login Form Detected"),
        ("csrf_token_present", "CSRF Token Present"),
        ("remember_me", "Remember Me Checkbox"),
        ("logout_link", "Logout Link"),
        ("oauth_links", "OAuth Links"),
        ("jwt_storage", "JWT in Storage Script"),
        ("session_in_url", "Session ID in URL"),
        ("password_http", "Password Form Over HTTP"),
        ("auth_protected", "Protected Endpoints")
    ]),
    ("Privacy & Info", [
        ("email_disclosure", "Email Disclosure"),
        ("phone_disclosure", "Phone Disclosure"),
        ("ip_disclosure", "IP Disclosure"),
        ("internal_links", "Internal Links"),
        ("staging_keywords", "Staging Keywords"),
        ("debug_headers", "Debug Headers"),
        ("server_errors", "Server Error Pages"),
        ("directory_listing_title", "Directory Listing Title"),
        ("robots_has_sitemap", "Robots Has Sitemap"),
        ("security_txt_contact", "security.txt Contact"),
    ]),
]

class SplashScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Loading")
        self.geometry("520x300")
        self.resizable(False, False)
        self.configure(fg_color="#0b0b0b")
        self._center()

        self.logo = ctk.CTkLabel(self, text="SS", font=("Segoe UI", 44, "bold"))
        self.logo.pack(pady=(60, 6))
        self.label = ctk.CTkLabel(self, text="ShadowScan", font=("Segoe UI", 16))
        self.label.pack(pady=(0, 14))

        self.progress = ctk.CTkProgressBar(self, progress_color="#b30000", fg_color="#2a2a2a", width=360)
        self.progress.pack(pady=(0, 20))
        self.progress.set(0)

        self.attributes("-alpha", 1.0)
        self._pulse_job = None
        self._fade_job = None
        self._pulse(0.0)
        self._fade_job = self.after(1400, lambda: self._fade_out(1.0))

    def _center(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _pulse(self, value):
        next_val = value + 0.03
        if next_val > 1:
            next_val = 0.0
        if not self.winfo_exists():
            return
        self.progress.set(next_val)
        self._pulse_job = self.after(40, lambda: self._pulse(next_val))

    def _fade_out(self, alpha):
        alpha -= 0.05
        if alpha <= 0:
            try:
                if self._pulse_job:
                    self.after_cancel(self._pulse_job)
                if self._fade_job:
                    self.after_cancel(self._fade_job)
            except Exception:
                pass
            self.destroy()
            return
        try:
            self.attributes("-alpha", alpha)
        except Exception:
            self.destroy()
            return
        if not self.winfo_exists():
            return
        self._fade_job = self.after(40, lambda: self._fade_out(alpha))

class WebPentestTool(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")

        self.title("ShadowScan")
        self.geometry("1080x700")
        self.minsize(980, 640)

        self.scan_vars = {}
        self.cancel_event = threading.Event()
        self.status_animating = False
        self.progress_animating = False
        self.idle_pulse = True
        self.last_results = None

        self._build_ui()
        self._start_idle_pulse()
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color="#0a0a0a")
        sidebar.grid(row=0, column=0, sticky="nswe")
        sidebar.grid_rowconfigure(17, weight=1)

        logo_frame = ctk.CTkFrame(sidebar, fg_color="#0f0f0f", border_color="#3a0000", border_width=1)
        logo_frame.grid(row=0, column=0, padx=14, pady=(14, 10), sticky="we")
        logo_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(logo_frame, text="ShadowScan", font=("Segoe UI", 17, "bold"), text_color="#ff3333").grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")
        ctk.CTkLabel(logo_frame, text="Stealth Web Audit", font=("Segoe UI", 11), text_color="#ff5555").grid(row=1, column=0, padx=10, pady=(0, 8), sticky="w")

        ctk.CTkLabel(sidebar, text="Target URL", font=("Segoe UI", 12, "bold"), text_color="#ff3333").grid(row=1, column=0, padx=16, pady=(6, 6), sticky="w")
        self.url_entry = ctk.CTkEntry(sidebar, placeholder_text="https://example.com", fg_color="#111111", border_color="#3a0000")
        self.url_entry.grid(row=2, column=0, padx=16, pady=(0, 8), sticky="we")
        self.url_entry.insert(0, "http://127.0.0.1:5001")

        self.thread_label = ctk.CTkLabel(sidebar, text="Threads: 10", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.thread_label.grid(row=3, column=0, padx=16, pady=(6, 6), sticky="w")
        self.thread_slider = ctk.CTkSlider(
            sidebar,
            from_=1,
            to=30,
            number_of_steps=29,
            fg_color="#1a1a1a",
            progress_color="#b30000",
            button_color="#b30000",
            button_hover_color="#ff1a1a",
            command=self._on_thread_change
        )
        self.thread_slider.set(10)
        self.thread_slider.grid(row=4, column=0, padx=16, pady=(0, 8), sticky="we")

        self.preset_label = ctk.CTkLabel(sidebar, text="Preset", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.preset_label.grid(row=5, column=0, padx=16, pady=(4, 6), sticky="w")
        self.preset_menu = ctk.CTkOptionMenu(
            sidebar,
            values=["Quick", "Standard", "Deep"],
            command=self._on_preset_change,
            fg_color="#111111",
            button_color="#b30000",
            button_hover_color="#ff1a1a"
        )
        self.preset_menu.set("Standard")
        self.preset_menu.grid(row=6, column=0, padx=16, pady=(0, 8), sticky="we")

        self.strict_var = ctk.BooleanVar(value=True)
        self.strict_switch = ctk.CTkSwitch(
            sidebar,
            text="Strict Mode",
            variable=self.strict_var,
            fg_color="#b30000",
            progress_color="#b30000",
            button_color="#ff1a1a"
        )
        self.strict_switch.grid(row=7, column=0, padx=16, pady=(0, 8), sticky="w")

        self.crawl_depth_label = ctk.CTkLabel(sidebar, text="Crawl Depth: 1", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.crawl_depth_label.grid(row=8, column=0, padx=16, pady=(4, 6), sticky="w")
        self.crawl_depth_slider = ctk.CTkSlider(
            sidebar,
            from_=0,
            to=3,
            number_of_steps=3,
            fg_color="#1a1a1a",
            progress_color="#b30000",
            button_color="#b30000",
            button_hover_color="#ff1a1a",
            command=self._on_crawl_depth_change
        )
        self.crawl_depth_slider.set(1)
        self.crawl_depth_slider.grid(row=9, column=0, padx=16, pady=(0, 8), sticky="we")

        self.max_pages_label = ctk.CTkLabel(sidebar, text="Max Pages", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.max_pages_label.grid(row=10, column=0, padx=16, pady=(4, 6), sticky="w")
        self.max_pages_entry = ctk.CTkEntry(sidebar, fg_color="#111111", border_color="#3a0000")
        self.max_pages_entry.insert(0, "30")
        self.max_pages_entry.grid(row=11, column=0, padx=16, pady=(0, 8), sticky="we")

        self.delay_label = ctk.CTkLabel(sidebar, text="Delay (ms)", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.delay_label.grid(row=12, column=0, padx=16, pady=(4, 6), sticky="w")
        self.delay_entry = ctk.CTkEntry(sidebar, fg_color="#111111", border_color="#3a0000")
        self.delay_entry.insert(0, "150")
        self.delay_entry.grid(row=13, column=0, padx=16, pady=(0, 8), sticky="we")

        button_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        button_row.grid(row=14, column=0, padx=16, pady=(0, 6), sticky="we")
        button_row.grid_columnconfigure((0, 1), weight=1)
        self.start_btn = ctk.CTkButton(button_row, text="Run Audit", command=self.start_scan, fg_color="#b30000", hover_color="#ff1a1a")
        self.start_btn.grid(row=0, column=0, padx=(0, 6), pady=6, sticky="we")
        self.stop_btn = ctk.CTkButton(button_row, text="Stop", fg_color="#1a1a1a", hover_color="#2a2a2a", command=self.stop_scan)
        self.stop_btn.grid(row=0, column=1, padx=(6, 0), pady=6, sticky="we")
        self.stop_btn.configure(state="disabled")

        control_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        control_row.grid(row=15, column=0, padx=16, pady=(0, 6), sticky="we")
        control_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(control_row, text="Select All", fg_color="#1a1a1a", hover_color="#2a2a2a", command=self.select_all).grid(row=0, column=0, padx=(0, 6), pady=4, sticky="we")
        ctk.CTkButton(control_row, text="Clear All", fg_color="#1a1a1a", hover_color="#2a2a2a", command=self.clear_all).grid(row=0, column=1, padx=(6, 0), pady=4, sticky="we")

        export_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        export_row.grid(row=16, column=0, padx=16, pady=(0, 8), sticky="we")
        export_row.grid_columnconfigure((0, 1), weight=1)
        self.export_btn = ctk.CTkButton(export_row, text="Export JSON", fg_color="#1a1a1a", hover_color="#2a2a2a", command=self.export_json)
        self.export_btn.grid(row=0, column=0, padx=(0, 6), pady=4, sticky="we")
        self.export_html_btn = ctk.CTkButton(export_row, text="Export HTML", fg_color="#1a1a1a", hover_color="#2a2a2a", command=self.export_html)
        self.export_html_btn.grid(row=0, column=1, padx=(6, 0), pady=4, sticky="we")

        note = ctk.CTkLabel(sidebar, text="Authorized testing only", font=("Segoe UI", 10), text_color="#ff3333")
        note.grid(row=17, column=0, padx=16, pady=(0, 12), sticky="w")

        main = ctk.CTkFrame(self, corner_radius=0, fg_color="#0a0a0a")
        main.grid(row=0, column=1, sticky="nswe")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="we", padx=18, pady=(16, 8))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="Live Audit", font=("Segoe UI", 19, "bold"), text_color="#ff3333").grid(row=0, column=0, sticky="w")
        status_frame = ctk.CTkFrame(header, fg_color="#120000", border_color="#3a0000", border_width=1, corner_radius=12)
        status_frame.grid(row=0, column=1, sticky="e")
        self.status_label = ctk.CTkLabel(status_frame, text="Idle", font=("Segoe UI", 12, "bold"), text_color="#ff3333")
        self.status_label.grid(row=0, column=0, padx=10, pady=4)

        self.progress = ctk.CTkProgressBar(main, progress_color="#b30000", fg_color="#1a1a1a")
        self.progress.grid(row=1, column=0, sticky="we", padx=18)
        self.progress.set(0)

        content = ctk.CTkFrame(main, fg_color="#0a0a0a")
        content.grid(row=2, column=0, sticky="nswe", padx=18, pady=(8, 18))
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(0, weight=1)

        modules_panel = ctk.CTkFrame(content, width=320, fg_color="#0f0f0f", border_color="#240000", border_width=1)
        modules_panel.grid(row=0, column=0, sticky="nswe", padx=(0, 10))
        modules_panel.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(modules_panel, text="Modules", font=("Segoe UI", 15, "bold"), text_color="#ff3333").grid(row=0, column=0, padx=14, pady=(14, 6), sticky="w")
        self.search_entry = ctk.CTkEntry(modules_panel, placeholder_text="Search modules...", fg_color="#111111", border_color="#3a0000")
        self.search_entry.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="we")
        self.search_entry.bind("<KeyRelease>", self.filter_modules)

        self.modules_scroll = ctk.CTkScrollableFrame(modules_panel, corner_radius=0, fg_color="#0f0f0f")
        self.modules_scroll.grid(row=2, column=0, sticky="nswe", padx=10, pady=(0, 10))
        self._render_modules()

        results_panel = ctk.CTkFrame(content, fg_color="#0f0f0f", border_color="#240000", border_width=1)
        results_panel.grid(row=0, column=1, sticky="nswe")
        results_panel.grid_rowconfigure(1, weight=1)
        results_panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(results_panel, text="Results", font=("Segoe UI", 15, "bold"), text_color="#ff3333").grid(row=0, column=0, padx=14, pady=(14, 6), sticky="w")
        self.results_text = ctk.CTkTextbox(results_panel, wrap="word", fg_color="#0b0b0b", text_color="#ff3333", font=("Consolas", 11))
        self.results_text.grid(row=1, column=0, sticky="nswe", padx=14, pady=(0, 14))

    def _render_modules(self):
        for child in self.modules_scroll.winfo_children():
            child.destroy()

        for category, items in MODULE_CATALOG:
            header = ctk.CTkLabel(self.modules_scroll, text=category, font=("Segoe UI", 13, "bold"), text_color="#ff3333")
            header.pack(anchor="w", padx=12, pady=(12, 6))
            for key, label in items:
                var = self.scan_vars.get(key)
                if not var:
                    var = ctk.BooleanVar(value=True)
                    self.scan_vars[key] = var
                cb = ctk.CTkCheckBox(self.modules_scroll, text=label, variable=var, fg_color="#b30000", hover_color="#ff1a1a", text_color="#ff3333")
                cb.pack(anchor="w", padx=20, pady=4)

    def filter_modules(self, _event=None):
        query = self.search_entry.get().strip().lower()
        for child in self.modules_scroll.winfo_children():
            child.destroy()

        for category, items in MODULE_CATALOG:
            filtered = [(k, l) for (k, l) in items if query in l.lower() or query in k.lower()]
            if not filtered:
                continue
            header = ctk.CTkLabel(self.modules_scroll, text=category, font=("Segoe UI", 13, "bold"), text_color="#ff3333")
            header.pack(anchor="w", padx=12, pady=(12, 6))
            for key, label in filtered:
                var = self.scan_vars.get(key)
                if not var:
                    var = ctk.BooleanVar(value=True)
                    self.scan_vars[key] = var
                cb = ctk.CTkCheckBox(self.modules_scroll, text=label, variable=var, fg_color="#b30000", hover_color="#ff1a1a", text_color="#ff3333")
                cb.pack(anchor="w", padx=20, pady=4)

    def _on_preset_change(self, value):
        if value == "Quick":
            self.crawl_depth_slider.set(0)
            self.max_pages_entry.delete(0, "end")
            self.max_pages_entry.insert(0, "10")
            self.delay_entry.delete(0, "end")
            self.delay_entry.insert(0, "300")
            self.strict_var.set(True)
        elif value == "Standard":
            self.crawl_depth_slider.set(1)
            self.max_pages_entry.delete(0, "end")
            self.max_pages_entry.insert(0, "30")
            self.delay_entry.delete(0, "end")
            self.delay_entry.insert(0, "150")
            self.strict_var.set(True)
        else:
            self.crawl_depth_slider.set(2)
            self.max_pages_entry.delete(0, "end")
            self.max_pages_entry.insert(0, "120")
            self.delay_entry.delete(0, "end")
            self.delay_entry.insert(0, "80")
            self.strict_var.set(False)
        self._on_crawl_depth_change(self.crawl_depth_slider.get())

    def _on_thread_change(self, value):
        try:
            count = int(float(value))
        except Exception:
            count = int(self.thread_slider.get())
        self.thread_label.configure(text=f"Threads: {count}")

    def _on_crawl_depth_change(self, value):
        try:
            depth = int(float(value))
        except Exception:
            depth = int(self.crawl_depth_slider.get())
        self.crawl_depth_label.configure(text=f"Crawl Depth: {depth}")

    def select_all(self):
        for v in self.scan_vars.values():
            v.set(True)

    def clear_all(self):
        for v in self.scan_vars.values():
            v.set(False)

    def _get_crawl_depth(self):
        try:
            return int(float(self.crawl_depth_slider.get()))
        except Exception:
            return 1

    def _get_max_pages(self):
        try:
            val = int(self.max_pages_entry.get().strip())
            return max(1, min(val, 500))
        except Exception:
            return 30

    def _get_delay_ms(self):
        try:
            val = int(self.delay_entry.get().strip())
            return max(0, min(val, 5000))
        except Exception:
            return 150

    def _get_strict_mode(self):
        return bool(self.strict_var.get())

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return

        active_scans = [k for k, v in self.scan_vars.items() if v.get()]
        if not active_scans:
            messagebox.showwarning("No Modules", "Please select at least one module.")
            return

        self.cancel_event.clear()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.idle_pulse = False
        self._set_status("Running")
        self._start_status_animation()
        self._start_progress_animation()

        self.results_text.delete("1.0", "end")
        self.results_text.insert("end", f"[+] SHADOWSCAN ACTIVE\n[>] Target: {url}\n[>] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*70}\n")
        self.last_results = None

        thread = threading.Thread(target=self.execute_scan, args=(url, active_scans))
        thread.daemon = True
        thread.start()

    def stop_scan(self):
        self.cancel_event.set()
        self._set_status("Stopping...")

    def execute_scan(self, url, scan_types):
        try:
            scanner = ProfessionalScanner(url, self.thread_slider.get(), self.cancel_event, self._get_crawl_depth(), self._get_max_pages(), self._get_delay_ms(), self._get_strict_mode())
            results = scanner.run_all_modules(scan_types)
        except Exception as exc:
            results = {"engine": [{"type": "Scanner Error", "location": str(exc)}]}
        self.after(0, self.display_results, results)

    def display_results(self, results):
        self.last_results = results
        total_findings = 0
        for module, findings in results.items():
            self.results_text.insert("end", f"\n[#] MODULE: {module.upper()}\n")
            if not findings:
                self.results_text.insert("end", "    [-] No issues detected.\n")
            else:
                for f in findings:
                    total_findings += 1
                    self.results_text.insert("end", f"    [!] {f.get('type')}\n")
                    self.results_text.insert("end", f"    [>] Location: {f.get('location')}\n")
                    if "payload" in f:
                        self.results_text.insert("end", f"    [>] Payload: {f['payload']}\n")
                    self.results_text.insert("end", "    " + "-" * 40 + "\n")

        status_text = "Stopped" if self.cancel_event.is_set() else "Idle"
        self.results_text.insert("end", f"\n[*] Audit finished at {datetime.now().strftime('%H:%M:%S')} | Findings: {total_findings}\n")
        self.results_text.see("end")
        self._stop_status_animation(status_text)
        self._stop_progress_animation()
        self.idle_pulse = True
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def export_html(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run a scan first to export results.")
            return
        default_name = f"shadowscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")],
            initialfile=default_name
        )
        if not path:
            return
        rows = []
        total = 0
        for module, findings in self.last_results.items():
            if not findings:
                continue
            for f in findings:
                total += 1
                rows.append(f"<tr><td>{html.escape(module)}</td><td>{html.escape(str(f.get('type')))}</td><td>{html.escape(str(f.get('location')))}</td><td>{html.escape(str(f.get('payload','')))}</td></tr>")
        table = "\n".join(rows) or "<tr><td colspan='4'>No findings</td></tr>"
        html_doc = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>ShadowScan Report</title>
<style>body{{background:#0b0b0b;color:#ff3333;font-family:Consolas,monospace}}
.card{{border:1px solid #3a0000;padding:16px;margin:16px;background:#0f0f0f}}
.table{{width:100%;border-collapse:collapse}}
.table th,.table td{{border:1px solid #3a0000;padding:6px;text-align:left}}
</style></head><body>
<div class='card'><h2>ShadowScan Report</h2>
<p>Target: {html.escape(self.url_entry.get().strip())}</p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p>Total Findings: {total}</p></div>
<div class='card'><table class='table'><thead><tr><th>Module</th><th>Type</th><th>Location</th><th>Payload</th></tr></thead><tbody>
{table}
</tbody></table></div>
</body></html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_doc)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    def export_json(self):
        if not self.last_results:
            messagebox.showwarning("No Data", "Run a scan first to export results.")
            return
        default_name = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile=default_name
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.last_results, f, indent=2)
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    def _set_status(self, text):
        self.status_label.configure(text=text)

    def _start_status_animation(self):
        if self.status_animating:
            return
        self.status_animating = True
        self._animate_status()

    def _animate_status(self):
        if not self.status_animating:
            return
        base = "Running"
        dots = "." * ((int(time.time() * 2) % 3) + 1)
        self.status_label.configure(text=base + dots)
        self.after(250, self._animate_status)

    def _stop_status_animation(self, final_text):
        self.status_animating = False
        self.status_label.configure(text=final_text)

    def _start_progress_animation(self):
        if self.progress_animating:
            return
        self.progress_animating = True
        self._pulse_progress(0.0)

    def _pulse_progress(self, value):
        if not self.progress_animating:
            return
        next_val = value + 0.02
        if next_val > 1:
            next_val = 0.0
        self.progress.set(next_val)
        self.after(60, lambda: self._pulse_progress(next_val))

    def _stop_progress_animation(self):
        self.progress_animating = False
        self.progress.set(0)

    def _start_idle_pulse(self):
        self._pulse_start_button(0)

    def _pulse_start_button(self, tick):
        if not self.idle_pulse:
            return
        colors = ["#b30000", "#cc0000", "#e60000", "#cc0000"]
        self.start_btn.configure(fg_color=colors[tick % len(colors)], hover_color="#ff1a1a")
        self.after(450, lambda: self._pulse_start_button(tick + 1))

class ProfessionalScanner:
    def __init__(self, base_url, thread_limit, cancel_event, crawl_depth=1, max_pages=30, delay_ms=150, strict_mode=True):
        self.base_url = base_url.rstrip("/")
        self.threads = max(1, int(thread_limit))
        self.cancel_event = cancel_event
        self.crawl_depth = max(0, int(crawl_depth))
        self.max_pages = max(1, int(max_pages))
        self.delay_ms = max(0, int(delay_ms))
        self.strict_mode = bool(strict_mode)
        self.session = self._build_session()
        self._main_response_cache = None
        self.rate_limit_hits = 0
        self._tls_cache = None
        self.delay_ms = REQUEST_DELAY_MS
        self._last_request_ts = 0.0

    def _build_session(self):
        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def __getattr__(self, name):
        if name.startswith("_scan_"):
            key = name[len("_scan_"):]
            def _scan_wrapper():
                return self._scan_generic(key)
            return _scan_wrapper
        raise AttributeError(name)

    def _cancelled(self):
        return self.cancel_event.is_set()


    def _baseline_404(self):
        if self._main_response_cache is None:
            self._fetch_main()
        if getattr(self, "_baseline_404_cache", None) is not None:
            return self._baseline_404_cache
        rand_path = f"__shadowscan_{random.randint(100000, 999999)}__"
        url = f"{self.base_url}/{rand_path}"
        res = self._request(url, allow_redirects=True)
        baseline = {
            "status": res.status_code if res else None,
            "len": len(res.text) if res and res.text else 0,
            "title": "",
            "text": (res.text or "")[:4000] if res else ""
        }
        if res and res.text:
            soup = BeautifulSoup(res.text, "html.parser")
            if soup.title and soup.title.text:
                baseline["title"] = soup.title.text.strip().lower()
        self._baseline_404_cache = baseline
        return baseline

    def _is_soft_404(self, res, baseline):
        if not res:
            return True
        if baseline.get("status") in [403, 401] and res.status_code == baseline.get("status"):
            return True
        text = res.text or ""
        if not text:
            return res.status_code in [404]
        # Compare length and title against baseline
        blen = baseline.get("len", 0) or 0
        rlen = len(text)
        if blen and rlen:
            diff = abs(rlen - blen) / max(blen, rlen)
            if diff < 0.08:
                btitle = baseline.get("title")
                if btitle:
                    soup = BeautifulSoup(text, "html.parser")
                    title = soup.title.text.strip().lower() if soup.title and soup.title.text else ""
                    if title == btitle:
                        return True
                # fallback: shared snippet similarity
                btxt = baseline.get("text", "")
                if btxt and btxt in text:
                    return True
        return False

    def _request(self, url, method="GET", data=None, params=None, headers=None, allow_redirects=True):
        if self._cancelled():
            return None
        self._sleep_if_needed()
        try:
            merged_headers = {'User-Agent': random.choice(USER_AGENTS)}
            if headers:
                merged_headers.update(headers)
            if method.upper() == "POST":
                res = self.session.post(url, data=data, params=params, headers=merged_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
            else:
                res = self.session.get(url, params=params, headers=merged_headers, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
            if res is not None and res.status_code == 429:
                self.rate_limit_hits += 1
            return res
        except Exception:
            return None

    def _same_origin(self, url):
        try:
            base = urlparse(self.base_url)
            other = urlparse(url)
            base_port = base.port or (443 if base.scheme == "https" else 80)
            other_port = other.port or (443 if other.scheme == "https" else 80)
            return base.scheme == other.scheme and base.hostname == other.hostname and base_port == other_port
        except Exception:
            return False

    def _sleep_if_needed(self):
        if self.delay_ms <= 0:
            return
        now = time.monotonic()
        min_interval = self.delay_ms / 1000.0
        elapsed = now - self._last_request_ts
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_ts = time.monotonic()

    def _get_forms(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            action_url = urljoin(self.base_url + "/", action)
            method = form.get("method", "GET").upper()
            inputs = [i.get("name") for i in form.find_all(["input", "textarea"]) if i.get("name")]
            if inputs:
                forms.append((action_url, method, inputs))
        return forms

    def _fetch_main(self):
        if self._main_response_cache is not None:
            return self._main_response_cache
        self._main_response_cache = self._request(self.base_url)
        return self._main_response_cache

    def _fetch_tls_info(self):
        if self._tls_cache is not None:
            return self._tls_cache
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            self._tls_cache = None
            return None
        host = parsed.hostname
        port = parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    self._tls_cache = {"cert": cert, "protocol": proto}
                    return self._tls_cache
        except Exception:
            self._tls_cache = None
            return None

    def _crawl(self):
        if self.crawl_depth <= 0:
            return {self.base_url}, []
        visited = set()
        forms = []
        queue = [(self.base_url, 0)]
        while queue and len(visited) < self.max_pages and not self._cancelled():
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            res = self._request(url)
            if not res or not res.text:
                continue
            soup = BeautifulSoup(res.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action') or ''
                action_url = urljoin(url + '/', action)
                method = form.get('method', 'GET').upper()
                inputs = [i.get('name') for i in form.find_all(['input','textarea']) if i.get('name')]
                if inputs:
                    forms.append((action_url, method, inputs))
            if depth >= self.crawl_depth:
                continue
            for tag in soup.find_all(['a','link','script']):
                href = tag.get('href') or tag.get('src') or ''
                if not href or href.startswith('mailto:') or href.startswith('javascript:'):
                    continue
                next_url = urljoin(url, href.split('#')[0])
                if self._same_origin(next_url) and next_url not in visited:
                    queue.append((next_url, depth + 1))
        return visited, forms

    def run_all_modules(self, scan_types):
        results = {}
        self._crawl_cache = self._crawl()
        with ThreadPoolExecutor(max_workers=self.threads) as main_exec:
            future_to_mod = {
                main_exec.submit(getattr(self, f"_scan_{st}")): st
                for st in scan_types if hasattr(self, f"_scan_{st}")
            }
            for future in as_completed(future_to_mod):
                mod = future_to_mod[future]
                if self._cancelled():
                    results[mod] = []
                    continue
                try:
                    results[mod] = future.result()
                except Exception as exc:
                    results[mod] = [{"type": "Module Error", "location": str(exc)}]
        return results
    def _scan_sql_injection(self):
        if self._cancelled():
            return []
        findings = []
        error_p = ["' OR 1=1 --", "admin' --", "') OR ('1'='1"]
        time_p = ["1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"]

        t1 = time.time()
        orig_res = self._request(self.base_url)
        baseline_time = time.time() - t1 if orig_res else 0
        if not orig_res:
            return []

        forms = self._crawl_cache[1] if hasattr(self, "_crawl_cache") else self._get_forms(orig_res.text)
        for action, method, inputs in forms:
            if self._cancelled():
                return findings
            for field in inputs:
                for pld in time_p:
                    t_start = time.time()
                    self._request(action, method, data={field: pld} if method == "POST" else None, params={field: pld} if method == "GET" else None)
                    if (time.time() - t_start) >= (baseline_time + 4.5):
                        findings.append({"type": "Blind SQLi (Time)", "location": action, "payload": pld})
                for pld in error_p:
                    res = self._request(action, method, data={field: pld} if method == "POST" else None, params={field: pld} if method == "GET" else None)
                    if res and any(e in res.text.lower() for e in ["sql syntax", "mysql", "sqlite", "postgres"]):
                        findings.append({"type": "SQLi (Error)", "location": action, "payload": pld})
        return findings

    def _scan_xss(self):
        if self._cancelled():
            return []
        findings = []
        payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
        res_main = self._request(self.base_url)
        if not res_main:
            return []

        forms = self._crawl_cache[1] if hasattr(self, "_crawl_cache") else self._get_forms(res_main.text)
        for action, method, inputs in forms:
            if self._cancelled():
                return findings
            for pld in payloads:
                data = {i: pld for i in inputs}
                res = self._request(action, method=method, data=data if method == "POST" else None, params=data if method == "GET" else None)
                if res and pld in res.text:
                    findings.append({"type": "XSS Detected", "location": action, "payload": pld})
        return findings

    def _scan_ssrf(self):
        if self._cancelled():
            return []
        findings = []
        test_url = f"{self.base_url}/robots.txt"
        baseline = self._request(test_url)
        target = f"{self.base_url}?url={quote_plus(test_url)}&dest={quote_plus(test_url)}&proxy={quote_plus(test_url)}"

        res = self._request(target)
        if res and baseline and baseline.text[:200] and baseline.text[:200] in res.text and test_url not in res.text:
            findings.append({"type": "Verified SSRF (Fetch)", "location": target, "payload": test_url})
        return findings

    def _scan_ssti(self):
        if self._cancelled():
            return []
        findings = []
        payload = "{{7*7}}"
        target_url = f"{self.base_url}?id={payload}&name={payload}"
        res = self._request(target_url)
        if res and "49" in res.text and payload not in res.text:
            findings.append({"type": "SSTI (Possible)", "location": target_url, "payload": payload})
        return findings

    def _scan_lfi(self):
        if self._cancelled():
            return []
        findings = []
        payloads = ["../../../../etc/passwd", "/etc/passwd", "..\\..\\..\\windows\\win.ini"]
        for p in payloads:
            url = f"{self.base_url}?file={p}&page={p}"
            res = self._request(url)
            if res and ("root:x:" in res.text or "[extensions]" in res.text):
                findings.append({"type": "LFI Detected", "location": url, "payload": p})
        return findings

    def _scan_headers(self):
        if self._cancelled():
            return []
        findings = []
        res = self._request(self.base_url)
        if res:
            for h in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security"]:
                if h not in res.headers:
                    findings.append({"type": "Missing Header", "location": h})
        return findings

    def _scan_rfi(self):
        if self._cancelled():
            return []
        findings = []
        payload = "https://example.invalid/evil.txt"
        url = f"{self.base_url}?file={quote_plus(payload)}&page={quote_plus(payload)}"
        res = self._request(url)
        if res and payload in res.text:
            findings.append({"type": "Potential RFI (Reflected)", "location": url, "payload": payload})
        return findings

    def _scan_xxe(self):
        if self._cancelled():
            return []
        findings = []
        xml_payload = """<?xml version=\"1.0\"?>
<!DOCTYPE root [
<!ENTITY xxe \"XXE_PROBE\">
]>
<root>&xxe;</root>"""
        headers = {"Content-Type": "application/xml"}
        res = self._request(self.base_url, method="POST", data=xml_payload, params=None, headers=headers)
        if res and "XXE_PROBE" in res.text:
            findings.append({"type": "Potential XXE (Reflected)", "location": self.base_url, "payload": "XXE_PROBE"})
        return findings

    def _scan_directory_brute(self):
        if self._cancelled():
            return []
        findings = []
        base = self.base_url + "/"
        with ThreadPoolExecutor(max_workers=min(self.threads, 12)) as exec_pool:
            futures = {exec_pool.submit(self._request, urljoin(base, d)): d for d in COMMON_DIRS}
            for future in as_completed(futures):
                directory = futures[future]
                res = future.result()
                if res and res.status_code in [200, 301, 302, 403]:
                    findings.append({"type": f"Accessible Path ({res.status_code})", "location": urljoin(base, directory)})
        return findings

    def _scan_rate_limit(self):
        if self.rate_limit_hits > 0:
            return [{"type": "Rate Limited", "location": f"429 hits: {self.rate_limit_hits}"}]
        return []

    def _scan_cors(self):
        if self._cancelled():
            return []
        findings = []
        origin = "https://evil.example"
        headers = {"Origin": origin}
        res = self._request(self.base_url, headers=headers)
        if not res:
            return findings
        aca_origin = res.headers.get("Access-Control-Allow-Origin")
        aca_creds = res.headers.get("Access-Control-Allow-Credentials")
        if aca_origin == "*" and (aca_creds or "").lower() == "true":
            findings.append({"type": "CORS Misconfig (Wildcard + Credentials)", "location": self.base_url})
        return findings

    def _scan_open_redirect(self):
        if self._cancelled():
            return []
        findings = []
        target = "https://example.invalid"
        for param in OPEN_REDIRECT_PARAMS:
            url = f"{self.base_url}?{param}={quote_plus(target)}"
            res = self._request(url, method="GET", allow_redirects=False)
            if res and res.status_code in [301, 302, 303, 307, 308]:
                location = res.headers.get("Location", "")
                if target in location:
                    findings.append({"type": "Open Redirect", "location": url, "payload": target})
        return findings

    def _scan_robots(self):
        if self._cancelled():
            return []
        findings = []
        url = f"{self.base_url}/robots.txt"
        res = self._request(url)
        if res and res.status_code == 200:
            findings.append({"type": "Found robots.txt", "location": url})
        return findings

    def _scan_sitemap(self):
        if self._cancelled():
            return []
        findings = []
        url = f"{self.base_url}/sitemap.xml"
        res = self._request(url)
        if res and res.status_code == 200:
            findings.append({"type": "Found sitemap.xml", "location": url})
        return findings

    def _scan_tech_fingerprint(self):
        if self._cancelled():
            return []
        findings = []
        res = self._request(self.base_url)
        if not res:
            return findings
        server = res.headers.get("Server")
        powered = res.headers.get("X-Powered-By")
        if server:
            findings.append({"type": "Server Header", "location": server})
        if powered:
            findings.append({"type": "X-Powered-By Header", "location": powered})
        soup = BeautifulSoup(res.text, 'html.parser')
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            findings.append({"type": "Generator Meta", "location": generator.get("content")})
        return findings

    def _scan_methods(self):
        if self._cancelled():
            return []
        findings = []
        try:
            res = self.session.options(self.base_url, timeout=DEFAULT_TIMEOUT)
        except Exception:
            return findings
        allow = res.headers.get("Allow", "")
        if allow:
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            if dangerous:
                findings.append({"type": "Dangerous Methods Enabled", "location": allow})
        return findings

    def _scan_cookies(self):
        if self._cancelled():
            return []
        findings = []
        res = self._request(self.base_url)
        if not res:
            return findings
        cookies = res.headers.get("Set-Cookie", "")
        if not cookies:
            return findings
        if "Secure" not in cookies:
            findings.append({"type": "Cookie Missing Secure", "location": "Set-Cookie"})
        if "HttpOnly" not in cookies:
            findings.append({"type": "Cookie Missing HttpOnly", "location": "Set-Cookie"})
        if "SameSite" not in cookies:
            findings.append({"type": "Cookie Missing SameSite", "location": "Set-Cookie"})
        return findings

    def _scan_csrf_forms(self):
        if self._cancelled():
            return []
        findings = []
        res = self._request(self.base_url)
        if not res:
            return findings
        forms = self._crawl_cache[1] if hasattr(self, "_crawl_cache") else self._get_forms(res.text)
        for action, method, inputs in forms:
            if method != "POST":
                continue
            lowered = [i.lower() for i in inputs]
            if not any("csrf" in name or "token" in name for name in lowered):
                findings.append({"type": "Form Missing CSRF Token", "location": action})
        return findings
        forms = self._crawl_cache[1] if hasattr(self, "_crawl_cache") else self._get_forms(res.text)
        for action, method, inputs in forms:
            method = form.get("method", "GET").upper()
            if method != "POST":
                continue
            inputs = [i.get("name", "").lower() for i in form.find_all("input")]
            if not any("csrf" in name or "token" in name for name in inputs):
                action = urljoin(self.base_url + "/", form.get("action") or "")
                findings.append({"type": "Form Missing CSRF Token", "location": action})
        return findings

    def _scan_sensitive_files(self):
        return self._scan_path_probe("sensitive_files", SENSITIVE_FILES)

    def _scan_security_txt(self):
        if self._cancelled():
            return []
        findings = []
        url = f"{self.base_url}/.well-known/security.txt"
        res = self._request(url)
        if res and res.status_code == 200:
            findings.append({"type": "security.txt Found", "location": url})
        return findings

    def _scan_graphql(self):
        if self._cancelled():
            return []
        findings = []
        for path in ["graphql", "graphiql"]:
            url = f"{self.base_url}/{path}"
            res = self._request(url)
            if res and res.status_code in [200, 400] and ("graphql" in res.text.lower() or "query" in res.text.lower()):
                findings.append({"type": "GraphQL Endpoint", "location": url})
        return findings

    def _scan_tls(self):
        if self._cancelled():
            return []
        findings = []
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            findings.append({"type": "TLS Not Enabled", "location": self.base_url})
            return findings
        info = self._fetch_tls_info()
        if info and info.get("protocol"):
            findings.append({"type": "TLS Protocol", "location": info.get("protocol")})
        if info and info.get("cert") and info["cert"].get("notAfter"):
            findings.append({"type": "TLS Cert Expires", "location": info["cert"].get("notAfter")})
        return findings

    def _scan_weak_tls(self):
        if self._cancelled():
            return []
        findings = []
        info = self._fetch_tls_info()
        if info and info.get("protocol") in ["TLSv1", "TLSv1.1"]:
            findings.append({"type": "Weak TLS Protocol", "location": info.get("protocol")})
        return findings

    def _scan_cert_expiry(self):
        if self._cancelled():
            return []
        findings = []
        info = self._fetch_tls_info()
        if info and info.get("cert") and info["cert"].get("notAfter"):
            findings.append({"type": "TLS Cert Expires", "location": info["cert"].get("notAfter")})
        return findings

    def _scan_mixed_content(self):
        if self._cancelled():
            return []
        findings = []
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            return findings
        res = self._request(self.base_url)
        if not res:
            return findings
        if "http://" in res.text:
            findings.append({"type": "Mixed Content", "location": self.base_url})
        return findings

    def _scan_http_to_https(self):
        if self._cancelled():
            return []
        findings = []
        parsed = urlparse(self.base_url)
        if parsed.scheme == "https":
            http_url = self.base_url.replace("https://", "http://", 1)
        else:
            http_url = self.base_url
        res = self._request(http_url, allow_redirects=False)
        if res and res.status_code in [301, 302, 303, 307, 308]:
            location = res.headers.get("Location", "")
            if location.startswith("https://"):
                findings.append({"type": "HTTP Redirects to HTTPS", "location": location})
        return findings

    def _scan_crawl_discovery(self):
        if not hasattr(self, "_crawl_cache"):
            return []
        urls = list(self._crawl_cache[0])
        return [{"type": "Discovered URL", "location": u} for u in urls[:50]]

    def _scan_param_discovery(self):
        if not hasattr(self, "_crawl_cache"):
            return []
        params = set()
        for u in self._crawl_cache[0]:
            parsed = urlparse(u)
            if parsed.query:
                for part in parsed.query.split('&'):
                    if '=' in part:
                        params.add(part.split('=')[0])
        for _, _, inputs in self._crawl_cache[1]:
            for name in inputs:
                params.add(name)
        return [{"type": "Parameter", "location": p} for p in sorted(params)]

    def _scan_js_endpoints(self):
        if not hasattr(self, "_crawl_cache"):
            return []
        findings = []
        for u in self._crawl_cache[0]:
            if u.endswith('.js'):
                res = self._request(u)
                if not res or not res.text:
                    continue
                for m in re.findall(r"/api/[a-zA-Z0-9_\-/]+", res.text):
                    findings.append({"type": "JS Endpoint", "location": m})
        return findings

    def _scan_auth_protected(self):
        findings = []
        for path in ["/admin", "/dashboard", "/account", "/settings"]:
            url = self.base_url + path
            res = self._request(url, allow_redirects=False)
            if res and res.status_code in [401, 403]:
                findings.append({"type": "Protected (401/403)", "location": url})
            elif res and res.status_code in [301, 302, 303, 307, 308] and res.headers.get('Location',''):
                findings.append({"type": "Redirect to Login", "location": url})
        return findings

    def _scan_waf_detect(self):
        res = self._request(self.base_url)
        if not res:
            return []
        signatures = ["cloudflare", "sucuri", "akamai", "imperva", "f5", "barracuda", "awswaf"]
        header_blob = " ".join([f"{k}:{v}" for k,v in res.headers.items()]).lower()
        body = (res.text or "").lower()
        for sig in signatures:
            if sig in header_blob or sig in body:
                return [{"type": "WAF Detected", "location": sig}]
        return []


    def _scan_waf_curl(self):
        url = self.base_url
        cmd = f"curl -I -L --max-time 15 '{url}'"
        return [{"type": "Safe Curl Command", "location": cmd}]

    def _scan_https_redirect_chain(self):
        if self._cancelled():
            return []
        findings = []
        res = self._request(self.base_url, allow_redirects=True)
        if res and res.history:
            chain = " -> ".join([r.headers.get("Location", "") for r in res.history if r.headers.get("Location")])
            if chain:
                findings.append({"type": "Redirect Chain", "location": chain})
        return findings

    def _scan_path_probe(self, key, paths):
        if self._cancelled():
            return []
        findings = []
        base = self.base_url + "/"
        baseline = self._baseline_404()
        with ThreadPoolExecutor(max_workers=min(self.threads, 12)) as exec_pool:
            futures = {exec_pool.submit(self._request, urljoin(base, p), None, None, None, False): p for p in paths}
            for future in as_completed(futures):
                path = futures[future]
                res = future.result()
                if not res:
                    continue
                # Handle redirects: ignore redirects back to home
                if res.status_code in [301, 302, 303, 307, 308]:
                    loc = res.headers.get("Location", "")
                    if not loc:
                        continue
                    # normalize
                    if loc == "/" or loc == self.base_url or loc == self.base_url + "/":
                        continue
                    findings.append({"type": f"Redirect ({res.status_code})", "location": urljoin(base, path)})
                    continue
                if res.status_code in [200, 206, 403]:
                    if self._is_soft_404(res, baseline):
                        continue
                    findings.append({"type": f"Path Found ({res.status_code})", "location": urljoin(base, path)})
        return findings

    def _scan_generic(self, key):
        if self._cancelled():
            return []
        if key in PATH_PROBES:
            return self._scan_path_probe(key, PATH_PROBES[key])
        if key == "path_traversal":
            return self._scan_lfi()

        res = self._fetch_main()
        if not res:
            return []

        heuristic_keys = {
            "debug_params", "staging_keywords", "js_secrets", "jwt_in_page",
            "jwt_storage", "email_disclosure", "phone_disclosure", "ip_disclosure",
            "internal_links", "external_links", "external_resources",
            "cache_control_weak", "referrer_policy_unsafe", "server_date",
            "cookie_prefixes", "cookie_path", "cookie_domain", "set_cookie_multiple",
            "remember_me", "oauth_links"
        }
        findings = []
        if self.strict_mode and key in heuristic_keys:
            return findings
        headers = res.headers
        html = res.text or ""
        soup = BeautifulSoup(html, "html.parser")

        header_missing = {
            "cache_control": "Cache-Control",
            "pragma": "Pragma",
            "expires": "Expires",
            "hsts": "Strict-Transport-Security",
            "csp": "Content-Security-Policy",
            "csp_report_only": "Content-Security-Policy-Report-Only",
            "x_frame_options": "X-Frame-Options",
            "x_content_type": "X-Content-Type-Options",
            "referrer_policy": "Referrer-Policy",
            "permissions_policy": "Permissions-Policy",
            "x_xss_protection": "X-XSS-Protection",
            "expect_ct": "Expect-CT",
            "feature_policy": "Feature-Policy",
            "clear_site_data": "Clear-Site-Data",
            "x_download_options": "X-Download-Options",
            "x_dns_prefetch": "X-DNS-Prefetch-Control",
            "report_to": "Report-To",
            "nel": "NEL",
            "coop": "Cross-Origin-Opener-Policy",
            "coep": "Cross-Origin-Embedder-Policy",
            "corp": "Cross-Origin-Resource-Policy",
        }

        if key in header_missing:
            h = header_missing[key]
            if h not in headers:
                findings.append({"type": "Missing Header", "location": h})
            return findings

        if key == "cache_control_weak":
            value = headers.get("Cache-Control", "")
            if value and "no-store" not in value.lower() and "no-cache" not in value.lower():
                findings.append({"type": "Weak Cache-Control", "location": value})
        elif key == "referrer_policy_unsafe":
            value = headers.get("Referrer-Policy", "")
            if value.lower() in ["unsafe-url", "no-referrer-when-downgrade"]:
                findings.append({"type": "Unsafe Referrer-Policy", "location": value})
        elif key == "server_date":
            value = headers.get("Date")
            if value:
                findings.append({"type": "Date Header Present", "location": value})
        elif key == "cookie_prefixes":
            value = headers.get("Set-Cookie", "")
            if value and "__Host-" not in value and "__Secure-" not in value:
                findings.append({"type": "Cookie Prefix Missing", "location": "Set-Cookie"})
        elif key == "cookie_path":
            value = headers.get("Set-Cookie", "")
            if value and "Path=" not in value:
                findings.append({"type": "Cookie Path Missing", "location": "Set-Cookie"})
        elif key == "cookie_domain":
            value = headers.get("Set-Cookie", "")
            if value and "Domain=" in value:
                findings.append({"type": "Cookie Domain Attribute", "location": value})
        elif key == "set_cookie_multiple":
            count = 0
            try:
                if hasattr(res.raw, "headers") and hasattr(res.raw.headers, "get_all"):
                    count = len(res.raw.headers.get_all("Set-Cookie") or [])
            except Exception:
                count = 0
            if count > 1:
                findings.append({"type": "Multiple Set-Cookie Headers", "location": str(count)})

        if key == "server_banner" and headers.get("Server"):
            findings.append({"type": "Server Header Leak", "location": headers.get("Server")})
        elif key == "powered_by" and headers.get("X-Powered-By"):
            findings.append({"type": "X-Powered-By Leak", "location": headers.get("X-Powered-By")})
        elif key == "inline_scripts":
            if soup.find_all("script", src=False):
                findings.append({"type": "Inline Scripts Present", "location": self.base_url})
        elif key == "inline_styles":
            if soup.find_all("style"):
                findings.append({"type": "Inline Styles Present", "location": self.base_url})
        elif key == "sri_missing":
            for tag in soup.find_all(["script", "link"]):
                if tag.name == "script" and tag.get("src") and not tag.get("integrity"):
                    findings.append({"type": "SRI Missing", "location": tag.get("src")})
                if tag.name == "link" and tag.get("rel") == ["stylesheet"] and tag.get("href") and not tag.get("integrity"):
                    findings.append({"type": "SRI Missing", "location": tag.get("href")})
        elif key == "form_autocomplete":
            for form in soup.find_all("form"):
                if form.get("autocomplete") != "off":
                    findings.append({"type": "Form Autocomplete Enabled", "location": self.base_url})
                    break
        elif key == "password_autocomplete":
            for inp in soup.find_all("input"):
                if inp.get("type", "").lower() == "password" and inp.get("autocomplete") not in ["off", "new-password"]:
                    findings.append({"type": "Password Autocomplete Enabled", "location": self.base_url})
                    break
        elif key == "insecure_form_action":
            parsed = urlparse(self.base_url)
            if parsed.scheme == "https":
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action.startswith("http://"):
                        findings.append({"type": "Insecure Form Action", "location": action})
        elif key == "external_resources":
            for tag in soup.find_all(["script", "link", "img"]):
                ref = tag.get("src") or tag.get("href")
                if ref and ref.startswith("http") and not self._same_origin(ref):
                    findings.append({"type": "External Resource", "location": ref})
                    break
        elif key == "iframe_present":
            if soup.find("iframe"):
                findings.append({"type": "Iframe Present", "location": self.base_url})
        elif key == "iframe_sandbox_missing":
            for iframe in soup.find_all("iframe"):
                if not iframe.get("sandbox"):
                    findings.append({"type": "Iframe Missing Sandbox", "location": self.base_url})
                    break
        elif key == "form_method_get":
            for form in soup.find_all("form"):
                if form.get("method", "GET").upper() == "GET":
                    findings.append({"type": "Form Uses GET", "location": self.base_url})
                    break
        elif key == "form_action_blank":
            for form in soup.find_all("form"):
                if not form.get("action"):
                    findings.append({"type": "Form Action Blank", "location": self.base_url})
                    break
        elif key == "input_type_file":
            if soup.find("input", attrs={"type": "file"}):
                findings.append({"type": "File Input Present", "location": self.base_url})
        elif key == "input_type_hidden":
            if soup.find("input", attrs={"type": "hidden"}):
                findings.append({"type": "Hidden Input Present", "location": self.base_url})
        elif key == "autocomplete_off_missing":
            for form in soup.find_all("form"):
                if form.get("autocomplete") != "off":
                    findings.append({"type": "Autocomplete Not Disabled", "location": self.base_url})
                    break
        elif key == "meta_referrer":
            meta = soup.find("meta", attrs={"name": "referrer"})
            if meta and meta.get("content"):
                findings.append({"type": "Meta Referrer", "location": meta.get("content")})
        elif key == "meta_robots":
            meta = soup.find("meta", attrs={"name": "robots"})
            if meta and meta.get("content"):
                findings.append({"type": "Meta Robots", "location": meta.get("content")})
        elif key == "meta_viewport":
            meta = soup.find("meta", attrs={"name": "viewport"})
            if not meta:
                findings.append({"type": "Meta Viewport Missing", "location": self.base_url})
        elif key == "external_links":
            for tag in soup.find_all("a"):
                href = tag.get("href") or ""
                if href.startswith("http") and not self._same_origin(href):
                    findings.append({"type": "External Link", "location": href})
                    break
        elif key == "js_secrets":
            for token in ["api_key", "apikey", "secret", "token"]:
                if token in html.lower():
                    findings.append({"type": "Possible Secret Keyword", "location": token})
                    break
        elif key == "jwt_in_page":
            import re
            if re.search(r"eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.", html):
                findings.append({"type": "JWT Token Pattern", "location": self.base_url})
        elif key == "link_preload":
            if soup.find("link", attrs={"rel": "preload"}):
                findings.append({"type": "Preload Link Present", "location": self.base_url})
        elif key == "deprecated_tags":
            for tag in ["font", "center", "marquee"]:
                if soup.find(tag):
                    findings.append({"type": "Deprecated Tag", "location": tag})
                    break
        elif key == "favicon_missing":
            if not soup.find("link", attrs={"rel": lambda v: v and "icon" in v}):
                findings.append({"type": "Favicon Missing", "location": self.base_url})
        elif key == "manifest_present":
            if soup.find("link", attrs={"rel": "manifest"}):
                findings.append({"type": "Manifest Present", "location": self.base_url})
        elif key == "service_worker":
            if "serviceworker" in html.lower():
                findings.append({"type": "Service Worker Reference", "location": self.base_url})
        elif key == "canonical_missing":
            if not soup.find("link", attrs={"rel": "canonical"}):
                findings.append({"type": "Canonical Missing", "location": self.base_url})
        elif key == "lang_missing":
            html_tag = soup.find("html")
            if not html_tag or not html_tag.get("lang"):
                findings.append({"type": "Lang Attribute Missing", "location": self.base_url})
        elif key == "og_tags":
            if soup.find("meta", attrs={"property": lambda v: v and v.startswith("og:")}):
                findings.append({"type": "OpenGraph Tag Present", "location": self.base_url})
        elif key == "twitter_card":
            if soup.find("meta", attrs={"name": "twitter:card"}):
                findings.append({"type": "Twitter Card Present", "location": self.base_url})
        elif key == "meta_charset":
            if not soup.find("meta", attrs={"charset": True}):
                findings.append({"type": "Meta Charset Missing", "location": self.base_url})
        elif key == "content_language":
            value = headers.get("Content-Language")
            if value:
                findings.append({"type": "Content-Language Header", "location": value})
        elif key == "x_robots_tag":
            value = headers.get("X-Robots-Tag")
            if value:
                findings.append({"type": "X-Robots-Tag Header", "location": value})
        elif key == "exposed_comments":
            if "<!--" in html:
                findings.append({"type": "HTML Comments Found", "location": self.base_url})
        elif key == "error_disclosure":
            for token in ["Exception", "Traceback", "Stack trace", "SQLSTATE"]:
                if token.lower() in html.lower():
                    findings.append({"type": "Error Disclosure", "location": token})
                    break
        elif key == "meta_generator":
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                findings.append({"type": "Generator Meta", "location": gen.get("content")})
        elif key == "debug_params":
            if "debug" in html.lower() or "trace" in html.lower():
                findings.append({"type": "Debug Hints Found", "location": self.base_url})
        elif key == "js_files":
            for tag in soup.find_all("script"):
                if tag.get("src"):
                    findings.append({"type": "JS File", "location": tag.get("src")})
        elif key == "api_endpoints":
            if "/api/" in html or "api." in html:
                findings.append({"type": "API Endpoint Reference", "location": self.base_url})
        elif key == "directory_listing":
            if "Index of /" in html:
                findings.append({"type": "Directory Listing Enabled", "location": self.base_url})
        elif key == "password_inputs":
            if soup.find("input", attrs={"type": "password"}):
                findings.append({"type": "Password Input Present", "location": self.base_url})
        elif key == "email_inputs":
            if soup.find("input", attrs={"type": "email"}):
                findings.append({"type": "Email Input Present", "location": self.base_url})
        elif key == "inline_event_handlers":
            if "onload=" in html or "onclick=" in html:
                findings.append({"type": "Inline Event Handler Found", "location": self.base_url})
        elif key == "js_map_files":
            if ".map" in html:
                findings.append({"type": "JS Source Map Reference", "location": self.base_url})
        elif key == "input_autofocus":
            if soup.find("input", attrs={"autofocus": True}):
                findings.append({"type": "Autofocus Input", "location": self.base_url})
        elif key == "login_form":
            if soup.find("input", attrs={"type": "password"}):
                findings.append({"type": "Login Form Detected", "location": self.base_url})
        elif key == "csrf_token_present":
            found = False
            for inp in soup.find_all("input"):
                name = (inp.get("name") or "").lower()
                if "csrf" in name or "token" in name:
                    found = True
                    break
            if found:
                findings.append({"type": "CSRF Token Input Found", "location": self.base_url})
        elif key == "remember_me":
            for inp in soup.find_all("input"):
                name = (inp.get("name") or "").lower()
                if "remember" in name:
                    findings.append({"type": "Remember Me Input", "location": self.base_url})
                    break
        elif key == "logout_link":
            for tag in soup.find_all("a"):
                href = (tag.get("href") or "").lower()
                if "logout" in href:
                    findings.append({"type": "Logout Link", "location": href})
                    break
        elif key == "oauth_links":
            for tag in soup.find_all("a"):
                href = (tag.get("href") or "").lower()
                if "oauth" in href or "auth" in href:
                    findings.append({"type": "OAuth Link", "location": href})
                    break
        elif key == "jwt_storage":
            if "localstorage" in html.lower() and "token" in html.lower():
                findings.append({"type": "JWT Stored in Script", "location": self.base_url})
        elif key == "session_in_url":
            parsed = urlparse(self.base_url)
            if any(k in (parsed.query or "").lower() for k in ["session", "sid", "jsessionid"]):
                findings.append({"type": "Session ID in URL", "location": self.base_url})
        elif key == "password_http":
            parsed = urlparse(self.base_url)
            if parsed.scheme == "http" and soup.find("input", attrs={"type": "password"}):
                findings.append({"type": "Password Form Over HTTP", "location": self.base_url})
        elif key == "email_disclosure":
            import re
            if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+", html):
                findings.append({"type": "Email Address Found", "location": self.base_url})
        elif key == "phone_disclosure":
            import re
            if re.search(r"\\+?\\d[\\d\\s().-]{7,}\\d", html):
                findings.append({"type": "Phone Number Found", "location": self.base_url})
        elif key == "ip_disclosure":
            import re
            if re.search(r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b", html):
                findings.append({"type": "IP Address Found", "location": self.base_url})
        elif key == "internal_links":
            if "localhost" in html.lower() or "127.0.0.1" in html:
                findings.append({"type": "Internal Link Found", "location": self.base_url})
        elif key == "staging_keywords":
            for token in ["staging", "dev", "test"]:
                if token in html.lower():
                    findings.append({"type": "Staging Keyword", "location": token})
                    break
        elif key == "debug_headers":
            for h in ["X-Debug", "X-Trace", "X-Request-Id"]:
                if h in headers:
                    findings.append({"type": "Debug Header Present", "location": h})
                    break
        elif key == "server_errors":
            if res.status_code >= 500:
                findings.append({"type": "Server Error Response", "location": str(res.status_code)})
        elif key == "directory_listing_title":
            if "<title>Index of /" in html:
                findings.append({"type": "Directory Listing Title", "location": self.base_url})
        elif key == "robots_has_sitemap":
            robots = self._request(f"{self.base_url}/robots.txt")
            if robots and "Sitemap:" in robots.text:
                findings.append({"type": "Robots Contains Sitemap", "location": f"{self.base_url}/robots.txt"})
        elif key == "security_txt_contact":
            sec = self._request(f"{self.base_url}/.well-known/security.txt")
            if sec and ("contact:" in sec.text.lower() or "policy:" in sec.text.lower()):
                findings.append({"type": "security.txt Contact/Policy", "location": f"{self.base_url}/.well-known/security.txt"})
        elif key == "header_injection":
            test_url = f"{self.base_url}%0d%0aX-Test-Header:injected"
            res2 = self._request(test_url)
            if res2 and res2.headers.get("X-Test-Header") == "injected":
                findings.append({"type": "Header Injection", "location": test_url})
        return findings

if __name__ == "__main__":
    splash = SplashScreen()
    splash.mainloop()
    app = WebPentestTool()
    app.mainloop()
