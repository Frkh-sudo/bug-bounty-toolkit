"""
BugKit v4 — Technology Fingerprint Registry

Single source of truth for all tech-stack detection signatures used by:
  • recon/scanner.py       (HTTP header + body fingerprinting)
  • jsintel/analyzer.py   (JS framework detection)
  • reports/generator.py  (tech-aware remediation hints)

Structure:
  TECH_HEADERS  — header key/value patterns → tech label
  TECH_BODY     — body regex patterns → tech label
  TECH_PATHS    — known path patterns per tech (for targeted probing)
  CLOUD_SIGNATURES — subdomain takeover fingerprints (25+ services)
  WAF_SIGNATURES   — WAF detection by header/body
  LANGUAGE_HINTS   — backend language detection
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# ── HTTP Header → Tech label ───────────────────────────────────────────
# Each entry: header_name_lowercase → (match_substring, label)
# If match_substring is "", any non-empty value matches.

TECH_HEADERS: List[Tuple[str, str, str]] = [
    ("x-powered-by",              "php",         "PHP"),
    ("x-powered-by",              "asp.net",     "ASP.NET"),
    ("x-powered-by",              "express",     "Express.js"),
    ("x-powered-by",              "next.js",     "Next.js"),
    ("x-powered-by",              "django",      "Django"),
    ("x-powered-by",              "rails",       "Ruby on Rails"),
    ("x-powered-by",              "laravel",     "Laravel"),
    ("x-generator",               "drupal",      "Drupal"),
    ("x-generator",               "wordpress",   "WordPress"),
    ("x-drupal-cache",            "",            "Drupal"),
    ("x-drupal-dynamic-cache",    "",            "Drupal"),
    ("x-wp-total",                "",            "WordPress"),
    ("x-wp-totalpages",           "",            "WordPress"),
    ("x-wc-store-api-nonce",      "",            "WooCommerce"),
    ("x-shopify-stage",           "",            "Shopify"),
    ("x-shopify-shop-api-call-limit","",         "Shopify"),
    ("x-laravel-session",         "",            "Laravel"),
    ("set-cookie",                "laravel_session", "Laravel"),
    ("set-cookie",                "PHPSESSID",   "PHP"),
    ("set-cookie",                "JSESSIONID",  "Java/Tomcat"),
    ("set-cookie",                "ASP.NET_SessionId", "ASP.NET"),
    ("set-cookie",                "django",      "Django"),
    ("set-cookie",                "csrftoken",   "Django"),
    ("server",                    "nginx",       "Nginx"),
    ("server",                    "apache",      "Apache"),
    ("server",                    "iis",         "IIS"),
    ("server",                    "cloudflare",  "Cloudflare"),
    ("server",                    "lighttpd",    "Lighttpd"),
    ("server",                    "gunicorn",    "Gunicorn/Python"),
    ("server",                    "caddy",       "Caddy"),
    ("server",                    "openresty",   "OpenResty"),
    ("cf-ray",                    "",            "Cloudflare"),
    ("cf-cache-status",           "",            "Cloudflare"),
    ("x-amzn-requestid",          "",            "AWS"),
    ("x-amz-cf-id",               "",            "AWS CloudFront"),
    ("x-amz-request-id",          "",            "AWS S3"),
    ("x-cache",                   "cloudfront",  "AWS CloudFront"),
    ("x-envoy-upstream-service-time","",         "Envoy/Istio"),
    ("x-kong-upstream-latency",   "",            "Kong API Gateway"),
    ("x-varnish",                 "",            "Varnish"),
    ("via",                       "varnish",     "Varnish"),
    ("x-github-request-id",       "",            "GitHub Pages"),
    ("x-served-by",               "cache",       "Fastly"),
    ("fastly-restarts",           "",            "Fastly"),
    ("x-azure-ref",               "",            "Azure"),
    ("x-ms-request-id",           "",            "Azure"),
    ("x-goog-generation",         "",            "Google Cloud"),
    ("x-firebase-cache",          "",            "Firebase"),
    ("x-frame-options",           "",            "_security_header"),
    ("content-security-policy",   "",            "_security_header"),
    ("strict-transport-security", "",            "_security_header"),
    ("x-content-type-options",    "",            "_security_header"),
    ("x-xss-protection",          "",            "_security_header"),
    ("x-ratelimit-limit",         "",            "_rate_limited"),
    ("ratelimit-limit",           "",            "_rate_limited"),
]


# ── Response body regex → Tech label ─────────────────────────────────
# Each entry: (tech_label, [regex_patterns])

TECH_BODY: Dict[str, List[str]] = {
    "WordPress":     [r"wp-content", r"wp-includes", r"/wp-json/"],
    "Joomla":        [r"Joomla!", r"/components/com_", r"option=com_"],
    "Drupal":        [r"drupal\.org", r"/sites/default/files", r"Drupal\.settings"],
    "Magento":       [r"Mage\.Cookies", r"var BLANK_URL", r"mage/requirejs"],
    "PrestaShop":    [r"prestashop", r"var prestashop"],
    "Shopify":       [r"Shopify\.theme", r"cdn\.shopify\.com"],
    "WooCommerce":   [r"woocommerce", r"wc-ajax"],
    "React":         [r"__reactFiber", r"data-reactroot", r"__react"],
    "Angular":       [r"ng-version", r"ng-app", r"angular\.min\.js"],
    "Vue":           [r"__vue__", r"v-cloak", r"vue\.min\.js"],
    "Svelte":        [r"svelte-", r"__svelte"],
    "Next.js":       [r"__NEXT_DATA__", r"/_next/static"],
    "Nuxt":          [r"__NUXT__", r"_nuxt/"],
    "Ember.js":      [r"ember-application", r"data-ember"],
    "jQuery":        [r"jquery\.min\.js", r"jQuery\.fn\.jquery"],
    "Bootstrap":     [r"bootstrap\.min\.css", r"bootstrap\.bundle"],
    "Laravel":       [r"laravel_session", r"_token.*csrf"],
    "Django":        [r"csrfmiddlewaretoken", r"django\.jQuery", r"__django"],
    "Rails":         [r"authenticity_token", r"rails-ujs", r"ActionController"],
    "Spring":        [r"org\.springframework", r"spring-security"],
    "ASP.NET":       [r"__VIEWSTATE", r"__EVENTVALIDATION", r"WebResource\.axd"],
    "Express.js":    [r"X-Powered-By.*Express"],
    "GraphQL":       [r"\"__schema\"", r"graphql", r"\"__typename\""],
    "Elasticsearch": [r"\"_index\"", r"\"_shards\"", r"elasticsearch"],
    "Nginx":         [r"nginx", r"<center>nginx</center>"],
    "Apache":        [r"Apache/2\.", r"Apache Server"],
    "Tomcat":        [r"Apache Tomcat", r"JSESSIONID"],
    "Cloudflare":    [r"cloudflare-nginx", r"cdn-cgi"],
    "AWS":           [r"amazonaws\.com", r"s3\.amazonaws"],
    "GCP":           [r"storage\.googleapis\.com", r"googleusercontent\.com"],
    "Stripe":        [r"stripe\.com/v3", r"Stripe\.setPublishableKey"],
    "Intercom":      [r"intercomcdn\.com", r"window\.intercomSettings"],
    "Zendesk":       [r"zendesk\.com", r"zendeskWidget"],
    "HubSpot":       [r"js\.hs-scripts\.com", r"hubspot"],
    "Segment":       [r"cdn\.segment\.com", r"analytics\.identify"],
    "Sentry":        [r"browser\.sentry-cdn\.com", r"Sentry\.init"],
    "Datadog":       [r"datadoghq\.com", r"DD_RUM"],
}


# ── Known paths per tech (targeted probing) ───────────────────────────

TECH_PATHS: Dict[str, List[str]] = {
    "WordPress":  ["/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
                   "/wp-content/", "/xmlrpc.php"],
    "Joomla":     ["/administrator/", "/configuration.php", "/api/index.php"],
    "Drupal":     ["/user/login", "/admin/", "/sites/default/settings.php"],
    "Laravel":    ["/horizon", "/telescope", "/_ignition/health-check"],
    "Django":     ["/admin/", "/admin/login/"],
    "Rails":      ["/rails/info", "/sidekiq", "/letter_opener"],
    "Spring":     ["/actuator", "/actuator/health", "/actuator/env",
                   "/actuator/beans", "/actuator/mappings"],
    "Express.js": ["/graphql", "/api-docs"],
    "GraphQL":    ["/graphql", "/graphiql", "/api/graphql", "/graphql/playground"],
    "Elasticsearch": ["/_cat/indices", "/_cluster/health", "/_nodes"],
    "Strapi":     ["/admin", "/api/"],
    "Ghost":      ["/ghost/api/", "/ghost/"],
    "Swagger":    ["/swagger-ui.html", "/api-docs", "/swagger/index.html"],
}


# ── Subdomain takeover fingerprints ──────────────────────────────────
# (service_name, body_fingerprint, cname_pattern_or_empty)

CLOUD_SIGNATURES: List[Tuple[str, str, str]] = [
    ("GitHub Pages",       "There isn't a GitHub Pages site here",   r"\.github\.io$"),
    ("GitHub Pages",       "github.com/404",                          r"\.github\.io$"),
    ("Heroku",             "No such app",                             r"herokuapp\.com$"),
    ("Heroku",             "no-such-app.html",                        r"heroku\.com$"),
    ("Fastly",             "Fastly error: unknown domain",            r"fastly\.net$"),
    ("Netlify",            "Not Found - Request ID",                  r"netlify\.app$"),
    ("Netlify",            "netlify team slug",                       r"netlify\.com$"),
    ("AWS S3",             "NoSuchBucket",                            r"s3\.amazonaws\.com$"),
    ("AWS S3",             "The specified bucket does not exist",     r"s3\.amazonaws\.com$"),
    ("AWS CloudFront",     "ERROR: The request could not be satisfied",r"cloudfront\.net$"),
    ("Azure Web Apps",     "404 Web Site not found",                  r"azurewebsites\.net$"),
    ("Azure CDN",          "The page you are looking for",            r"azureedge\.net$"),
    ("Azure Traffic Mgr",  "404 Not Found: Azure Traffic Manager",    r"trafficmanager\.net$"),
    ("Shopify",            "Sorry, this shop is currently unavailable",r"myshopify\.com$"),
    ("Tumblr",             "Whatever you were looking for doesn't live here",r"tumblr\.com$"),
    ("Ghost",              "The thing you were looking for is no longer here",r"ghost\.io$"),
    ("Surge.sh",           "project not found",                       r"surge\.sh$"),
    ("Zendesk",            "Help Center Closed",                      r"zendesk\.com$"),
    ("UserVoice",          "This UserVoice subdomain is currently available",r"uservoice\.com$"),
    ("Statuspage.io",      "Better Uptime",                           r"statuspage\.io$"),
    ("WP Engine",          "This site is temporarily unavailable",    r"wpengine\.com$"),
    ("Webflow",            "The page you are looking for doesn't exist",r"webflow\.io$"),
    ("Pantheon",           "The gods are wise, but do not know",      r"pantheonsite\.io$"),
    ("Helpjuice",          "We could not find what you're looking for",r"helpjuice\.com$"),
    ("Freshdesk",          "There is no such company",                r"freshdesk\.com$"),
    ("Unbounce",           "The requested URL was not found",         r"unbounce\.com$"),
    ("Intercom",           "Uh oh. That page doesn't exist.",         r"intercom\.help$"),
    ("Pingdom",            "Sorry, couldn't find the status page",    r"pingdom\.com$"),
    ("Readme.io",          "is not a project we know about",          r"readme\.io$"),
    ("Fly.io",             "404 Not Found",                           r"fly\.dev$"),
    ("Render",             "No such app",                             r"onrender\.com$"),
    ("Railway",            "Application not found",                   r"railway\.app$"),
    ("Vercel",             "The deployment you're looking for",       r"vercel\.app$"),
    ("Squarespace",        "This domain has not been activated",      r"squarespace\.com$"),
]


# ── WAF detection ─────────────────────────────────────────────────────

WAF_SIGNATURES: List[Tuple[str, str, str]] = [
    # (waf_name, header_key, header_value_pattern)
    ("Cloudflare",  "server",              "cloudflare"),
    ("Cloudflare",  "cf-ray",              ""),
    ("Akamai",      "x-check-cacheable",   ""),
    ("Akamai",      "x-akamai-request-id", ""),
    ("AWS WAF",     "x-amzn-requestid",    ""),
    ("Sucuri",      "x-sucuri-id",         ""),
    ("Sucuri",      "x-sucuri-cache",      ""),
    ("Imperva",     "x-iinfo",             ""),
    ("ModSecurity", "x-mod-security-message",""),
    ("Barracuda",   "barra_counter_session",""),
    ("Comodo",      "x-protected-by",      "comodo"),
    ("F5 BIG-IP",   "x-wa-info",           ""),
    ("Fastly",      "x-fastly-request-id", ""),
    ("Varnish",     "x-varnish",           ""),
]

WAF_BODY_SIGNATURES: List[Tuple[str, str]] = [
    ("Cloudflare",  "Cloudflare Ray ID"),
    ("AWS WAF",     "AWS WAF"),
    ("ModSecurity", "ModSecurity Action"),
    ("Sucuri",      "Sucuri WebSite Firewall"),
    ("Imperva",     "Incapsula incident ID"),
    ("Akamai",      "Reference #18."),
    ("Barracuda",   "You have been blocked"),
    ("Wordfence",   "Generated by Wordfence"),
]


# ── Backend language hints ────────────────────────────────────────────

LANGUAGE_HINTS: Dict[str, List[str]] = {
    "PHP":         ["PHPSESSID", ".php", "X-Powered-By: PHP"],
    "Python":      ["X-Powered-By: Django", "gunicorn", "uvicorn", "csrftoken"],
    "Ruby":        ["X-Powered-By: Phusion Passenger", "authenticity_token"],
    "Java":        ["JSESSIONID", "X-Powered-By: Servlet", "Tomcat"],
    "Node.js":     ["X-Powered-By: Express", "x-request-id"],
    "Go":          ["X-Powered-By: go", "Go-http-client"],
    "ASP.NET":     ["X-Powered-By: ASP.NET", "__VIEWSTATE", "X-AspNet-Version"],
    "Rust":        ["actix-web", "warp"],
}


# ── Fingerprint helper functions ───────────────────────────────────────

def fingerprint_response(
    headers: Dict[str, str],
    body:    str,
) -> List[str]:
    """
    Return a deduplicated list of detected technology labels.
    Skips internal labels starting with '_'.
    """
    detected: set = set()
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # Header fingerprints
    for hdr_name, match_val, label in TECH_HEADERS:
        if hdr_name in h_lower:
            hdr_val = h_lower[hdr_name]
            if not match_val or match_val.lower() in hdr_val:
                if not label.startswith("_"):
                    detected.add(label)

    # Body fingerprints
    for label, patterns in TECH_BODY.items():
        for pat in patterns:
            if re.search(pat, body, re.I):
                detected.add(label)
                break

    return sorted(detected)


def detect_waf(
    headers: Dict[str, str],
    body:    str,
) -> Optional[str]:
    """Return the first detected WAF name, or None."""
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for waf_name, hdr_key, hdr_val_pattern in WAF_SIGNATURES:
        if hdr_key in h_lower:
            if not hdr_val_pattern or hdr_val_pattern in h_lower[hdr_key]:
                return waf_name

    for waf_name, body_sig in WAF_BODY_SIGNATURES:
        if body_sig.lower() in body.lower():
            return waf_name

    return None


def paths_for_tech(tech_label: str) -> List[str]:
    """Return known sensitive paths for a detected tech stack."""
    return TECH_PATHS.get(tech_label, [])


def check_takeover(body: str, cname: str = "") -> Optional[str]:
    """
    Check if body/CNAME matches any known subdomain takeover signature.
    Returns service name if match found, else None.
    """
    for service, body_sig, cname_pattern in CLOUD_SIGNATURES:
        if body_sig and body_sig.lower() in body.lower():
            return service
        if cname_pattern and cname and re.search(cname_pattern, cname, re.I):
            # Body check failed but CNAME matches — flag for manual review
            pass
    return None
