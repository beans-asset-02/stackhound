#!/usr/bin/env python3
"""
stackhound — map an org's SaaS footprint from a domain name.

Enumerates predictable tenant URLs (slug.slack.com, slug.atlassian.net, etc.)
and validates responses with an 8-layer filter to cut false positives.

Usage: python3 stackhound.py <domain>
"""

import asyncio
import time
import socket
import ssl
import json
import re
import argparse
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box

console = Console()

BANNER = r"""
[bold red]
   _____ __             __   __  __                      __
  / ___// /_____ ______/ /__/ / / /___  __  ______  ____/ /
  \__ \/ __/ __ `/ ___/ //_/ /_/ / __ \/ / / / __ \/ __  / 
 ___/ / /_/ /_/ / /__/ ,< / __  / /_/ / /_/ / / / / /_/ /  
/____/\__/\__,_/\___/_/|_/_/ /_/\____/\__,_/_/ /_/\__,_/   
[/bold red]
[dim]SaaS Tenant Reconnaissance · v3.0[/dim]
[dim]───────────────────────────────────────────────────[/dim]
"""

# ─── types ────────────────────────────────────────────────────

@dataclass
class SaaSTarget:
    category: str
    service: str
    url_pattern: str

    # where the slug should end up after redirects: "subdomain", "path", or "any"
    slug_location: str = "subdomain"

    valid_codes: list = field(default_factory=lambda: [200])

    # body strings that mean "this tenant doesn't exist"
    not_found_body: list = field(default_factory=list)

    # URL path fragments that mean the same thing (e.g. /oops, /slug_not_found)
    not_found_url: list = field(default_factory=list)

    # at least one of these must show up in the body or we bail
    require_body: list = field(default_factory=list)

    # tiny pages are almost always error stubs
    min_body_size: int = 1000

    # reject if final URL lost the slug (service bounced us to its homepage)
    strict_redirect: bool = True

    # if the page title is *exactly* one of these, it's the homepage not a tenant
    generic_titles: list = field(default_factory=list)


@dataclass
class ScanResult:
    category: str
    service: str
    url: str
    final_url: str
    status: int
    title: str
    slug: str
    confidence: str  # HIGH, MEDIUM, LOW


# ─── bad-URL patterns ─────────────────────────────────────────

GENERIC_NOT_FOUND_URL = [
    "slug_not_found",
    "/404",
    "/not-found",
    "/error",
    "/oops",
    "/page-not-found",
]

# ─── bad-body patterns ────────────────────────────────────────

GLOBAL_NOT_FOUND_BODY = [
    "does not exist",
    "doesn't exist",
    "page not found",
    "workspace not found",
    "organization not found",
    "account not found",
    "team not found",
    "invalid subdomain",
    "is not active",
    "no organization",
    "there is nothing here",
    "there's nothing here",
    "we couldn't find",
    "we can't find",
    "this site can't be reached",
    "claim your url",
    "claim your site",
    "this page isn't available",
    "this workspace does not exist",
    "slug_not_found",
]

# ─── targets ──────────────────────────────────────────────────
# each target has per-service validation tuned against real-world FPs.
# if you add a new service, test it with a known bad slug first.

SAAS_TARGETS = [

    # ═══ Identity & SSO ═══
    SaaSTarget("Identity & SSO", "Okta", "https://{slug}.okta.com",
               slug_location="subdomain",
               not_found_body=["sign-in widget"],
               generic_titles=["sign in", "okta", "sign in to your account"],
               require_body=["okta"],
               min_body_size=2000),
    SaaSTarget("Identity & SSO", "Auth0", "https://{slug}.auth0.com",
               slug_location="subdomain",
               generic_titles=["auth0", "log in", "secure ai agent"],
               min_body_size=2000),
    SaaSTarget("Identity & SSO", "OneLogin", "https://{slug}.onelogin.com",
               slug_location="subdomain",
               generic_titles=["onelogin"],
               min_body_size=2000),
    SaaSTarget("Identity & SSO", "Duo Security", "https://{slug}.duosecurity.com",
               slug_location="subdomain",
               generic_titles=["duo", "duo security", "complete identity security"],
               min_body_size=2000),

    # ═══ Collaboration ═══
    SaaSTarget("Collaboration", "Slack", "https://{slug}.slack.com",
               slug_location="subdomain",
               not_found_body=["create a new workspace", "no such workspace",
                                "this workspace does not exist",
                                "workspace not found", "find your workspace"],
               generic_titles=["slack"],
               min_body_size=3000),
    SaaSTarget("Collaboration", "Atlassian", "https://{slug}.atlassian.net",
               slug_location="subdomain",
               valid_codes=[200, 302, 303],
               not_found_body=["is not available", "sign up"],
               generic_titles=["atlassian"],
               min_body_size=2000),
    SaaSTarget("Collaboration", "Notion", "https://{slug}.notion.site",
               slug_location="subdomain",
               valid_codes=[200, 301],
               not_found_body=["page not found"],
               # notion returns 200 with just "Notion" for non-existent sites
               generic_titles=["notion", "notion – the all-in-one workspace",
                                "notion - the all-in-one workspace"],
               min_body_size=3000),
    SaaSTarget("Collaboration", "Monday.com", "https://{slug}.monday.com",
               slug_location="subdomain",
               not_found_body=["page not found", "slug_not_found"],
               not_found_url=["slug_not_found"],
               generic_titles=["monday.com", "where teams get work done",
                                "monday.com: where teams get work done",
                                "a platform built for a new way of working"],
               min_body_size=3000),
    SaaSTarget("Collaboration", "Teamwork", "https://{slug}.teamwork.com",
               slug_location="subdomain",
               generic_titles=["teamwork", "teamwork projects",
                                "teamwork.com", "project management software"],
               not_found_body=["get started for free", "start for free"],
               min_body_size=5000),
    SaaSTarget("Collaboration", "ClickUp", "https://app.clickup.com/{slug}",
               slug_location="path",
               generic_titles=["clickup"],
               not_found_body=["not found"],
               min_body_size=3000),
    SaaSTarget("Collaboration", "Coda", "https://coda.io/@{slug}",
               slug_location="path",
               not_found_body=["page not found"],
               min_body_size=3000),
    SaaSTarget("Collaboration", "Basecamp", "https://{slug}.basecamphq.com",
               slug_location="subdomain",
               not_found_body=["not found"],
               min_body_size=2000),

    # ═══ Support & CX ═══
    SaaSTarget("Support & CX", "Zendesk", "https://{slug}.zendesk.com",
               slug_location="subdomain",
               not_found_body=["this help center no longer exists",
                                "page not found", "help center not found"],
               generic_titles=["zendesk"],
               min_body_size=3000),
    SaaSTarget("Support & CX", "Freshdesk", "https://{slug}.freshdesk.com",
               slug_location="subdomain",
               not_found_body=["account does not exist", "there's no account",
                                "does not exist"],
               generic_titles=["freshdesk"],
               min_body_size=2000),
    SaaSTarget("Support & CX", "Freshservice", "https://{slug}.freshservice.com",
               slug_location="subdomain",
               not_found_body=["does not exist"],
               generic_titles=["freshservice"],
               min_body_size=2000),
    SaaSTarget("Support & CX", "Intercom Docs", "https://{slug}.intercom.help",
               slug_location="subdomain",
               not_found_body=["not found"],
               generic_titles=["intercom"],
               min_body_size=2000),
    SaaSTarget("Support & CX", "HelpScout", "https://{slug}.helpscoutdocs.com",
               slug_location="subdomain",
               not_found_body=["not found"],
               min_body_size=2000),
    SaaSTarget("Support & CX", "ServiceNow", "https://{slug}.service-now.com",
               slug_location="subdomain",
               not_found_body=["not found"],
               generic_titles=["servicenow"],
               min_body_size=2000),

    # ═══ Infrastructure & Status ═══
    SaaSTarget("Infrastructure", "Statuspage", "https://{slug}.statuspage.io",
               slug_location="subdomain",
               not_found_body=["you may have mistyped", "page not found"],
               generic_titles=["statuspage", "atlassian statuspage",
                                "improve transparency with statuspage"],
               min_body_size=3000),
    SaaSTarget("Infrastructure", "BetterUptime", "https://{slug}.betteruptime.com",
               slug_location="subdomain",
               generic_titles=["better stack", "betteruptime",
                                "uptime monitoring by better stack",
                                "better uptime"],
               min_body_size=3000),
    SaaSTarget("Infrastructure", "Instatus", "https://{slug}.instatus.com",
               slug_location="subdomain",
               generic_titles=["instatus", "get ready for downtime",
                                "instatus - get ready for downtime"],
               min_body_size=3000),
    SaaSTarget("Infrastructure", "Vercel", "https://{slug}.vercel.app",
               slug_location="subdomain",
               not_found_body=["the deployment could not be found", "not found"],
               min_body_size=500),
    SaaSTarget("Infrastructure", "Netlify", "https://{slug}.netlify.app",
               slug_location="subdomain",
               not_found_body=["page not found", "not found"],
               min_body_size=500),
    SaaSTarget("Infrastructure", "Heroku", "https://{slug}.herokuapp.com",
               slug_location="subdomain",
               not_found_body=["no such app", "there is no app",
                                "application error"],
               min_body_size=500),
    SaaSTarget("Infrastructure", "Fly.io", "https://{slug}.fly.dev",
               slug_location="subdomain",
               not_found_body=["not found"],
               min_body_size=500),
    SaaSTarget("Infrastructure", "Render", "https://{slug}.onrender.com",
               slug_location="subdomain",
               not_found_body=["not found"],
               min_body_size=500),

    # ═══ Dev & Code ═══
    SaaSTarget("Dev & Code", "GitHub", "https://github.com/{slug}",
               slug_location="path",
               strict_redirect=True,
               min_body_size=50000,
               not_found_body=["not found"]),
    SaaSTarget("Dev & Code", "GitLab", "https://gitlab.com/{slug}",
               slug_location="path",
               not_found_body=["the page could not be found", "not found"],
               min_body_size=5000),
    SaaSTarget("Dev & Code", "Bitbucket", "https://bitbucket.org/{slug}",
               slug_location="path",
               not_found_body=["we can't find", "not found"],
               min_body_size=5000),
    SaaSTarget("Dev & Code", "Docker Hub", "https://hub.docker.com/u/{slug}",
               slug_location="path",
               require_body=["repository"],
               not_found_body=["httperror 404"],
               min_body_size=3000),
    SaaSTarget("Dev & Code", "npm Org", "https://www.npmjs.com/org/{slug}",
               slug_location="path",
               not_found_body=["not found", "page not found", "404"],
               min_body_size=3000),
    SaaSTarget("Dev & Code", "Sentry", "https://sentry.io/organizations/{slug}/",
               slug_location="path",
               not_found_url=["/auth/login", "/auth/", "/login"],
               generic_titles=["sentry", "sign in"],
               min_body_size=3000),
    SaaSTarget("Dev & Code", "Snyk", "https://app.snyk.io/org/{slug}",
               slug_location="path",
               not_found_body=["not found"],
               not_found_url=["/login"],
               generic_titles=["snyk"],
               min_body_size=3000),

    # ═══ E-Commerce ═══
    SaaSTarget("E-Commerce", "Shopify", "https://{slug}.myshopify.com",
               slug_location="subdomain",
               not_found_body=["only the store owner can",
                                "this store is unavailable",
                                "sorry, this shop is currently unavailable",
                                "password-page"],
               min_body_size=2000),

    # ═══ HR & Hiring ═══
    SaaSTarget("HR & Hiring", "Greenhouse", "https://boards.greenhouse.io/{slug}",
               slug_location="path",
               require_body=["greenhouse"],
               not_found_body=["not found"],
               not_found_url=["/job-seekers", "/about", "/blog"],
               generic_titles=["greenhouse", "job board"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "Lever", "https://jobs.lever.co/{slug}",
               slug_location="path",
               not_found_body=["page not found", "this page does not exist"],
               generic_titles=["lever"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "Workable", "https://apply.workable.com/{slug}/",
               slug_location="path",
               not_found_body=["page not found"],
               not_found_url=["/oops", "/error"],
               generic_titles=["workable"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "Ashby", "https://jobs.ashbyhq.com/{slug}",
               slug_location="path",
               not_found_body=["not found", "does not exist"],
               generic_titles=["jobs", "ashby"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "BambooHR", "https://{slug}.bamboohr.com",
               slug_location="subdomain",
               generic_titles=["bamboohr", "hr software",
                                "bamboohr: the complete hr software",
                                "the complete hr software"],
               not_found_body=["free trial", "request a demo"],
               min_body_size=5000),
    SaaSTarget("HR & Hiring", "Breezy HR", "https://{slug}.breezy.hr",
               slug_location="subdomain",
               generic_titles=["breezy hr", "breezy",
                                "modern hiring software"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "JazzHR", "https://{slug}.applytojob.com",
               slug_location="subdomain",
               not_found_url=["/job-seekers", "/job-seeker"],
               generic_titles=["jazzhr", "job seeker resources"],
               min_body_size=3000),
    SaaSTarget("HR & Hiring", "SmartRecruiters", "https://careers.smartrecruiters.com/{slug}",
               slug_location="path",
               not_found_url=["/job-search"],
               generic_titles=["smartrecruiters", "job search",
                                "smartrecruiters job search"],
               min_body_size=3000),

    # ═══ Marketing & CRM ═══
    SaaSTarget("Marketing & CRM", "HubSpot", "https://{slug}.hubspotpagebuilder.com",
               slug_location="subdomain",
               generic_titles=["hubspot"],
               min_body_size=2000),
    SaaSTarget("Marketing & CRM", "Salesforce", "https://{slug}.my.salesforce.com",
               slug_location="subdomain",
               valid_codes=[200, 302],
               generic_titles=["salesforce"],
               min_body_size=2000),
    SaaSTarget("Marketing & CRM", "ActiveCampaign", "https://{slug}.activehosted.com",
               slug_location="subdomain",
               generic_titles=["activecampaign"],
               min_body_size=2000),
    SaaSTarget("Marketing & CRM", "Pipedrive", "https://{slug}.pipedrive.com",
               slug_location="subdomain",
               generic_titles=["pipedrive"],
               min_body_size=2000),

    # ═══ Knowledge & Docs ═══
    SaaSTarget("Knowledge & Docs", "GitBook", "https://{slug}.gitbook.io",
               slug_location="subdomain",
               not_found_body=["does not exist"],
               generic_titles=["gitbook"],
               min_body_size=2000),
    SaaSTarget("Knowledge & Docs", "ReadMe", "https://{slug}.readme.io",
               slug_location="subdomain",
               generic_titles=["readme"],
               min_body_size=2000),

    # ═══ Analytics & Monitoring ═══
    SaaSTarget("Analytics", "Datadog", "https://{slug}.datadoghq.com",
               slug_location="subdomain",
               not_found_url=["/account/login"],
               generic_titles=["datadog", "log in", "datadog: log in"],
               min_body_size=2000),
    SaaSTarget("Analytics", "Grafana Cloud", "https://{slug}.grafana.net",
               slug_location="subdomain",
               generic_titles=["grafana"],
               min_body_size=2000),
    SaaSTarget("Analytics", "PagerDuty", "https://{slug}.pagerduty.com",
               slug_location="subdomain",
               generic_titles=["pagerduty"],
               min_body_size=2000),
    SaaSTarget("Analytics", "Looker", "https://{slug}.looker.com",
               slug_location="subdomain",
               generic_titles=["looker"],
               min_body_size=2000),

    # ═══ Project Management ═══
    SaaSTarget("Project Mgmt", "Linear", "https://linear.app/{slug}",
               slug_location="path",
               not_found_body=["not found"],
               generic_titles=["linear"],
               min_body_size=3000),
    SaaSTarget("Project Mgmt", "Trello", "https://trello.com/{slug}",
               slug_location="path",
               not_found_body=["model not found"],
               generic_titles=["trello"],
               min_body_size=5000),
    SaaSTarget("Project Mgmt", "Shortcut", "https://app.shortcut.com/{slug}",
               slug_location="path",
               not_found_body=["not found"],
               generic_titles=["shortcut"],
               min_body_size=3000),

    # ═══ Communication ═══
    SaaSTarget("Communication", "Discord", "https://discord.gg/{slug}",
               slug_location="path",
               not_found_body=["invite invalid", "this invite is invalid",
                                "invite is invalid or has expired",
                                "this invite may be expired"],
               require_body=["og:title"],
               generic_titles=["discord", "discord - group chat",
                                "discord - a new way to chat",
                                "discord | your place to talk"],
               min_body_size=3000),

    # ═══ Design ═══
    SaaSTarget("Design", "Figma", "https://www.figma.com/@{slug}",
               slug_location="path",
               not_found_body=["page not found"],
               generic_titles=["figma"],
               min_body_size=5000),

    # ═══ Security ═══
    SaaSTarget("Security", "HackerOne", "https://hackerone.com/{slug}",
               slug_location="path",
               require_body=["hackerone"],
               not_found_body=["page not found", "does not exist"],
               generic_titles=["hackerone"],
               min_body_size=5000),
    SaaSTarget("Security", "Bugcrowd", "https://bugcrowd.com/{slug}",
               slug_location="path",
               require_body=["bugcrowd"],
               not_found_body=["page not found", "does not exist"],
               generic_titles=["bugcrowd"],
               min_body_size=5000),

    # ═══ Finance ═══
    SaaSTarget("Finance", "Chargebee", "https://{slug}.chargebee.com",
               slug_location="subdomain",
               generic_titles=["chargebee"],
               min_body_size=2000),

    # ═══ Learning ═══
    SaaSTarget("Learning", "Teachable", "https://{slug}.teachable.com",
               slug_location="subdomain",
               not_found_body=["school not found"],
               generic_titles=["teachable"],
               min_body_size=2000),
    SaaSTarget("Learning", "Thinkific", "https://{slug}.thinkific.com",
               slug_location="subdomain",
               generic_titles=["thinkific"],
               min_body_size=2000),
]


# ─── slugs ────────────────────────────────────────────────────

def generate_slugs(domain: str) -> list[str]:
    """Turn 'acme.com' into ['acme', 'acme-hq', 'acme-inc', 'acmehq']."""
    clean = domain.lower().strip()
    clean = re.sub(r'^https?://', '', clean)
    clean = clean.replace("www.", "").rstrip("/")

    parts = clean.split(".")
    name = parts[0] if len(parts) >= 2 else clean

    slugs = set()
    slugs.add(name)

    no_sep = name.replace("-", "").replace("_", "")
    if no_sep != name:
        slugs.add(no_sep)
    if "-" in name:
        slugs.add(name.replace("-", "_"))
    if "_" in name:
        slugs.add(name.replace("_", "-"))

    slugs.add(name + "hq")
    slugs.add(name + "-hq")
    slugs.add(name + "-inc")

    return sorted(s for s in slugs if len(s) >= 2)


# ─── validation ───────────────────────────────────────────────

def extract_title(html: str) -> str:
    """Pull the <title> tag out of an HTML blob."""
    lower = html.lower()
    if "<title>" not in lower or "</title>" not in lower:
        return ""
    try:
        s = lower.index("<title>") + 7
        e = lower.index("</title>")
        raw = html[s:e].strip()
        return " ".join(raw.split())[:120]
    except ValueError:
        return ""


def validate_response(
    target: SaaSTarget,
    slug: str,
    original_url: str,
    resp: httpx.Response,
) -> tuple[bool, str, str]:
    """Run the response through all 8 filter layers. Returns (ok, confidence, reject_reason)."""
    final_url = str(resp.url)
    final_url_lower = final_url.lower()
    body_lower = resp.text.lower()[:15000]
    body_size = len(resp.text)
    title = extract_title(resp.text)
    title_lower = title.lower().strip()

    # 1) status code
    if resp.status_code not in target.valid_codes:
        return False, "", "bad_status"

    # 2) body size
    if body_size < target.min_body_size:
        return False, "", "too_small"

    # 3) redirect-away: slug must survive in the final URL
    if target.strict_redirect and resp.history:
        slug_lower = slug.lower()
        if target.slug_location == "subdomain":
            parsed = urlparse(final_url_lower)
            hostname = parsed.hostname or ""
            if slug_lower not in hostname:
                return False, "", "redirected_away"
        elif target.slug_location == "path":
            parsed = urlparse(final_url_lower)
            if slug_lower not in parsed.path:
                return False, "", "redirected_away"
        else:  # "any"
            if slug_lower not in final_url_lower:
                return False, "", "redirected_away"

    # 4) URL path patterns
    parsed_final = urlparse(final_url_lower)
    final_path = parsed_final.path + ("?" + parsed_final.query if parsed_final.query else "")

    for bad_path in GENERIC_NOT_FOUND_URL:
        if bad_path in final_path:
            return False, "", f"url_pattern:{bad_path}"

    for bad_path in target.not_found_url:
        if bad_path.lower() in final_path:
            return False, "", f"url_pattern:{bad_path}"

    # 5) global body patterns
    for pattern in GLOBAL_NOT_FOUND_BODY:
        if pattern in body_lower:
            return False, "", f"body_global:{pattern}"

    # 6) per-service body patterns
    for pattern in target.not_found_body:
        if pattern.lower() in body_lower:
            return False, "", f"body_target:{pattern}"

    # 7) required content
    if target.require_body:
        if not any(req.lower() in body_lower for req in target.require_body):
            return False, "", "missing_required"

    # 8) generic title — "Notion" or "Datadog: Log In" without the slug = homepage
    if target.generic_titles and title_lower:
        for gt in target.generic_titles:
            if title_lower == gt.lower().strip():
                return False, "", f"generic_title:{gt}"
            # catch "ServiceName: Log In" variants
            if title_lower.startswith(gt.lower().strip()):
                if slug.lower() not in title_lower:
                    # "ServiceName: Log In" --> strip service prefix, check remainder
                    remainder = title_lower.replace(gt.lower().strip(), "").strip(" :-|·–—")
                    generic_remainders = ["log in", "login", "sign in", "sign up",
                                          "register", "home", "welcome", ""]
                    if remainder in generic_remainders:
                        return False, "", f"generic_title_prefix:{gt}"

    # ── confidence ──
    confidence = "HIGH"

    if slug.lower() in title_lower:
        confidence = "HIGH"
    elif body_size < 5000:
        confidence = "MEDIUM"

    # auth page with no slug in title = suspicious
    auth_signals = ["sign in", "log in", "login", "authenticate"]
    if any(s in title_lower for s in auth_signals) and slug.lower() not in title_lower:
        confidence = "MEDIUM"

    # too many hops = shaky
    if len(resp.history) > 3:
        if confidence == "HIGH":
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

    return True, confidence, ""


# ─── check one target ─────────────────────────────────────────

async def check_target(
    client: httpx.AsyncClient,
    target: SaaSTarget,
    slug: str,
) -> ScanResult | None:
    """Fire one request, validate, return result or None."""
    original_url = target.url_pattern.format(slug=slug)

    try:
        resp = await client.get(original_url, follow_redirects=True, timeout=12.0)
        is_valid, confidence, reason = validate_response(
            target, slug, original_url, resp)

        if not is_valid:
            return None

        title = extract_title(resp.text)

        return ScanResult(
            category=target.category,
            service=target.service,
            url=original_url,
            final_url=str(resp.url),
            status=resp.status_code,
            title=title,
            slug=slug,
            confidence=confidence,
        )
    except Exception:
        return None


# ─── scan runner ──────────────────────────────────────────────

async def run_scan(domain: str, slugs: list[str], concurrency: int = 20) -> list[ScanResult]:
    results: list[ScanResult] = []
    total = len(SAAS_TARGETS) * len(slugs)
    completed = 0
    found = 0
    sem = asyncio.Semaphore(concurrency)

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    import warnings
    warnings.filterwarnings("ignore")

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        with Progress(
            SpinnerColumn("dots", style="red"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=40, style="red", complete_style="bold red",
                      finished_style="green"),
            TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
            TextColumn("[bold green]{task.fields[found]} found[/bold green]"),
            console=console,
        ) as progress:
            task = progress.add_task("Sniffing tenants...", total=total, found=0)

            async def _check(t, s):
                nonlocal completed, found
                async with sem:
                    r = await check_target(client, t, s)
                    completed += 1
                    if r:
                        found += 1
                        results.append(r)
                    progress.update(task, completed=completed, found=found)

            await asyncio.gather(
                *[_check(t, s) for t in SAAS_TARGETS for s in slugs],
                return_exceptions=True,
            )

    return results


# ─── output ───────────────────────────────────────────────────

def _conf_rank(c: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(c, 0)


def _dedup(results: list[ScanResult]) -> list[ScanResult]:
    """Dedupe by final URL, keep highest confidence."""
    seen: dict[str, ScanResult] = {}
    for r in results:
        key = r.final_url
        if key not in seen or _conf_rank(r.confidence) > _conf_rank(seen[key].confidence):
            seen[key] = r
    return sorted(seen.values(), key=lambda x: (x.category, x.service, x.slug))


def display_results(domain: str, slugs: list[str], results: list[ScanResult], elapsed: float):
    console.print()

    if not results:
        console.print(Panel(
            "[bold yellow]No SaaS tenants discovered.[/bold yellow]\n\n"
            "[dim]Try:\n"
            "  • Custom slugs: stackhound -s myco,mycompany domain.com\n"
            "  • Different variations of the org name\n"
            "  • Some tenants are behind SSO / not publicly accessible[/dim]",
            title="[bold red]◆ StackHound[/bold red] [dim]— No Results[/dim]",
            border_style="red", padding=(1, 2),
        ))
        return

    unique = _dedup(results)

    # Summary
    summary = Text()
    summary.append("  Target:     ", style="dim")
    summary.append(f"{domain}\n", style="bold white")
    summary.append("  Slugs:      ", style="dim")
    summary.append(f"{', '.join(slugs)}\n", style="white")
    summary.append("  Services:   ", style="dim")
    summary.append(f"{len(SAAS_TARGETS)} checked\n", style="white")
    summary.append("  Requests:   ", style="dim")
    summary.append(f"{len(SAAS_TARGETS) * len(slugs)}\n", style="white")
    summary.append("  Discovered: ", style="dim")
    summary.append(f"{len(unique)} verified tenants\n", style="bold green")
    summary.append("  Time:       ", style="dim")
    summary.append(f"{elapsed:.1f}s\n", style="white")

    console.print(Panel(summary,
        title="[bold red]◆ StackHound[/bold red] [dim]— Scan Complete[/dim]",
        border_style="red", padding=(0, 1)))
    console.print()

    # Table
    table = Table(box=box.HEAVY_EDGE, border_style="red",
                  header_style="bold white on red",
                  row_styles=["", "dim"], padding=(0, 1), show_lines=False)

    table.add_column("Category", style="bold red", width=18)
    table.add_column("Service", style="bold white", width=22)
    table.add_column("URL", style="cyan", min_width=44)
    table.add_column("Conf", justify="center", width=8)
    table.add_column("Title / Info", style="dim", max_width=40, overflow="ellipsis")

    current_cat = ""
    for r in unique:
        cat_display = r.category if r.category != current_cat else ""
        current_cat = r.category
        cs = {"HIGH": "bold green", "MEDIUM": "yellow", "LOW": "red"}.get(r.confidence, "dim")
        display_url = r.final_url if r.final_url != r.url else r.url
        table.add_row(cat_display, r.service, display_url,
                      f"[{cs}]{r.confidence}[/{cs}]",
                      (r.title[:40] if r.title else ""))

    console.print(table)
    console.print()

    # Stack Profile
    cats: dict[str, set[str]] = {}
    for r in unique:
        cats.setdefault(r.category, set()).add(r.service)

    profile = Text()
    for cat in sorted(cats):
        services = sorted(cats[cat])
        profile.append(f"  {cat}: ", style="bold red")
        profile.append(f"{', '.join(services)}\n", style="white")

    console.print(Panel(profile,
        title="[bold red]◆ Stack Profile[/bold red]",
        border_style="red", padding=(0, 1)))

    console.print()
    console.print("  [dim]Confidence: [bold green]HIGH[/bold green] = slug in title/URL · "
                   "[yellow]MEDIUM[/yellow] = valid but verify · "
                   "[red]LOW[/red] = check manually[/dim]")
    console.print()


# ─── export ───────────────────────────────────────────────────

def export_results(results: list[ScanResult], domain: str, output_file: str):
    unique = _dedup(results)
    export = {
        "tool": "StackHound v3.0",
        "target": domain,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services_checked": len(SAAS_TARGETS),
        "total_found": len(unique),
        "results": [asdict(r) for r in unique],
    }
    with open(output_file, "w") as f:
        json.dump(export, f, indent=2)
    console.print(f"  [dim]Exported →[/dim] [bold cyan]{output_file}[/bold cyan]")


# ─── list services ────────────────────────────────────────────

def list_services():
    console.print(BANNER)
    table = Table(title="[bold]All Checked Services[/bold]",
                  box=box.SIMPLE_HEAVY, border_style="red",
                  header_style="bold white on red", padding=(0, 1))
    table.add_column("#", style="dim", width=4)
    table.add_column("Category", style="bold red", width=20)
    table.add_column("Service", style="white", width=24)
    table.add_column("URL Pattern", style="cyan")
    table.add_column("Slug In", style="dim", width=12)

    for i, t in enumerate(SAAS_TARGETS, 1):
        table.add_row(str(i), t.category, t.service,
                      t.url_pattern, t.slug_location)

    console.print(table)
    cats = len(set(t.category for t in SAAS_TARGETS))
    console.print(f"\n  [bold]{len(SAAS_TARGETS)}[/bold] services across "
                  f"[bold]{cats}[/bold] categories\n")


# ─── main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="StackHound — SaaS Tenant Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 stackhound.py stripe.com
  python3 stackhound.py -s stripe,stripe-inc,stripehq stripe.com
  python3 stackhound.py --export results.json openai.com
  python3 stackhound.py -c 30 cloudflare.com
  python3 stackhound.py --list
        """)

    parser.add_argument("domain", nargs="?", help="Target domain or company name")
    parser.add_argument("-s", "--slugs", help="Comma-separated custom slugs")
    parser.add_argument("-c", "--concurrency", type=int, default=20,
                        help="Concurrent requests (default: 20)")
    parser.add_argument("--export", help="Export results to JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="No banner")
    parser.add_argument("--list", action="store_true", help="List all services")

    args = parser.parse_args()

    if args.list:
        list_services()
        return
    if not args.domain:
        parser.print_help()
        return

    if not args.quiet:
        console.print(BANNER)

    domain = args.domain
    slugs = ([s.strip().lower() for s in args.slugs.split(",") if s.strip()]
             if args.slugs else generate_slugs(domain))

    console.print(Panel(
        f"[bold white]  Target:[/bold white]   {domain}\n"
        f"[bold white]  Slugs:[/bold white]    {', '.join(slugs)}\n"
        f"[bold white]  Services:[/bold white] {len(SAAS_TARGETS)}\n"
        f"[bold white]  Requests:[/bold white] {len(SAAS_TARGETS) * len(slugs)}\n"
        f"[bold white]  Workers:[/bold white]  {args.concurrency}",
        title="[bold red]◆ Initializing Scan[/bold red]",
        border_style="red", padding=(0, 1)))
    console.print()

    start = time.time()
    results = asyncio.run(run_scan(domain, slugs, args.concurrency))
    elapsed = time.time() - start

    display_results(domain, slugs, results, elapsed)

    if args.export:
        export_results(results, domain, args.export)

    console.print(f"  [dim red]StackHound v3.0 — scan complete.[/dim red]\n")


if __name__ == "__main__":
    main()