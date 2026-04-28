<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue" alt="Python">
  <img src="https://img.shields.io/badge/services-62-red" alt="Services">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

```
   _____ __             __   __  __                      __
  / ___// /_____ ______/ /__/ / / /___  __  ______  ____/ /
  \__ \/ __/ __ `/ ___/ //_/ /_/ / __ \/ / / / __ \/ __  / 
 ___/ / /_/ /_/ / /__/ ,< / __  / /_/ / /_/ / / / / /_/ /  
/____/\__/\__,_/\___/_/|_/_/ /_/\____/\__,_/_/ /_/\__,_/   
```

# StackHound

Map an organization's SaaS footprint from just a domain name.

Give it `stripe.com` and it tells you which SaaS platforms Stripe uses — Slack, Atlassian, Zendesk, Greenhouse, Okta, GitHub, and whatever else is publicly discoverable.

## How it works

Most SaaS platforms use predictable tenant URLs: `company.slack.com`, `company.atlassian.net`, `boards.greenhouse.io/company`, etc. StackHound generates slug variations from a domain name, checks 62 services across 16 categories, and validates responses through an 8-layer filter to cut false positives.

**The hard part isn't checking URLs — it's not returning garbage.** Most tools in this space flag every 200 response as a hit. StackHound catches redirects to homepages, generic login pages, marketing sites, `slug_not_found` responses, and all the other ways SaaS platforms return 200 for things that don't exist.

## Install

```bash
git clone https://github.com/beans-asset-02/stackhound.git
cd stackhound
pip install -r requirements.txt
```

## Usage

```bash
# basic scan
python3 stackhound.py stripe.com

# custom slug variations
python3 stackhound.py -s stripe,stripe-inc,stripehq,stripe-payments stripe.com

# export to JSON
python3 stackhound.py --export results.json openai.com

# crank up concurrency
python3 stackhound.py -c 40 cloudflare.com

# see all 62 services
python3 stackhound.py --list
```

## What it checks

| Category | Services |
|----------|----------|
| Identity & SSO | Okta, Auth0, OneLogin, Duo Security |
| Collaboration | Slack, Atlassian, Notion, Monday.com, Teamwork, ClickUp, Coda, Basecamp |
| Support & CX | Zendesk, Freshdesk, Freshservice, Intercom, HelpScout, ServiceNow |
| Infrastructure | Statuspage, BetterUptime, Instatus, Vercel, Netlify, Heroku, Fly.io, Render |
| Dev & Code | GitHub, GitLab, Bitbucket, Docker Hub, npm, Sentry, Snyk |
| HR & Hiring | Greenhouse, Lever, Workable, Ashby, BambooHR, Breezy HR, JazzHR, SmartRecruiters |
| Marketing & CRM | HubSpot, Salesforce, ActiveCampaign, Pipedrive |
| Project Mgmt | Linear, Trello, Shortcut |
| Analytics | Datadog, Grafana Cloud, PagerDuty, Looker |
| Knowledge & Docs | GitBook, ReadMe |
| E-Commerce | Shopify |
| Communication | Discord |
| Design | Figma |
| Security | HackerOne, Bugcrowd |
| Finance | Chargebee |
| Learning | Teachable, Thinkific |

## Validation

Every response goes through 8 layers of filtering before it's reported:

1. **Status code** — reject non-200s (or whatever the service expects)
2. **Body size** — tiny responses are almost always error stubs
3. **Redirect tracking** — if `slug.bamboohr.com` bounces to `www.bamboohr.com`, the slug is gone → rejected
4. **URL path analysis** — catches `/slug_not_found`, `/account/login`, `/oops`
5. **Global body patterns** — "does not exist", "page not found", etc.
6. **Per-service body patterns** — service-specific error strings
7. **Required content** — some services need specific strings to confirm a real tenant
8. **Generic title detection** — if the page title is just "Notion" or "Datadog: Log In" with no mention of the org, it's a homepage

Each result gets a confidence score: **HIGH** (slug appears in title/URL), **MEDIUM** (valid but worth verifying), or **LOW** (check manually).

## Output

```
╭──────────────────────── ◆ StackHound — Scan Complete ────────────────────────╮
│   Target:     acme.com                                                       │
│   Services:   62 checked                                                     │
│   Discovered: 8 verified tenants                                             │
│   Time:       5.2s                                                           │
╰──────────────────────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ Category           │ Service                │ URL
┠────────────────────┼────────────────────────┼─────────────────────────────────
┃ Collaboration      │ Slack                  │ https://acme.slack.com
┃                    │ Atlassian              │ https://acme.atlassian.net
┃ Dev & Code         │ GitHub                 │ https://github.com/acme
┃ HR & Hiring        │ Greenhouse             │ https://boards.greenhouse.io/acme
┃ Support & CX       │ Zendesk                │ https://acme.zendesk.com
┗━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━┷━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Adding services

The target list is just a Python list of `SaaSTarget` objects. To add a new service:

```python
SaaSTarget("Category", "Service Name", "https://{slug}.service.com",
           slug_location="subdomain",
           not_found_body=["whatever their 404 page says"],
           generic_titles=["service name"],
           min_body_size=2000),
```

Test it with a slug you know doesn't exist before committing. The whole point of this tool is not returning false positives.

## Flags

| Flag | Description |
|------|-------------|
| `-s`, `--slugs` | Comma-separated custom slugs instead of auto-generated ones |
| `-c`, `--concurrency` | Max parallel requests (default: 20) |
| `--export` | Write results to a JSON file |
| `-q`, `--quiet` | Skip the banner |
| `--list` | Print all checked services and exit |

## License

MIT
