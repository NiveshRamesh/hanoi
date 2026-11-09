#!/usr/bin/env python3
"""Turn the nightly Trivy scan of deployed images into tracked remediation tickets.

One ticket per service and fix: OS packages are grouped into a single "rebuild on a patched
base image" ticket, application packages get one ticket each. Every ticket has an owner, a
severity and a due date (SLA counted from the night the fix was first seen). Tickets are
updated in place, reopened if a finding comes back, and closed when it is gone.

Backends: Jira when JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN and JIRA_PROJECT are set,
otherwise GitHub Issues in this repository (GITHUB_TOKEN + GITHUB_REPOSITORY).

  sync   --scan-dir DIR --config owners.json   create / update / close tickets
  check  --branch release/3.3                  exit 1 if an open ticket for that branch is overdue
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LABEL = "vulnerability"
SEV_RANK = {"CRITICAL": 2, "HIGH": 1}
DEFAULT_SLA = {"CRITICAL": 7, "HIGH": 30}
STATE_MARK = "vuln-state:"


# --------------------------------------------------------------------------- findings
def load_groups(scan_dir, today):
    """Read manifest.json + Trivy JSON files and group fixable HIGH/CRITICAL findings."""
    scan_dir = Path(scan_dir)
    groups = {}
    for entry in json.loads((scan_dir / "manifest.json").read_text()):
        data = json.loads((scan_dir / entry["scan"]).read_text())
        ignores = []
        if entry.get("ignore") and (scan_dir / entry["ignore"]).exists():
            ignores = json.loads((scan_dir / entry["ignore"]).read_text()) or []
        expired = {e["id"]: str(e["expired_at"])[:10] for e in ignores
                   if e.get("id") and e.get("expired_at") and str(e["expired_at"])[:10] < today}
        svc, branch = entry["service"], entry["branch"]
        for res in data.get("Results") or []:
            os_pkgs = res.get("Class") == "os-pkgs"
            for v in res.get("Vulnerabilities") or []:
                if not v.get("FixedVersion") or v.get("Severity") not in SEV_RANK:
                    continue
                pkg = v["PkgName"]
                key = f"{svc}:base-image" if os_pkgs else f"{svc}:pkg:{pkg}"
                g = groups.setdefault(key, {"key": key, "service": svc, "kind": "base-image" if os_pkgs else "package",
                                            "package": None if os_pkgs else pkg, "cves": {}, "branches": set(), "images": set()})
                c = g["cves"].setdefault(f"{v['VulnerabilityID']}|{pkg}", {
                    "id": v["VulnerabilityID"], "pkg": pkg, "sev": v["Severity"], "installed": v.get("InstalledVersion", ""),
                    "fixed": v["FixedVersion"], "url": v.get("PrimaryURL", ""), "branches": set(),
                    "exception_expired": expired.get(v["VulnerabilityID"])})
                c["branches"].add(branch)
                g["branches"].add(branch)
                g["images"].add(entry["image"])
    return groups


def render(g, prev_first_seen, today, cfg):
    """Ticket title, body, labels, due date and state for one group."""
    sla = {**DEFAULT_SLA, **cfg.get("sla_days", {})}
    owner = {**cfg.get("default", {}), **cfg.get("services", {}).get(g["service"], {})}
    first_seen = {k: prev_first_seen.get(k, today) for k in g["cves"]}
    dues = []
    for k, c in g["cves"].items():
        dues.append(dt.date.fromisoformat(first_seen[k]) + dt.timedelta(days=int(sla[c["sev"]])))
        if c["exception_expired"]:
            dues.append(dt.date.fromisoformat(c["exception_expired"]))
    due = min(dues).isoformat()
    sev = max((c["sev"] for c in g["cves"].values()), key=SEV_RANK.get)
    n = len({c["id"] for c in g["cves"].values()})
    what = "Rebuild on a patched base image" if g["kind"] == "base-image" else f"Upgrade {g['package']} to a fixed version"
    title = f"[{g['service']}] {what} ({n} {sev} CVE{'s' if n > 1 else ''})"
    expired = sorted({c["id"] for c in g["cves"].values() if c["exception_expired"]})
    overdue = due < today
    rows = "\n".join(
        f"| {c['sev']} | [{c['id']}]({c['url']}) | {c['pkg']} | {c['installed']} | {c['fixed']} | {first_seen[k]} | "
        f"{', '.join(sorted(c['branches']))} |" if c["url"] else
        f"| {c['sev']} | {c['id']} | {c['pkg']} | {c['installed']} | {c['fixed']} | {first_seen[k]} | {', '.join(sorted(c['branches']))} |"
        for k, c in sorted(g["cves"].items(), key=lambda kv: (-SEV_RANK[kv[1]["sev"]], kv[0])))
    how = ("Rebuild the image so it picks up the patched base image (merge any change to develop, or bump the "
           "base image tag), then let it flow through develop and the release branches."
           if g["kind"] == "base-image" else
           f"Upgrade `{g['package']}` to at least the fixed version below in the service repo, through a normal PR.")
    body = "\n".join([
        f"**Service:** {g['service']}  ",
        f"**Severity:** {sev}  ",
        f"**Due:** {due}{' (OVERDUE)' if overdue else ''}  ",
        f"**Owner:** {owner.get('github') or owner.get('jira_account_id') or 'unassigned'}  ",
        f"**Affected branches:** {', '.join(sorted(g['branches']))}  ",
        f"**Images:** {', '.join(f'`{i}`' for i in sorted(g['images']))}",
        "",
        f"**How to fix:** {how}",
        "",
        "SLA: CRITICAL %s days, HIGH %s days, counted from the night a fix was first seen." % (sla["CRITICAL"], sla["HIGH"]),
        *([f"**Exception expired** for {', '.join(expired)}: fix it, or renew the entry in the service's .trivyignore.yaml."]
          if expired else []),
        "",
        "| Severity | CVE | Package | Installed | Fixed in | First seen | Branches |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        rows,
        "",
        "_Maintained by the nightly vulnerability scan. It updates this ticket and closes it when the finding is gone._",
    ])
    labels = [LABEL, f"severity:{sev.lower()}", f"service:{g['service']}"]
    if overdue:
        labels.append("overdue")
    if expired:
        labels.append("exception-expired")
    state = {"key": g["key"], "service": g["service"], "first_seen": first_seen, "due": due,
             "severity": sev, "branches": sorted(g["branches"])}
    return {"title": title, "body": body, "labels": labels, "due": due, "severity": sev, "owner": owner, "state": state}


# --------------------------------------------------------------------------- backends
def _http(method, url, headers, payload=None, allow_404=False):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        if allow_404 and e.code == 404:
            return None
        raise RuntimeError(f"{method} {url} -> HTTP {e.code}: {e.read().decode(errors='replace')[:500]}") from None


class GitHubIssues:
    name = "GitHub Issues"

    def __init__(self, token, repo):
        self.api = f"https://api.github.com/repos/{repo}"
        self.h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                  "X-GitHub-Api-Version": "2022-11-28"}
        self._labels = None

    def tickets(self):
        out, page = {}, 1
        while True:
            items = _http("GET", f"{self.api}/issues?labels={LABEL}&state=all&per_page=100&page={page}", self.h)
            for i in items:
                if "pull_request" in i:
                    continue
                st = _parse_state(i.get("body") or "")
                if not st:
                    continue
                t = {"id": i["number"], "closed": i["state"] == "closed", "state": st, "title": i["title"],
                     "body": i.get("body") or "", "labels": sorted(lb["name"] for lb in i["labels"])}
                if st["key"] not in out or out[st["key"]]["closed"]:   # prefer the open one
                    out[st["key"]] = t
            if len(items) < 100:
                return out
            page += 1

    def _ensure_labels(self, names):
        if self._labels is None:
            self._labels = {lb["name"] for lb in _http("GET", f"{self.api}/labels?per_page=100", self.h)}
        colors = {"vulnerability": "b60205", "overdue": "d93f0b", "exception-expired": "d93f0b",
                  "severity:critical": "b60205", "severity:high": "fbca04"}
        for n in names:
            if n not in self._labels:
                _http("POST", f"{self.api}/labels", self.h, {"name": n, "color": colors.get(n, "c5def5")})
                self._labels.add(n)

    def _fields(self, r):
        self._ensure_labels(r["labels"])
        f = {"title": r["title"], "body": r["body"] + _state_block(r["state"]), "labels": r["labels"]}
        if r["owner"].get("github"):
            f["assignees"] = [r["owner"]["github"]]
        return f

    def create(self, r):
        return _http("POST", f"{self.api}/issues", self.h, self._fields(r))["number"]

    def update(self, t, r):
        _http("PATCH", f"{self.api}/issues/{t['id']}", self.h, self._fields(r))

    def changed(self, t, r):
        body = (t["body"] or "").replace("\r\n", "\n")
        return t["title"] != r["title"] or body != r["body"] + _state_block(r["state"]) or t["labels"] != sorted(r["labels"])

    def comment(self, t, text):
        _http("POST", f"{self.api}/issues/{t['id']}/comments", self.h, {"body": text})

    def close(self, t, text):
        self.comment(t, text)
        _http("PATCH", f"{self.api}/issues/{t['id']}", self.h, {"state": "closed", "state_reason": "completed"})

    def reopen(self, t, text):
        _http("PATCH", f"{self.api}/issues/{t['id']}", self.h, {"state": "open"})
        self.comment(t, text)


def _wiki_text(s):
    """Escape characters Jira wiki markup would read as formatting (e.g. +x+ underline in 1.3-1+deb13u1)."""
    return re.sub(r"([-+*_^~?{}\[\]|!#])", r"\\\1", s)


def _wiki_inline(s):
    """**bold**, `code` and [text](url) to Jira wiki; everything else escaped."""
    out, pos = [], 0
    for m in re.finditer(r"\*\*(.+?)\*\*|`(.+?)`|\[([^\]]+)\]\((https?://[^)\s]+)\)", s):
        out.append(_wiki_text(s[pos:m.start()]))
        if m.group(1) is not None:
            out.append(f"*{_wiki_inline(m.group(1))}*")
        elif m.group(2) is not None:
            out.append("{{" + _wiki_text(m.group(2)) + "}}")
        else:
            out.append(f"[{_wiki_text(m.group(3))}|{m.group(4)}]")
        pos = m.end()
    return "".join(out) + _wiki_text(s[pos:])


def to_jira_wiki(md):
    """The ticket body (written as GitHub Markdown) in Jira wiki markup, for the v2 REST API."""
    lines, header = [], True
    for line in md.split("\n"):
        if re.fullmatch(r"\|( *-+ *\|)+", line):
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [_wiki_inline(c.strip()) for c in line[1:-1].split("|")]
            sep = "||" if header else "|"
            lines.append(sep + sep.join(cells) + sep)
            header = False
            continue
        header = True
        if len(line) > 2 and line.startswith("_") and line.endswith("_"):
            lines.append("_" + _wiki_inline(line[1:-1]) + "_")
        else:
            lines.append(_wiki_inline(line.rstrip()))
    return "\n".join(lines)


class Jira:
    """Jira Cloud REST (v2 API: wiki-markup descriptions and comments)."""
    name = "Jira"

    def __init__(self, url, user, token, project, issue_type, priorities):
        import base64
        self.base = url.rstrip("/")
        self.h = {"Authorization": "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode(),
                  "Accept": "application/json"}
        self.project, self.issue_type, self.priorities = project, issue_type, priorities

    def tickets(self):
        out, token = {}, None
        jql = f'project = "{self.project}" AND labels = "{LABEL}" ORDER BY created DESC'
        while True:
            q = {"jql": jql, "fields": "summary,status,labels,duedate", "maxResults": 100}
            if token:
                q["nextPageToken"] = token
            res = _http("GET", f"{self.base}/rest/api/3/search/jql?{urllib.parse.urlencode(q)}", self.h)
            for i in res.get("issues", []):
                prop = _http("GET", f"{self.base}/rest/api/2/issue/{i['key']}/properties/vuln-state", self.h,
                             allow_404=True)
                st = (prop or {}).get("value")
                if not st:
                    continue
                f = i["fields"]
                t = {"id": i["key"], "closed": f["status"]["statusCategory"]["key"] == "done", "state": st,
                     "title": f["summary"], "body": None, "labels": sorted(f.get("labels") or []), "due": f.get("duedate")}
                if st["key"] not in out or out[st["key"]]["closed"]:
                    out[st["key"]] = t
            token = res.get("nextPageToken")
            if not token or res.get("isLast", True):
                return out

    def _fields(self, r):
        f = {"summary": r["title"], "description": to_jira_wiki(r["body"]), "labels": [lb.replace(":", "-") for lb in r["labels"]],
             "duedate": r["due"]}
        if self.priorities.get(r["severity"]):
            f["priority"] = {"name": self.priorities[r["severity"]]}
        if r["owner"].get("jira_account_id"):
            f["assignee"] = {"accountId": r["owner"]["jira_account_id"]}
        return f

    def _set_state(self, key, state):
        _http("PUT", f"{self.base}/rest/api/2/issue/{key}/properties/vuln-state", self.h, state)

    def create(self, r):
        f = {"project": {"key": self.project}, "issuetype": {"name": self.issue_type}, **self._fields(r)}
        key = _http("POST", f"{self.base}/rest/api/2/issue", self.h, {"fields": f})["key"]
        self._set_state(key, r["state"])
        return key

    def update(self, t, r):
        _http("PUT", f"{self.base}/rest/api/2/issue/{t['id']}", self.h, {"fields": self._fields(r)})
        self._set_state(t["id"], r["state"])

    def changed(self, t, r):
        return (t["title"] != r["title"] or t.get("due") != r["due"] or t["state"] != r["state"]
                or t["labels"] != sorted(lb.replace(":", "-") for lb in r["labels"]))

    def comment(self, t, text):
        _http("POST", f"{self.base}/rest/api/2/issue/{t['id']}/comment", self.h, {"body": _wiki_inline(text)})

    def _transition(self, t, category):
        trs = _http("GET", f"{self.base}/rest/api/2/issue/{t['id']}/transitions", self.h)["transitions"]
        match = [x for x in trs if x["to"]["statusCategory"]["key"] == category]
        if not match:
            raise RuntimeError(f"{t['id']}: no transition to a '{category}' status")
        _http("POST", f"{self.base}/rest/api/2/issue/{t['id']}/transitions", self.h, {"transition": {"id": match[0]["id"]}})

    def close(self, t, text):
        self.comment(t, text)
        self._transition(t, "done")

    def reopen(self, t, text):
        self._transition(t, "new")
        self.comment(t, text)


def _state_block(state):
    return f"\n\n<!-- {STATE_MARK} {json.dumps(state, sort_keys=True)} -->"


def _parse_state(body):
    i = body.rfind(f"<!-- {STATE_MARK}")
    if i < 0:
        return None
    try:
        return json.loads(body[i + len(f"<!-- {STATE_MARK}"):].rsplit("-->", 1)[0])
    except ValueError:
        return None


def backend_from_env():
    e = os.environ
    if all(e.get(k) for k in ("JIRA_URL", "JIRA_USERNAME", "JIRA_API_TOKEN", "JIRA_PROJECT")):
        prio = json.loads(e.get("JIRA_PRIORITIES") or "{}")
        return Jira(e["JIRA_URL"], e["JIRA_USERNAME"], e["JIRA_API_TOKEN"], e["JIRA_PROJECT"],
                    e.get("JIRA_ISSUE_TYPE") or "Bug", prio)
    return GitHubIssues(e["GITHUB_TOKEN"], e["GITHUB_REPOSITORY"])


# --------------------------------------------------------------------------- commands
def sync(backend, groups, cfg, today, log=print):
    tickets = backend.tickets()
    summary = {"created": 0, "updated": 0, "reopened": 0, "closed": 0, "unchanged": 0}
    for key, g in sorted(groups.items()):
        t = tickets.get(key)
        r = render(g, t["state"].get("first_seen", {}) if t else {}, today, cfg)
        if not t:
            tid = backend.create(r)
            summary["created"] += 1
            log(f"created  {tid}  {r['title']}  due {r['due']}")
            continue
        if t["closed"]:
            backend.reopen(t, f"Detected again by the nightly scan on {today}: reopening.")
            summary["reopened"] += 1
            log(f"reopened {t['id']}  {r['title']}")
        new = sorted({g["cves"][k]["id"] for k in r["state"]["first_seen"] if k not in t["state"].get("first_seen", {})})
        if backend.changed(t, r):
            backend.update(t, r)
            if not t["closed"]:
                summary["updated"] += 1
                log(f"updated  {t['id']}  {r['title']}  due {r['due']}")
        elif not t["closed"]:
            summary["unchanged"] += 1
        if new and t["state"].get("first_seen"):
            backend.comment(t, f"New since the last scan ({today}): {', '.join(new)}.")
    for key, t in sorted(tickets.items()):
        if not t["closed"] and key not in groups:
            backend.close(t, f"No longer detected in any deployed image by the nightly scan on {today}. Closing.")
            summary["closed"] += 1
            log(f"closed   {t['id']}  {t['title']}")
    return summary


def check(backend, branch, today, log=print):
    overdue = [t for t in backend.tickets().values()
               if not t["closed"] and t["state"].get("due", "9999") < today
               and (branch is None or branch in t["state"].get("branches", []))]
    for t in overdue:
        log(f"OVERDUE  {t['id']}  {t['title']}  (due {t['state']['due']})")
    return overdue


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    s.add_argument("--scan-dir", required=True)
    s.add_argument("--config", required=True, help="owners/SLA config as JSON")
    c = sub.add_parser("check")
    c.add_argument("--branch", help="only tickets affecting this branch")
    a = ap.parse_args(argv)
    today = dt.date.today().isoformat()
    backend = backend_from_env()
    print(f"Ticket backend: {backend.name}")
    if a.cmd == "sync":
        cfg = json.loads(Path(a.config).read_text())
        summary = sync(backend, load_groups(a.scan_dir, today), cfg, today)
        print("Summary:", json.dumps(summary))
        _step_summary(f"### Vulnerability tickets ({backend.name})\n\n" + "\n".join(f"- {k}: {v}" for k, v in summary.items()))
        return 0
    overdue = check(backend, a.branch, today)
    if overdue:
        print(f"::error::{len(overdue)} overdue vulnerability ticket(s) affect {a.branch or 'deployed images'}. "
              "Fix them, or renew the exception, before releasing.")
        return 1
    print(f"No overdue vulnerability tickets for {a.branch or 'any branch'}.")
    return 0


def _step_summary(text):
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        with open(p, "a", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())
