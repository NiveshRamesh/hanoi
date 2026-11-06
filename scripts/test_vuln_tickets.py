"""Unit tests for vuln_tickets.py, run before every nightly sync (no network)."""
import json
import tempfile
import unittest
from pathlib import Path

import vuln_tickets as vt

CFG = {"sla_days": {"CRITICAL": 7, "HIGH": 30}, "default": {"github": "owner-default"},
       "services": {"cairo": {"github": "cairo-owner"}}}


class Fake:
    """In-memory ticket backend with the same interface as GitHubIssues / Jira."""
    name = "fake"

    def __init__(self):
        self.t, self.n, self.comments = {}, 0, []

    def tickets(self):
        return {t["state"]["key"]: dict(t) for t in self.t.values()}

    def create(self, r):
        self.n += 1
        self.t[self.n] = {"id": self.n, "closed": False, "state": r["state"], "title": r["title"],
                          "labels": sorted(r["labels"]), "body": r["body"], "owner": r["owner"]}
        return self.n

    def changed(self, t, r):
        return t["title"] != r["title"] or t["state"] != r["state"] or t["labels"] != sorted(r["labels"])

    def update(self, t, r):
        self.t[t["id"]].update(state=r["state"], title=r["title"], labels=sorted(r["labels"]), body=r["body"])

    def comment(self, t, text):
        self.comments.append((t["id"], text))

    def close(self, t, text):
        self.comment(t, text)
        self.t[t["id"]]["closed"] = True

    def reopen(self, t, text):
        self.t[t["id"]]["closed"] = False
        self.comment(t, text)


def vuln(cve, pkg, sev, fixed="9.9", installed="1.0"):
    return {"VulnerabilityID": cve, "PkgName": pkg, "Severity": sev, "InstalledVersion": installed,
            "FixedVersion": fixed, "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}"}


def scan_dir(entries, ignores=None):
    """entries: [(branch, service, os_vulns, lang_vulns)] -> temp dir with manifest + scans."""
    d = Path(tempfile.mkdtemp())
    manifest = []
    for i, (branch, svc, osv, langv) in enumerate(entries):
        (d / f"s{i}.json").write_text(json.dumps({"Results": [
            {"Target": "debian", "Class": "os-pkgs", "Vulnerabilities": osv},
            {"Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": langv}]}))
        m = {"branch": branch, "service": svc, "image": f"ghcr.io/x/{svc}:{branch}", "scan": f"s{i}.json"}
        if ignores and svc in ignores:
            (d / f"i{i}.json").write_text(json.dumps(ignores[svc]))
            m["ignore"] = f"i{i}.json"
        manifest.append(m)
    (d / "manifest.json").write_text(json.dumps(manifest))
    return d


class Tests(unittest.TestCase):
    def test_grouping_os_packages_into_one_base_image_ticket(self):
        g = vt.load_groups(scan_dir([("develop", "cairo",
                                      [vuln("CVE-1", "apt", "HIGH"), vuln("CVE-1", "libapt", "HIGH"), vuln("CVE-2", "libc6", "CRITICAL")],
                                      [vuln("CVE-3", "urllib3", "HIGH"), vuln("CVE-4", "urllib3", "HIGH"), vuln("CVE-5", "jinja2", "HIGH")])]),
                           "2026-11-06")
        self.assertEqual(sorted(g), ["cairo:base-image", "cairo:pkg:jinja2", "cairo:pkg:urllib3"])
        self.assertEqual(len(g["cairo:base-image"]["cves"]), 3)

    def test_unfixable_and_medium_are_not_ticketed(self):
        g = vt.load_groups(scan_dir([("develop", "cairo", [vuln("CVE-1", "apt", "HIGH", fixed="")],
                                      [vuln("CVE-2", "x", "MEDIUM")])]), "2026-11-06")
        self.assertEqual(g, {})

    def test_sla_due_date_and_title(self):
        g = vt.load_groups(scan_dir([("develop", "cairo", [vuln("CVE-2", "libc6", "CRITICAL"), vuln("CVE-1", "apt", "HIGH")], [])]),
                           "2026-11-06")["cairo:base-image"]
        r = vt.render(g, {}, "2026-11-06", CFG)
        self.assertEqual(r["due"], "2026-11-13")             # CRITICAL: 7 days
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertIn("Rebuild on a patched base image (2 CRITICAL CVEs)", r["title"])
        self.assertEqual(r["owner"]["github"], "cairo-owner")

    def test_first_seen_is_kept_so_due_does_not_move(self):
        g = vt.load_groups(scan_dir([("develop", "cairo", [], [vuln("CVE-3", "urllib3", "HIGH")])]), "2026-12-20")["cairo:pkg:urllib3"]
        r = vt.render(g, {"CVE-3|urllib3": "2026-11-01"}, "2026-12-20", CFG)
        self.assertEqual(r["due"], "2026-12-01")
        self.assertIn("overdue", r["labels"])

    def test_expired_exception_sets_due_to_expiry_and_labels_it(self):
        ign = {"perth": [{"id": "CVE-9", "expired_at": "2026-11-01", "statement": "x"},
                         {"id": "CVE-8", "expired_at": "2026-12-31"}]}
        g = vt.load_groups(scan_dir([("release/3.3", "perth", [], [vuln("CVE-9", "lib", "HIGH")])], ign), "2026-11-06")
        r = vt.render(g["perth:pkg:lib"], {}, "2026-11-06", CFG)
        self.assertEqual(r["due"], "2026-11-01")
        self.assertIn("exception-expired", r["labels"])
        self.assertIn("overdue", r["labels"])
        self.assertEqual(r["owner"]["github"], "owner-default")

    def test_sync_creates_then_is_idempotent(self):
        b = Fake()
        d = scan_dir([("develop", "cairo", [vuln("CVE-1", "apt", "HIGH")], [vuln("CVE-3", "urllib3", "HIGH")])])
        s1 = vt.sync(b, vt.load_groups(d, "2026-11-06"), CFG, "2026-11-06", log=lambda *_: None)
        s2 = vt.sync(b, vt.load_groups(d, "2026-11-07"), CFG, "2026-11-07", log=lambda *_: None)
        self.assertEqual(s1["created"], 2)
        self.assertEqual((s2["created"], s2["updated"], s2["unchanged"]), (0, 0, 2))
        self.assertEqual(b.comments, [])

    def test_new_cve_on_existing_ticket_comments_and_keeps_first_seen(self):
        b = Fake()
        vt.sync(b, vt.load_groups(scan_dir([("develop", "cairo", [], [vuln("CVE-3", "urllib3", "HIGH")])]), "2026-11-06"),
                CFG, "2026-11-06", log=lambda *_: None)
        vt.sync(b, vt.load_groups(scan_dir([("develop", "cairo", [], [vuln("CVE-3", "urllib3", "HIGH"), vuln("CVE-4", "urllib3", "HIGH")])]),
                                  "2026-11-08"), CFG, "2026-11-08", log=lambda *_: None)
        t = b.t[1]
        self.assertEqual(t["state"]["first_seen"], {"CVE-3|urllib3": "2026-11-06", "CVE-4|urllib3": "2026-11-08"})
        self.assertEqual(t["state"]["due"], "2026-12-06")
        self.assertTrue(any("CVE-4" in c for _, c in b.comments))

    def test_auto_close_and_reopen(self):
        b = Fake()
        d = scan_dir([("develop", "cairo", [vuln("CVE-1", "apt", "HIGH")], [])])
        vt.sync(b, vt.load_groups(d, "2026-11-06"), CFG, "2026-11-06", log=lambda *_: None)
        s = vt.sync(b, {}, CFG, "2026-11-07", log=lambda *_: None)
        self.assertEqual(s["closed"], 1)
        self.assertTrue(b.t[1]["closed"])
        s = vt.sync(b, vt.load_groups(d, "2026-11-09"), CFG, "2026-11-09", log=lambda *_: None)
        self.assertEqual((s["reopened"], s["created"]), (1, 0))
        self.assertFalse(b.t[1]["closed"])

    def test_check_blocks_only_overdue_tickets_on_that_branch(self):
        b = Fake()
        d = scan_dir([("release/3.3", "cairo", [vuln("CVE-2", "libc6", "CRITICAL")], []),
                      ("develop", "perth", [], [vuln("CVE-7", "x", "CRITICAL")])])
        vt.sync(b, vt.load_groups(d, "2026-11-01"), CFG, "2026-11-01", log=lambda *_: None)
        self.assertEqual(vt.check(b, "release/3.3", "2026-11-06", log=lambda *_: None), [])      # due 11-08
        self.assertEqual(len(vt.check(b, "release/3.3", "2026-11-09", log=lambda *_: None)), 1)  # overdue
        self.assertEqual(len(vt.check(b, "release/9.9", "2026-11-09", log=lambda *_: None)), 0)  # other branch
        b.t[1]["closed"] = True
        self.assertEqual(vt.check(b, "release/3.3", "2026-11-09", log=lambda *_: None), [])

    def test_state_round_trips_through_issue_body(self):
        st = {"key": "cairo:base-image", "due": "2026-11-13", "first_seen": {"CVE-1|apt": "2026-11-06"}}
        self.assertEqual(vt._parse_state("text" + vt._state_block(st)), st)
        self.assertIsNone(vt._parse_state("an issue without state"))


if __name__ == "__main__":
    unittest.main()
