"""Answers 35/32/11 tests: website completeness and legal-draft
labeling. Structural checks over the repo website files."""

import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    "..", ".."))
WEB = os.path.join(REPO, "website")


def read(name):
    with open(os.path.join(REPO, name.lstrip("./"))) as fh:
        return fh.read()


def flat(name):
    return " ".join(read(os.path.join("website", name)).split())


class TestServingConfiguration:
    def test_control_plane_serves_site_portal_admin(self):
        """The intended serving configuration: control-plane mounts the
        website at /, the customer portal at /portal/ and the admin
        dashboard at /web/ (the Caddy example proxies everything to
        control-plane), so the website's login links resolve."""
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from fastapi.testclient import TestClient
        from app.config import Settings
        from app.main import create_app
        c = TestClient(create_app(Settings(
            {"KG_DATABASE_URL": "postgresql://placeholder",
             "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}),
            engine=None))
        site = c.get("/")
        assert site.status_code == 200
        assert "KosherGuard" in site.text
        assert '/portal/' in site.text and '/web/' in site.text
        portal = c.get("/portal/")
        assert portal.status_code == 200
        assert "support-form" in portal.text
        admin = c.get("/web/")
        assert admin.status_code == 200

    def test_portal_has_working_support_form(self):
        """The in-product support request the website describes exists
        in the portal UI and posts to the real support API."""
        portal = read(os.path.join("..", "portal", "index.html"))
        assert 'id="support-form"' in portal
        assert "policy_change" in portal
        js = read(os.path.join("..", "portal", "app.js"))
        assert "/api/support/requests" in js


class TestWebsite:
    def test_required_pages_exist(self):
        for page in ("index.html", "privacy.html", "terms.html",
                     "support.html", "enrollment.html", "status.html"):
            assert os.path.isfile(os.path.join(WEB, page)), page

    def test_brand_and_tagline(self):
        index = read(os.path.join("website", "index.html"))
        assert "KosherGuard" in index
        assert "The best filtering solution for our" in index

    def test_homepage_sections_and_logins(self):
        index = read(os.path.join("website", "index.html"))
        for section in ("How it works", "Features", "Contact"):
            assert section in index
        # Customer login and a SEPARATE administrator login.
        assert "/portal/" in index
        assert "/web/" in index
        assert "Administrator sign in" in index

    def test_support_channels_listed(self):
        page = read(os.path.join("website", "support.html"))
        for channel in ("In-product support requests",
                        "Verified email support", "Escalation"):
            assert channel in page
        # No invented support hours or 24/7 promises.
        blob = (page + read(os.path.join("website", "index.html"))).lower()
        assert "24/7" not in blob.replace("do not advertise support "
                                          "hours or 24/7 service", "")
        assert "support hours or 24/7 service during the pilot" in \
            page

    def test_enrollment_info_is_honest(self):
        page = read(os.path.join("website", "enrollment.html"))
        assert "Apple approval" in page
        assert "not yet been validated on real devices" in page

    def test_legal_pages_are_drafts(self):
        for page in ("privacy.html", "terms.html"):
            text = flat(page)
            assert "DRAFT - pending professional legal review" in text
            assert "not legal advice" in text or \
                "not a binding agreement" in text

    def test_privacy_states_minimization(self):
        page = read(os.path.join("website", "privacy.html"))
        assert "do not collect device location" in page
        assert "personal apps" in page

    def test_no_unsupported_service_claims(self):
        blob = ""
        for page in ("index.html", "support.html", "enrollment.html",
                     "status.html"):
            blob += flat(page).lower() + " "
        # Pre-launch honesty markers present; no SLA/availability
        # promises.
        assert "in development and not yet launched" in blob or \
            "under active development" in blob
        assert "no availability target or sla is promised" in blob
