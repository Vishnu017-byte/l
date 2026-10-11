import os
import re
import tempfile
import unittest
from datetime import date, timedelta

_bootstrap_dir = tempfile.TemporaryDirectory(prefix="campus-lfs-bootstrap-")
os.environ.update({
    "APP_ENV": "development",
    "DATABASE_PATH": os.path.join(_bootstrap_dir.name, "bootstrap.db"),
    "UPLOAD_DIR": os.path.join(_bootstrap_dir.name, "uploads"),
    "SECRET_KEY": "unit-test-secret-key",
    "INITIAL_ADMIN_EMAIL": "admin@campus.test",
    "INITIAL_ADMIN_PASSWORD": "qa-admin-password-123",
    "COLLEGE_EMAIL_DOMAIN": "",
    "SMTP_HOST": "",
})

from werkzeug.security import check_password_hash

import app as app_module


class CampusAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="campus-lfs-test-")
        app_module.DB_PATH = os.path.join(self.temp_dir.name, "test.db")
        app_module.UPLOAD_DIR = os.path.join(self.temp_dir.name, "uploads")
        os.makedirs(app_module.UPLOAD_DIR, exist_ok=True)
        app_module.app.config.update(
            TESTING=True,
            SECRET_KEY="unit-test-secret-key",
            APP_ENV="development",
            INITIAL_ADMIN_EMAIL="admin@campus.test",
            INITIAL_ADMIN_PASSWORD="qa-admin-password-123",
            COLLEGE_EMAIL_DOMAIN="",
            SMTP_HOST="",
            WTF_CSRF_ENABLED=True,
        )
        app_module.init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, client, path):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match, f"No CSRF token found in {path}")
        return match.group(1)

    def create_user(self, email, name):
        client = app_module.app.test_client()
        token = self.csrf_token(client, "/register")
        response = client.post("/register", data={
            "csrf_token": token,
            "name": name,
            "email": email,
            "phone": "",
            "password": "campus-pass-123",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        return client

    def create_report(self, client, title="Blue key ring"):
        token = self.csrf_token(client, "/report")
        response = client.post("/report", data={
            "csrf_token": token,
            "type": "found",
            "title": title,
            "description": "Found near the library entrance",
            "category": "Keys",
            "location": "Library entrance",
            "date_event": date.today().isoformat(),
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        return int(response.headers["Location"].rsplit("/", 1)[-1])

    def row(self, query, params=()):
        with app_module.app.app_context():
            return app_module.db().execute(query, params).fetchone()

    def test_mutating_requests_require_csrf_and_logout_is_post_only(self):
        client = app_module.app.test_client()
        self.assertEqual(client.post("/login", data={"email": "x", "password": "x"}).status_code, 400)
        self.assertEqual(client.get("/logout").status_code, 405)
        client = self.create_user("csrf@example.test", "CSRF User")
        response = client.post("/logout", data={"csrf_token": self.csrf_token(client, "/login")})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/dashboard", follow_redirects=False).status_code, 302)

    def test_login_rejects_external_next_but_keeps_local_path(self):
        client = self.create_user("redirect@example.test", "Redirect User")
        token = self.csrf_token(client, "/login")
        response = client.post("/login?next=//attacker.example", data={
            "csrf_token": token,
            "email": "redirect@example.test",
            "password": "campus-pass-123",
        }, follow_redirects=False)
        self.assertEqual(response.headers["Location"], "/")

        token = self.csrf_token(client, "/login")
        response = client.post("/login?next=/dashboard", data={
            "csrf_token": token,
            "email": "redirect@example.test",
            "password": "campus-pass-123",
        }, follow_redirects=False)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_claims_are_unique_and_only_one_claim_can_resolve_item(self):
        owner = self.create_user("owner@example.test", "Owner")
        item_id = self.create_report(owner)
        claimant = self.create_user("claimant@example.test", "Claimant")
        other_claimant = self.create_user("other@example.test", "Other Claimant")

        claim_path = f"/item/{item_id}/claim"
        first_token = self.csrf_token(claimant, f"/item/{item_id}")
        first = claimant.post(claim_path, data={"csrf_token": first_token, "message": "Mine."})
        duplicate = claimant.post(claim_path, data={"csrf_token": first_token, "message": "Still mine."})
        second_token = self.csrf_token(other_claimant, f"/item/{item_id}")
        second = other_claimant.post(claim_path, data={"csrf_token": second_token, "message": "I can identify it."})
        self.assertEqual((first.status_code, duplicate.status_code, second.status_code), (302, 302, 302))

        with app_module.app.app_context():
            claim_ids = [row[0] for row in app_module.db().execute(
                "SELECT id FROM claims WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()]
        self.assertEqual(len(claim_ids), 2)

        owner_token = self.csrf_token(owner, f"/item/{item_id}")
        approved = owner.post(f"/claim/{claim_ids[0]}/approve", data={"csrf_token": owner_token})
        stale_approval = owner.post(f"/claim/{claim_ids[1]}/approve", data={"csrf_token": owner_token})
        stale_rejection = owner.post(f"/claim/{claim_ids[0]}/reject", data={"csrf_token": owner_token})
        self.assertEqual((approved.status_code, stale_approval.status_code, stale_rejection.status_code),
                         (302, 302, 302))
        self.assertEqual(self.row("SELECT status FROM items WHERE id=?", (item_id,))[0], "resolved")
        statuses = self.row(
            "SELECT group_concat(status, ',') FROM (SELECT status FROM claims WHERE item_id=? ORDER BY id)",
            (item_id,),
        )[0].split(",")
        self.assertEqual(statuses, ["approved", "rejected"])

    def test_manual_resolve_rejects_pending_claims(self):
        owner = self.create_user("manual-owner@example.test", "Owner")
        item_id = self.create_report(owner, "Green notebook")
        claimant = self.create_user("manual-claimant@example.test", "Claimant")
        path = f"/item/{item_id}/claim"
        claimant.post(path, data={"csrf_token": self.csrf_token(claimant, f"/item/{item_id}"),
                      "message": "My notebook."})
        response = owner.post(f"/item/{item_id}/resolve", data={
            "csrf_token": self.csrf_token(owner, f"/item/{item_id}")
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.row("SELECT status FROM claims WHERE item_id=?", (item_id,))[0], "rejected")

    def test_invalid_and_future_event_dates_are_rejected(self):
        client = self.create_user("date@example.test", "Date User")
        for event_date in ("not-a-date", (date.today() + timedelta(days=1)).isoformat()):
            response = client.post("/report", data={
                "csrf_token": self.csrf_token(client, "/report"),
                "type": "lost",
                "title": "Test item",
                "description": "Test description",
                "category": "Keys",
                "location": "Library",
                "date_event": event_date,
            })
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.row("SELECT COUNT(*) FROM items")[0], 0)

    def test_large_page_numbers_are_clamped(self):
        response = app_module.app.test_client().get("/?page=999999999999999999999999999999")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_reports_unread_count_before_marking_read(self):
        client = self.create_user("alerts@example.test", "Alerts User")
        with app_module.app.app_context():
            user_id = app_module.db().execute(
                "SELECT id FROM users WHERE email=?", ("alerts@example.test",)
            ).fetchone()[0]
            app_module.db().executemany(
                "INSERT INTO notifications(user_id,message,is_read) VALUES(?,?,?)",
                [(user_id, "Unread one", 0), (user_id, "Unread two", 0), (user_id, "Already read", 1)],
            )
            app_module.db().commit()
        response = client.get("/dashboard")
        self.assertRegex(response.get_data(as_text=True), r"Unread alerts</span>\s*<strong>2</strong>")
        self.assertEqual(self.row("SELECT SUM(is_read=0) FROM notifications WHERE user_id=?", (user_id,))[0], 0)

    def test_seeded_admin_does_not_use_known_password(self):
        password_hash = self.row(
            "SELECT password_hash FROM users WHERE role='admin' LIMIT 1"
        )[0]
        self.assertFalse(check_password_hash(password_hash, "admin123"))

    def test_configured_admin_password_can_rotate_existing_admin(self):
        replacement = "replacement-admin-password-123"
        app_module.app.config["INITIAL_ADMIN_PASSWORD"] = replacement
        app_module.init_db()
        password_hash = self.row(
            "SELECT password_hash FROM users WHERE role='admin' LIMIT 1"
        )[0]
        self.assertTrue(check_password_hash(password_hash, replacement))


if __name__ == "__main__":
    unittest.main()