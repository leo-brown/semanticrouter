"""Actual HTTP sessions, CSRF, invitations and tenant-scoped workspace persistence.

Only synthetic identities/configs are used. PHP listens on loopback for the test's
lifetime; SQLite and cookies are isolated in a disposable directory.
"""

import contextlib
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parents[1]


class Client:
    def __init__(self, base):
        self.base = base
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.csrf = ""

    def request(self, action, payload=None, setup=False, csrf=True):
        headers = {"X-Semanticrouter-Setup": "test-setup-token"} if setup else {}
        if payload is None:
            from urllib.parse import urlencode

            url = self.base + "/api.php?" + urlencode({"action": action})
            data = None
        else:
            url = self.base + "/api.php"
            data = json.dumps({"action": action, **payload}).encode()
            headers["Content-Type"] = "application/json"
            if csrf:
                headers["X-CSRF-Token"] = self.csrf
        try:
            with self.http.open(
                urllib.request.Request(url, data=data, headers=headers), timeout=10
            ) as result:
                status, value = result.status, json.load(result)
        except urllib.error.HTTPError as error:
            with error:
                status, value = error.code, json.load(error)
        if value.get("csrf"):
            self.csrf = value["csrf"]
        return status, value

    def get(self, action, **values):
        from urllib.parse import urlencode

        query = urlencode({"action": action, **values})
        try:
            with self.http.open(self.base + "/api.php?" + query, timeout=10) as result:
                return result.status, json.load(result)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)


@unittest.skipUnless(shutil.which("php"), "PHP is required")
class TeamHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "pdo_sqlite" not in subprocess.check_output(["php", "-m"], text=True):
            raise unittest.SkipTest("PDO SQLite is required")
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        web = cls.root / "web"
        web.mkdir()
        shutil.copytree(ROOT / "playground/server", web / "server")
        for name in ("api.php", "oauth_callback.php", "login.php"):
            shutil.copyfile(ROOT / "playground" / name, web / name)
        # A fixture identity provider exists only in this disposable HTTP server.
        # Production has no endpoint that accepts an asserted GitHub identity.
        (web / "fixture.php").write_text("""<?php
require __DIR__ . '/server/auth.php';
SemanticRouter\\sessionStart(); $store=SemanticRouter\\database(); try {
$name=$_GET['who'] ?? 'owner';
$ids=['owner'=>1001,'other'=>2001,'member'=>3001];
$user=$store->githubAccount(['id'=>$ids[$name], 'login'=>$name]);
SemanticRouter\\authenticate($user);
if (!empty($_GET['invite'])) $extra=['token'=>$store->invite($user['id'],$_GET['team'],['id'=>3001,'login'=>'member'])];
elseif (!empty($_GET['accept'])) { $store->acceptGithub($user['id'],$_GET['accept']); $extra=[]; }
else $extra=[];
if ($name!=='member' && !$store->teams($user['id'])) $store->createTeam($user['id'],$name.' team');
header('Content-Type: application/json');
echo json_encode(['ok'=>true,'user'=>$user,'csrf'=>SemanticRouter\\csrf(),'teams'=>$store->teams($user['id']),...$extra]);
} catch (Throwable $e) { http_response_code(400); echo json_encode(['error'=>$e->getMessage()]); }
""")
        cls.web = web
        env = {
            **os.environ,
            "SEMANTICROUTER_STANDALONE": "1",
            "SEMANTICROUTER_SETUP_TOKEN": "test-setup-token",
            "SEMANTICROUTER_DB_DSN": "sqlite:" + str(cls.root / "teams.sqlite"),
            "SEMANTICROUTER_GITHUB_CLIENT_ID": "test-client-id-1234",
            "SEMANTICROUTER_GITHUB_CLIENT_SECRET": "synthetic-client-secret-12345",
        }
        cls.server = subprocess.Popen(
            ["php", "-S", f"127.0.0.1:{port}", "-t", str(web)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        cls.addClassCleanup(
            lambda: cls.server.kill() if cls.server.poll() is None else None
        )
        cls.addClassCleanup(cls.directory.cleanup)
        for _ in range(100):
            try:
                cls.owner = Client(cls.base)
                if cls.owner.request("session", setup=True)[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.02)
        else:
            cls.server.terminate()
            raise RuntimeError("Test PHP server did not start")

        def fixture(client, **values):
            from urllib.parse import urlencode

            with client.http.open(
                cls.base + "/fixture.php?" + urlencode(values)
            ) as response:
                data = json.load(response)
            client.csrf = data["csrf"]
            return data

        cls.fixture = staticmethod(fixture)
        cls.team = fixture(cls.owner, who="owner")["teams"][0]["id"]
        cls.other = Client(cls.base)
        cls.other_team = fixture(cls.other, who="other")["teams"][0]["id"]

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            cls.server.wait(timeout=5)
        if cls.server.poll() is None:
            cls.server.kill()
        cls.directory.cleanup()

    def test_anonymous_requests_and_missing_csrf_are_denied(self):
        client = Client(self.base)
        self.assertEqual(client.get("workspaces", team_id=self.team)[0], 401)
        client.request("session")
        self.assertEqual(
            client.request("create_team", {"name": "Denied"}, csrf=False)[0], 403
        )
        self.assertEqual(
            client.request("configure_github", {"client_id": "example"})[0], 403
        )

    def test_workspace_revisions_and_team_isolation(self):
        snapshot = {"routers": [], "rules": [], "policy": {}, "sources": {}}
        status, data = self.owner.request(
            "save_workspace",
            {
                "team_id": self.team,
                "name": "Migration lab",
                "snapshot": snapshot,
                "revision": 0,
            },
        )
        self.assertEqual(status, 200, data)
        workspace = data["workspace"]
        self.assertEqual(
            self.other.get("workspace", team_id=self.team, id=workspace["id"])[0], 403
        )
        self.assertEqual(self.other.get("workspaces", team_id=self.team)[0], 403)
        payload = {**workspace, "team_id": self.team, "name": "Updated lab"}
        status, updated = self.owner.request("save_workspace", payload)
        self.assertEqual(status, 200, updated)
        self.assertEqual(updated["workspace"]["revision"], 2)
        self.assertEqual(self.owner.request("save_workspace", payload)[0], 409)
        self.assertEqual(
            self.other.request(
                "save_workspace", {**payload, "team_id": self.other_team}
            )[0],
            409,
        )
        self.assertEqual(
            self.owner.get("workspace", team_id=self.team, id=workspace["id"])[1][
                "workspace"
            ]["name"],
            "Updated lab",
        )

    def test_invite_is_identity_bound_single_use_and_members_cannot_invite(self):
        data = self.fixture(self.owner, who="owner", invite="yes", team=self.team)
        member = Client(self.base)
        self.fixture(member, who="member", accept=data["token"])
        self.assertEqual(member.request("session")[1]["teams"][0]["role"], "member")
        self.assertEqual(
            member.request("invite", {"team_id": self.team, "github_login": "next"})[0],
            403,
        )
        # A second use fails in the underlying transactional service.
        with self.assertRaises(urllib.error.HTTPError) as rejected:
            self.fixture(member, who="member", accept=data["token"])
        rejected.exception.close()
        self.assertEqual(member.get("workspaces", team_id=self.team)[0], 200)
        member.request("session")
        self.assertEqual(member.request("logout", {})[0], 200)
        self.assertIsNone(member.request("session")[1]["user"])

    def test_oauth_starts_with_pkce_without_exposing_the_secret(self):
        from urllib.parse import parse_qs, urlparse

        client = Client(self.base)
        client.request("session")
        status, data = client.request("oauth_start", {})
        self.assertEqual(status, 200, data)
        url = urlparse(data["url"])
        params = parse_qs(url.query)
        self.assertEqual(url.netloc, "github.com")
        self.assertEqual(params["scope"], ["read:user"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(len(params["code_challenge"][0]), 43)
        self.assertNotIn("synthetic-client-secret", json.dumps(data))

    def test_team_bootstrap_is_empty_and_contains_no_bf_source_access(self):
        status, data = self.owner.get("bootstrap")
        self.assertEqual(status, 200, data)
        self.assertEqual(data["routers"], [])
        self.assertEqual(data["rules"], [])
        self.assertNotIn("source_url", data)
        self.assertNotIn("source_hashes", data)
        self.assertTrue(data["workspace_namespace"].startswith("user-"))

    def test_git_requires_membership_before_starting_a_process(self):
        payload = {"team_id": self.team, "url": "git@github.com:example/private.git"}
        self.assertEqual(self.other.request("git_pull", payload)[0], 403)
