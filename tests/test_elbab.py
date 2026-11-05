#!/usr/bin/env python3
"""elbab tests. Every test uses throwaway stores, identities and homes; nothing touches real credentials.

Opt-in backend tests (they create and then delete a real OS secret):
  ELBAB_TEST_KEYCHAIN=1   macOS login Keychain
  ELBAB_TEST_TPM=1        Linux TPM through systemd-creds
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

ELBAB = Path(__file__).resolve().parent.parent / "bin" / "elbab"
FAKE_KEY = "sk-test-" + "x" * 40
WINDOWS = os.name == "nt"
HOST = __import__("re").sub(r"[^a-z0-9-]+", "-", __import__("platform").node().split(".")[0].lower()).strip("-") or "host"
FAKE_TOOL = r'''import os, sys
d = os.path.join(os.environ["ELBAB_USER_HOME"], ".faketool")
db = os.path.join(d, "credentials.db")
sys.stdout.write(open(db).read() if os.path.exists(db) else "")
print()
if sys.argv[1:2] == ["logout"]:
    os.remove(db)
else:
    open(os.path.join(d, "access_tokens.db"), "a").write("tok")
sys.exit(3)
'''


def keygen(path):
    subprocess.run(["age-keygen", "-o", str(path)], check=True, capture_output=True)
    return subprocess.run(["age-keygen", "-y", str(path)], check=True, capture_output=True, text=True).stdout


def executable(folder, name, script):
    """A command named NAME in FOLDER that runs a Python script, on any OS."""
    folder.mkdir(parents=True, exist_ok=True)
    py = folder / f"{name}.py"
    py.write_text(script)
    if WINDOWS:
        (folder / f"{name}.cmd").write_text(f'@"{sys.executable}" "{py}" %*\r\n')
    else:
        (folder / name).write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py}" "$@"\n')
        (folder / name).chmod(0o755)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def e(self, *args, stdin=None, ok=True, env=None):
        r = subprocess.run([sys.executable, "-I", str(ELBAB), *args], input=stdin, capture_output=True,
                           text=True, env=env or self.env)
        if ok:
            self.assertEqual(r.returncode, 0, r.stderr)
        return r


class InitTest(Base):
    def env_for(self, machine):
        return {k: v for k, v in dict(os.environ, ELBAB_HOME=str(self.base / f"{machine}-store"),
                                      ELBAB_CONFIG=str(self.base / f"{machine}-config")).items()
                if k != "ELBAB_IDENTITY_FILE"}

    def test_init_join_recover(self):
        self.env = a = self.env_for("a")
        recovery = self.base / "recovery.txt"
        out = self.e("init", "--backend", "file", "--recovery", str(recovery)).stdout
        self.assertIn("recipient age1", out)
        self.assertNotEqual(self.e("init", "--backend", "file", ok=False).returncode, 0)  # never twice
        self.e("set-key", "demo", "TOKEN", stdin="value-1")
        self.assertEqual(self.e("get", "demo", "TOKEN").stdout, "value-1")
        self.e("verify")
        self.assertEqual(self.e("get", "demo", "TOKEN", env=dict(a, ELBAB_IDENTITY_FILE=str(recovery))).stdout, "value-1")

        b = self.env_for("b")  # a second machine joins: its recipient is added on A, then the store is copied
        join = self.e("init", "--backend", "file", "--join", env=b).stdout
        recipient = next(w for w in join.split() if w.startswith("age1"))
        self.e("recipients", "add", recipient, "--name", "machine-b")
        self.assertIn("machine-b", self.e("recipients").stdout)
        self.e("rekey")
        shutil.copytree(a["ELBAB_HOME"], b["ELBAB_HOME"])
        self.assertEqual(self.e("get", "demo", "TOKEN", env=b).stdout, "value-1")
        self.assertNotEqual(self.e("init", "--backend", "file", env=b, ok=False).returncode, 0)

    def test_existing_identity_file_and_command(self):
        ident = self.base / "existing.txt"
        keygen(ident)
        if not WINDOWS:
            ident.chmod(0o600)
        self.env = self.env_for("c")
        self.e("init", "--identity-file", str(ident))
        self.e("set-key", "x", "Y", stdin="z")
        self.env = self.env_for("d")
        self.e("init", "--command", f'"{sys.executable}" -c "import sys; sys.stdout.write(open(sys.argv[1]).read())" "{ident}"')
        self.e("set-key", "x", "Y", stdin="z2")
        self.assertEqual(self.e("get", "x", "Y").stdout, "z2")
        self.assertEqual(self.e("get", "x", "Y", env=dict(self.env, ELBAB_IDENTITY_FILE=str(ident))).stdout, "z2")

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("age-plugin-se"), "needs macOS and age-plugin-se")
    def test_secure_enclave(self):
        self.env = self.env_for("se")
        r = self.e("init", "--backend", "secure-enclave", ok=False)
        if r.returncode:
            self.skipTest(f"no usable Secure Enclave: {r.stderr.strip()}")
        self.assertIn("age1se1", r.stdout)
        self.e("set-key", "se", "K", stdin="enclave-value")
        self.assertEqual(self.e("get", "se", "K").stdout, "enclave-value")

    @unittest.skipUnless(sys.platform == "darwin" and os.environ.get("ELBAB_TEST_KEYCHAIN"), "opt-in: ELBAB_TEST_KEYCHAIN=1")
    def test_keychain(self):
        service = f"elbab-test-{os.getpid()}"
        self.env = self.env_for("kc")
        try:
            self.e("init", "--backend", "keychain", "--service", service)
            self.assertNotEqual(self.e("init", "--backend", "keychain", "--service", service,
                                       env=dict(self.env, ELBAB_CONFIG=self.env["ELBAB_CONFIG"] + "-2"), ok=False).returncode, 0)
            self.e("set-key", "kc", "K", stdin="keychain-value")
            self.assertEqual(self.e("get", "kc", "K").stdout, "keychain-value")
        finally:
            subprocess.run(["/usr/bin/security", "delete-generic-password", "-s", service], capture_output=True)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("ELBAB_TEST_TPM"), "opt-in: ELBAB_TEST_TPM=1")
    def test_tpm(self):
        self.env = self.env_for("tpm")
        self.e("init", "--backend", "tpm")
        self.e("set-key", "tpm", "K", stdin="tpm-value")
        self.assertEqual(self.e("get", "tpm", "K").stdout, "tpm-value")
        self.e("verify")
        import hashlib  # remove this test's RAM cache; its name hashes the credential path, so no other store's is touched
        cred = json.loads((Path(self.env["ELBAB_CONFIG"]) / "config.json").read_text())["identity"]["path"]
        run = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")
        (run / f"elbab-identity-{hashlib.sha256(cred.encode()).hexdigest()[:12]}").unlink(missing_ok=True)

    @unittest.skipUnless(WINDOWS, "Windows only")
    def test_dpapi(self):
        self.env = self.env_for("dpapi")
        self.e("init")  # dpapi is the Windows default
        self.e("set-key", "win", "K", stdin="dpapi-value")
        self.assertEqual(self.e("get", "win", "K").stdout, "dpapi-value")
        blob = (Path(self.env["ELBAB_CONFIG"]) / "identity.dpapi").read_bytes()
        self.assertNotIn(b"AGE-SECRET-KEY", blob)


class StoreTest(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.root = cls.base / "store"
        cls.root.mkdir(mode=0o700)
        cls.ident = cls.base / "id.txt"
        (cls.root / "recipients.txt").write_text(f"# test\n{keygen(cls.ident)}")
        keys = {"entries": {"demo.local": {"provider": "Demo", "scope": "testing", "credentials": {"DEMO_KEY": FAKE_KEY}}}}
        (cls.root / "keys.json").write_text(json.dumps(keys))
        (cls.root / "logins.csv").write_text("record_id,service,url,username,password,notes\n"
                                             "1,Portal,https://portal.example,ann,hunter2pass,plain note\n")
        (cls.root / "accounts.json").write_text(json.dumps({"credentials": {"payroll": {"username": "u", "password": "pw1"}}}))
        (cls.root / "backups").mkdir()
        (cls.root / "backups" / "old.csv").write_text("password\nsecretold\n")
        (cls.root / ".DS_Store").write_text("junk")
        cls.home = cls.base / "home"
        cls.home.mkdir()
        cls.env = dict(os.environ, ELBAB_HOME=str(cls.root), ELBAB_IDENTITY_FILE=str(cls.ident),
                       ELBAB_CONFIG=str(cls.base / "config"), ELBAB_USER_HOME=str(cls.home), ELBAB_NO_KEYCHAIN="1")

    def test_1_migrate_purge_verify(self):
        self.assertNotEqual(self.e("verify", ok=False).returncode, 0)  # plaintext still present
        self.e("migrate")
        self.e("purge-plaintext")
        self.assertFalse((self.root / "keys.json").exists())
        self.assertFalse((self.root / ".DS_Store").exists())
        self.assertTrue((self.root / "backups" / "old.csv.age").exists())
        self.assertIn("encrypted files decrypt", self.e("verify").stdout)
        for path in self.root.rglob("*"):
            if path.is_file() and path.name not in ("recipients.txt", "index.json"):
                self.assertNotIn(b"hunter2pass", path.read_bytes(), path)
                self.assertNotIn(FAKE_KEY.encode(), path.read_bytes(), path)

    def test_2_lookups(self):
        self.assertIn("demo.local: testing", self.e("list").stdout)
        self.assertEqual(self.e("get", "demo.local", "DEMO_KEY").stdout, FAKE_KEY)
        r = self.e("run", "demo.local", "--", sys.executable, "-c",
                   f'import os; assert os.environ["DEMO_KEY"] == "{FAKE_KEY}"; print("ok")')
        self.assertEqual(r.stdout.strip(), "ok")
        self.assertNotIn(FAKE_KEY, self.e("show", "keys.json").stdout)
        self.assertNotIn("pw1", self.e("show", "accounts.json").stdout)
        self.assertEqual(self.e("field", "accounts.json", "credentials/payroll/password").stdout, "pw1")
        q = self.e("csv", "query", "-w", "service=port").stdout
        self.assertIn("ann", q)
        self.assertNotIn("hunter2pass", q)
        self.assertIn("hunter2pass", self.e("csv", "query", "--reveal").stdout)
        self.assertIn("ann", self.e("csv", "query", "-a", "PLAIN NOTE").stdout)
        self.assertNotIn("ann", self.e("csv", "query", "-a", "hunter2").stdout)
        self.assertEqual(self.e("csv", "get", "1", "password").stdout, "hunter2pass")

    def test_3_writes(self):
        self.e("csv", "upsert", stdin=json.dumps({"record_id": "2", "service": "New", "password": "pw2"}))
        self.e("csv", "upsert", stdin=json.dumps({"record_id": "1", "notes": "changed"}))
        self.assertEqual(self.e("csv", "get", "2", "password").stdout, "pw2")
        self.assertEqual(self.e("csv", "get", "1", "notes").stdout, "changed")
        self.assertEqual(self.e("csv", "get", "1", "password").stdout, "hunter2pass")
        self.assertNotEqual(self.e("csv", "upsert", stdin=json.dumps({"record_id": "3", "bogus": 1}), ok=False).returncode, 0)
        self.e("set", "accounts.json", "credentials/payroll/password", stdin="pw3\n")
        self.assertEqual(self.e("field", "accounts.json", "credentials/payroll/password").stdout, "pw3")
        self.e("set-key", "new.entry", "NEW_KEY", "--scope", "new scope", stdin="value-123\n")
        self.assertEqual(self.e("get", "new.entry", "NEW_KEY").stdout, "value-123")
        self.assertIn("new.entry: new scope", self.e("list").stdout)
        self.e("put", "accounts/x.json", stdin='{"a": 1}')
        self.assertEqual(self.e("cat", "accounts/x.json").stdout, '{"a": 1}')
        backups = list((self.root / "backups").glob("*"))
        self.assertTrue(any(b.name.startswith("logins.csv.") and b.name.endswith(".age") for b in backups))
        for b in backups:
            self.assertNotIn(b"pw2", b.read_bytes())
        self.assertNotEqual(self.e("cat", "../etc/passwd", ok=False).returncode, 0)
        self.e("verify")

    def test_3a_import_env_and_encrypt(self):
        env_file = self.home / "app.env"
        env_file.write_text('# comment\nexport API_TOKEN="tok en"\nDB_PASSWORD=pw # trailing\nEMPTY=\nnot a line\n')
        r = self.e("import-env", "app", str(env_file))
        self.assertNotIn("tok en", r.stdout + r.stderr)
        self.assertEqual(self.e("get", "app", "API_TOKEN").stdout, "tok en")
        self.assertEqual(self.e("get", "app", "DB_PASSWORD").stdout, "pw")
        r = self.e("run", "app", "--", sys.executable, "-c", 'import os; print(os.environ["API_TOKEN"])')
        self.assertEqual(r.stdout.strip(), "tok en")
        self.e("encrypt", str(env_file))
        self.assertNotIn(b"tok en", env_file.read_bytes())
        self.assertIn("tok en", self.e("print", str(env_file)).stdout)
        self.e("decrypt", str(env_file))
        self.assertIn("tok en", env_file.read_text())

    def test_3b_show_and_dump(self):
        env = {k: v for k, v in self.env.items() if k != "ELBAB_IDENTITY_FILE"}
        for flag in ("--show", "--dump"):  # no terminal, so it refuses before asking for a password
            r = subprocess.run([sys.executable, "-I", str(ELBAB), flag], env=env, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, **({"creationflags": subprocess.DETACHED_PROCESS} if WINDOWS
                                                            else {"start_new_session": True}))  # no console or tty
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("password", r.stderr)
        doc = json.loads(self.e("--show").stdout)
        self.assertEqual(doc["files"]["keys.json"]["entries"]["demo.local"]["credentials"]["DEMO_KEY"], FAKE_KEY)
        self.assertEqual(doc["files"]["logins.csv"][0]["password"], "hunter2pass")
        self.assertEqual(list(doc["files"])[:2], ["keys.json", "logins.csv"])
        self.assertFalse(any(n.startswith("backups/") for n in doc["files"]))
        self.assertTrue(any(n.startswith("backups/") for n in json.loads(self.e("--show", "--backups").stdout)["files"]))
        out = self.base / "export"
        out.mkdir()
        path = Path(self.e("--dump", str(out)).stdout.strip())
        self.assertEqual(path.parent, out)
        if not WINDOWS:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.e("--dump", str(path), ok=False).returncode, 0)  # never overwrites
        import xml.etree.ElementTree as ET
        import zipfile
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            for part in names:
                ET.fromstring(z.read(part))
            self.assertIn(b"hunter2pass", b"".join(z.read(n) for n in names))

    def test_3c_aws(self):
        (self.home / ".aws").mkdir(exist_ok=True)
        creds = self.home / ".aws" / "credentials"
        creds.write_text("[default]\naws_access_key_id = TESTKEYID0001\naws_secret_access_key = s3cr3t/abc+def\n"
                         "region = us-west-2\n\n[other]\naws_access_key_id = TESTKEYID0002\naws_secret_access_key = two\n"
                         "\n[plain]\nregion = us-east-1\n")
        creds.chmod(0o600)
        self.e("aws-protect", str(creds))
        stub = creds.read_text()
        self.assertNotIn("TESTKEYID", stub)
        self.assertNotIn("s3cr3t", stub)
        self.assertIn("region = us-west-2", stub)
        self.assertIn("[plain]", stub)
        self.assertEqual(stub.count("credential_process"), 2)
        self.assertEqual(json.loads(self.e("aws", "credentials", "default").stdout),
                         {"Version": 1, "AccessKeyId": "TESTKEYID0001", "SecretAccessKey": "s3cr3t/abc+def"})
        self.assertEqual(json.loads(self.e("aws", "credentials", "other").stdout)["SecretAccessKey"], "two")
        self.assertNotEqual(self.e("aws", "credentials", "plain", ok=False).returncode, 0)
        self.assertIn("skipped", self.e("aws-protect", str(creds)).stdout)  # a stub has no keys left to move
        if shutil.which("aws"):  # the real CLI resolves the stub through credential_process
            r = subprocess.run(["aws", "configure", "list"], env=dict(self.env, AWS_SHARED_CREDENTIALS_FILE=str(creds),
                               AWS_CONFIG_FILE=str(self.base / "no-config")), capture_output=True, text=True)
            self.assertIn("custom-process", r.stdout, r.stderr)

    def test_3d_ssh(self):
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700, exist_ok=True)
        key = ssh / "work.pem"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "work", "-f", str(key)], check=True)
        pub = (ssh / "work.pem.pub").read_text().split()[:2]
        (ssh / "work.pem.pub").unlink()  # protect writes the missing .pub
        if not WINDOWS:
            key.chmod(0o400)
        (ssh / "empty.pub").write_text("")
        self.e("ssh-protect", str(key))
        self.assertEqual((ssh / "work.pem.pub").read_text().split()[:2], pub)
        if not WINDOWS:
            self.assertEqual(key.stat().st_mode & 0o777, 0o400)
        self.assertNotEqual(subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)], capture_output=True).returncode, 0)
        secret = self.e("ssh-pass", str(key)).stdout
        self.assertGreater(len(secret), 30)
        out = subprocess.run(["ssh-keygen", "-y", "-P", secret, "-f", str(key)], capture_output=True, text=True).stdout
        self.assertEqual(out.split()[:2], pub)
        self.assertIn("already has a passphrase", self.e("ssh-protect", str(key)).stdout)
        scan = self.e("scan", str(ssh)).stdout
        self.assertIn("private-key (passphrase)", scan)
        self.assertEqual(self.e("pubkeys", "work.pem").stdout.split()[:2], pub)
        self.assertEqual(self.e("pubkeys", "work").stdout.split()[:2], pub)
        listing = self.e("pubkeys", "--list").stdout
        self.assertIn("passphrase", listing)
        self.assertNotIn("empty", listing)
        self.assertIn("# work.pem", self.e("pubkeys").stdout)
        if WINDOWS:
            return
        d = tempfile.mkdtemp()
        agent = subprocess.Popen(["ssh-agent", "-D", "-a", f"{d}/s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.3)
            env = dict(self.env, SSH_AUTH_SOCK=f"{d}/s")
            self.assertIn("loaded", self.e("ssh-load", env=env).stdout)
            listed = subprocess.run(["ssh-add", "-L"], env=env, capture_output=True, text=True).stdout
            self.assertEqual(listed.split()[:2], pub)
            extra = ssh / "extra"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(extra)], check=True)
            subprocess.run(["ssh-add", str(extra)], env=env, capture_output=True, check=True)
            self.e("ssh-load", "--exact", str(key), env=env)  # drops the extra key, no prompt
            listed = subprocess.run(["ssh-add", "-L"], env=env, capture_output=True, text=True).stdout.splitlines()
            self.assertEqual([l.split()[:2] for l in listed], [pub])
            self.assertEqual(self.e("ssh-load", "--exact", str(key), env=env).stdout, "")  # already exact
        finally:
            agent.terminate()
            agent.wait()
            shutil.rmtree(d, ignore_errors=True)
        self.e("verify")

    def test_3e_guard(self):
        tooldir = self.home / ".faketool"
        tooldir.mkdir()
        (tooldir / "credentials.db").write_text("refresh-token-1")
        (tooldir / "settings.ini").write_text("[core]\naccount = me\n")
        fake = self.base / "fakebin"
        executable(fake, "faketool", FAKE_TOOL)
        out = self.e("guard-add", "faketool", "--dir", ".faketool", "--files", "credentials.db*",
                     "--files", "access_tokens.db*").stdout
        self.assertIn("1 login files", out)
        env = dict(self.env, PATH=os.pathsep.join([str(self.root / "shims"), str(fake), os.environ["PATH"]]))
        tool = shutil.which("faketool", path=env["PATH"])
        self.assertIn("shims", tool)
        run = lambda *a: subprocess.run([tool, *a], env=env, capture_output=True, text=True)
        self.assertIn("sealed 1", self.e("guard-seal", "faketool").stdout)
        self.assertFalse((tooldir / "credentials.db").exists())
        self.assertTrue((tooldir / "settings.ini").exists())  # settings stay
        r = run("auth", "list")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("refresh-token-1", r.stdout)
        self.assertFalse((tooldir / "credentials.db").exists())
        self.assertFalse((tooldir / "access_tokens.db").exists())
        self.assertEqual(self.e("cat", "tools/faketool/access_tokens.db").stdout, "tok")
        run("x")
        self.assertEqual(self.e("cat", "tools/faketool/access_tokens.db").stdout, "toktok")
        (tooldir / "credentials.db").write_text("")  # an unguarded run creates an empty database
        r = run("auth", "list")
        self.assertIn("refresh-token-1", r.stdout)  # the stored login wins
        self.assertIn("changed outside", r.stderr)
        self.assertTrue(list((self.root / "tools-conflicts/faketool").glob("credentials.db.*.age")))
        run("logout")  # the tool deletes its login, so the stored copy goes too
        self.assertNotEqual(self.e("cat", "tools/faketool/credentials.db", ok=False).returncode, 0)
        for f in tooldir.rglob("*"):
            if f.is_file():
                self.assertNotIn(b"refresh-token-1", f.read_bytes(), f)
        names = self.e("shims").stdout
        self.assertIn("gcloud", names)
        self.assertIn("faketool", names)
        self.e("verify")

    def test_3f_scan(self):
        d = self.base / "scan"
        d.mkdir()
        (d / "wallet.json").write_text(json.dumps(list(range(64))))
        (d / "id_test").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        (d / ".env").write_text("API_TOKEN=abcdefgh12345678\n")
        (d / "notes.txt").write_text("nothing here\n")
        (d / "node_modules").mkdir()
        (d / "node_modules" / "x.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
        r = self.e("scan", str(d))
        self.assertIn("wallet-keypair", r.stdout)
        self.assertIn("private-key\t", r.stdout)
        self.assertIn("env-secret", r.stdout)
        self.assertNotIn("notes.txt", r.stdout)
        self.assertNotIn("node_modules", r.stdout)
        self.assertNotIn("abcdefgh12345678", r.stdout)
        self.assertIn("3 files", r.stderr)

    def test_3g_paths(self):
        work = self.home / "work"
        d = work / ".keys"
        (d / "sub").mkdir(parents=True)
        (d / "a.json").write_text("[1,2,3]")
        (d / "a.json").chmod(0o644)
        (d / "sub" / "b.json").write_text("secret-b")
        (d / "run.sh").write_text("#!/bin/sh\necho hi\n")
        (d / "run.sh").chmod(0o755)
        (d / ".DS_Store").write_text("junk")
        run = lambda *a: subprocess.run([sys.executable, "-I", str(ELBAB), *a], env=self.env, cwd=work,
                                        capture_output=True, text=True)
        py = lambda code: [sys.executable, "-c", code]
        leftovers = lambda: sorted(p.name for p in work.iterdir() if ".elbab-" in p.name)
        magic = lambda p: p.read_bytes()[:22] == b"age-encryption.org/v1\n"
        # one file, in place: same path, ciphertext, execute bit and time kept
        f = work / "tool.sh"
        f.write_bytes(b"#!/bin/sh\necho secret-tool\n")
        f.chmod(0o755)
        os.utime(f, (1_600_000_000, 1_600_000_000))
        self.e("encrypt", str(f))
        self.assertTrue(magic(f))
        self.assertNotEqual(run("encrypt", "tool.sh").returncode, 0)  # already encrypted
        self.assertEqual(run("print", "tool.sh").stdout, "#!/bin/sh\necho secret-tool\n")
        plain = subprocess.run(["age", "-d", "-i", str(self.ident), str(f)], capture_output=True).stdout
        self.assertEqual(plain, b"#!/bin/sh\necho secret-tool\n")  # plain age reads it too
        self.e("decrypt", str(f))
        self.assertEqual(f.read_bytes(), b"#!/bin/sh\necho secret-tool\n")
        self.assertEqual(int(f.stat().st_mtime), 1_600_000_000)
        if not WINDOWS:
            self.assertEqual(f.stat().st_mode & 0o777, 0o700)
        self.assertNotEqual(run("decrypt", "tool.sh").returncode, 0)  # not encrypted
        # -o: a copy, the original untouched, never overwriting
        self.assertEqual(run("encrypt", "tool.sh", "-o", "tool.age").returncode, 0)
        self.assertFalse(magic(f))
        self.assertTrue(magic(work / "tool.age"))
        self.assertNotEqual(run("decrypt", "tool.age", "-o", "tool.sh").returncode, 0)
        self.assertEqual(run("decrypt", "tool.age", "-o", "copy.sh").returncode, 0)
        self.assertEqual((work / "copy.sh").read_bytes(), f.read_bytes())
        self.assertTrue(magic(work / "tool.age"))
        # refused: the store, the home folder, links
        self.assertNotEqual(run("encrypt", str(self.root / "keys.json.age")).returncode, 0)
        self.assertNotEqual(run("encrypt", str(self.home)).returncode, 0)
        self.assertTrue(self.home.is_dir())
        try:
            (work / "link").symlink_to(d)
        except OSError:  # Windows without symlink rights
            pass
        else:
            self.assertNotEqual(run("encrypt", "link").returncode, 0)
            (work / "link").unlink()
        # a folder: one age file at the same path, nothing left beside it
        self.assertIn("(3 files)", self.e("encrypt", str(d)).stdout)
        self.assertTrue(d.is_file() and magic(d))
        self.assertEqual(leftovers(), [])
        for p in [*self.root.rglob("*"), *work.rglob("*")]:
            if p.is_file():
                self.assertNotIn(b"secret-b", p.read_bytes(), p)
        self.assertEqual(run("print", ".keys").stdout,
                         "==> a.json <==\n[1,2,3]\n\n==> run.sh <==\n#!/bin/sh\necho hi\n\n==> sub/b.json <==\nsecret-b\n")
        blob = subprocess.run(["age", "-d", "-i", str(self.ident), str(d)], capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(blob)) as tar:  # plain age and tar read it too
            self.assertIn("sub/b.json", tar.getnames())
        self.assertEqual(run("decrypt", ".keys", "-o", "keys-copy").returncode, 0)
        self.assertEqual((work / "keys-copy" / "sub" / "b.json").read_text(), "secret-b")
        if not WINDOWS:
            self.assertEqual((work / "keys-copy" / "a.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((work / "keys-copy" / "run.sh").stat().st_mode & 0o777, 0o700)
        self.assertTrue(magic(d))
        # run: decrypted in place for the command, changes and deletions kept, encrypted again after
        script = ("import os, sys; sys.stdout.write(open('.keys/a.json').read()); open('.keys/new.txt', 'wb').write(b'new\\n'); "
                  "os.remove(os.path.join('.keys', 'sub', 'b.json')); sys.exit(4)")
        r = run("run", "./.keys", "--", *py(script))
        self.assertEqual((r.returncode, r.stdout), (4, "[1,2,3]"), r.stderr)
        self.assertTrue(magic(d))
        self.assertEqual(leftovers(), [])
        out = run("print", ".keys").stdout
        self.assertIn("==> new.txt <==\nnew\n", out)
        self.assertNotIn("b.json", out)
        backups = lambda: sorted((self.root / "backups").glob("paths__work__.keys.*.age"))
        self.assertEqual(len(backups()), 1)  # the version before the change
        before = d.read_bytes()
        r = run("run", str(d), *py(f"print(open({str(d / 'new.txt')!r}).read(), end='')"))
        self.assertEqual(r.stdout, "new\n", r.stderr)
        self.assertEqual(d.read_bytes(), before)  # nothing changed: the same ciphertext, no new backup
        self.assertEqual(len(backups()), 1)
        r = run("run", str(d), *py(f"import shutil; shutil.rmtree({str(d)!r})"))
        self.assertIn("restored", r.stderr)
        self.assertEqual(d.read_bytes(), before)
        r = run("run", str(d), *py(f"import os; os.mkfifo({str(d / 'x')!r})" if not WINDOWS else
                                   "import sys; sys.exit(9)"))
        if not WINDOWS:  # a special file cannot be encrypted: it stays decrypted and is reported
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("special files", r.stderr)
            self.assertTrue((d / "a.json").exists())
            self.assertIn("is decrypted now", self.e("verify").stdout)
            (d / "x").unlink()
            self.e("encrypt", str(d))  # picks up what the run left
            self.assertEqual(d.read_bytes(), before)
        self.assertEqual(leftovers(), [])
        self.assertNotIn("is decrypted now", self.e("verify").stdout)
        # decrypt in place: stays decrypted through runs, until encrypted again
        self.assertIn("(3 files)", self.e("decrypt", str(d)).stdout)
        r = run("run", "./.keys", *py("print(open('.keys/a.json').read(), end='')"))
        self.assertEqual(r.stdout, "[1,2,3]", r.stderr)
        self.assertTrue(d.is_dir())
        self.assertNotIn("is decrypted now", self.e("verify").stdout)  # on purpose, so no warning
        self.assertIn("==> a.json <==", run("print", ".keys").stdout)  # print reads plaintext too
        self.e("encrypt", str(d))
        self.assertIn("./NAME", run("run", "nope.local", "x").stderr)
        # the owner export shows each file of a folder encrypted in place
        r = subprocess.run([sys.executable, "-I", "-c", "import runpy, sys; g = runpy.run_path(sys.argv[1], run_name='x'); "
                            "f = g['export_files'](False); n = '~/work/.keys'; "
                            "print(g['sheet_rows'](n, f[n]))", str(ELBAB)], env=self.env, capture_output=True, text=True)
        self.assertIn("['new.txt', 'new\\n']", r.stdout, r.stderr)
        self.e("verify")

    def test_4_tmp_durations(self):
        for duration, seconds in (("12d", 1036800), ("2h", 7200), ("1m", 60), ("1h30m", 5400), ("1W", 604800)):
            name = "duration-" + duration.lower()
            result = self.e("tmp", name, duration, stdin="alice / temporary-dummy-password\n")
            self.assertNotIn("temporary-dummy-password", result.stdout + result.stderr)
            entry = json.loads(self.e("show", "keys.json", "--reveal").stdout)["entries"]["tmp." + name]
            self.assertTrue(entry["temporary"])
            self.assertEqual((datetime.fromisoformat(entry["expires_at"]) -
                              datetime.fromisoformat(entry["created_at"])).total_seconds(), seconds)
            self.assertEqual(entry["credentials"], {"USERNAME": "alice", "PASSWORD": "temporary-dummy-password"})
            self.assertIn("expires", self.e("list").stdout)
            self.assertNotIn("temporary-dummy-password", self.e("show", "keys.json").stdout)
        self.assertEqual(self.e("get", "tmp.duration-12d", "USERNAME").stdout, "alice")
        index = (self.root / "index.json").read_text()
        self.assertNotIn("temporary-dummy-password", index)
        self.assertNotIn("alice", index)
        env = {k: v for k, v in self.env.items() if k != "ELBAB_IDENTITY_FILE"}
        self.assertIn("tmp.duration-12d", self.e("list", env=env).stdout)  # the listing needs no identity

    def test_4a_tmp_invalid_inputs(self):
        before = (self.root / "keys.json.age").read_bytes()
        for duration in ("0m", "-2h", "2", "1.5h", "3months", "1h 2m", "9" * 70 + "d"):
            r = self.e("tmp", "invalid-duration", duration, stdin="do-not-store", ok=False)
            self.assertNotEqual(r.returncode, 0, duration)
            self.assertNotIn("do-not-store", r.stdout + r.stderr)
        for name, value in (("../escape", "a"), ("bad name", "a"), ("x", ""), ("x", "a\nb / pass")):
            self.assertNotEqual(self.e("tmp", name, "12d", stdin=value, ok=False).returncode, 0)
        self.assertEqual(before, (self.root / "keys.json.age").read_bytes())

    def test_4b_tmp_expiry_and_history(self):
        name, secret = "tmp.expires-soon", "expires-soon-dummy-password"
        self.e("tmp", "expires-soon", "2s", stdin=secret)
        self.e("set-key", "expiry-backup", "DUMMY", stdin="backup-test")
        history = str(max((self.root / "backups").glob("keys.json.*.age")).relative_to(self.root).as_posix())
        self.assertIn(secret, self.e("cat", history).stdout)
        time.sleep(2.1)
        self.assertNotIn(name, self.e("list").stdout)
        self.assertNotIn(secret, self.e("show", "keys.json", "--reveal").stdout)
        self.assertNotIn(secret, self.e("cat", "keys.json").stdout)
        self.assertNotIn(secret, self.e("cat", history).stdout)
        self.assertNotIn(secret, self.e("--show", "--backups").stdout)
        self.assertNotEqual(self.e("get", name, "PASSWORD", ok=False).returncode, 0)
        marker = self.base / "expired-command-ran"
        self.assertNotEqual(self.e("run", name, "--", sys.executable, "-c", f"open(r'{marker}', 'w')", ok=False).returncode, 0)
        self.assertFalse(marker.exists())

    def test_4c_concurrent_writes(self):
        commands = [(["tmp", "concurrent-a", "12d"], "dummy-a"), (["tmp", "concurrent-b", "2h"], "dummy-b"),
                    (["set-key", "concurrent-permanent", "KEEP"], "dummy-c"), (["concurrent-login"], "alice / dummy-d")]
        procs = [subprocess.Popen([sys.executable, "-I", str(ELBAB), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=self.env) for args, _ in commands]
        for proc, (_, value) in zip(procs, commands):
            proc.stdin.write(value)
            proc.stdin.close()
            proc.stdin = None
        for proc in procs:
            _, err = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(self.e("get", "tmp.concurrent-a", "PASSWORD").stdout, "dummy-a")
        self.assertEqual(self.e("get", "tmp.concurrent-b", "PASSWORD").stdout, "dummy-b")
        self.assertEqual(self.e("get", "concurrent-permanent", "KEEP").stdout, "dummy-c")
        self.assertEqual(self.e("get", "concurrent-login", "USERNAME").stdout, "alice")

    def test_4d_passwords_and_notes(self):
        secret = "permanent-password-dummy"
        r = self.e("saved-login", "--scope", "owner login", stdin=secret + "\n")
        self.assertIn("permanent (no expiry)", r.stderr)
        self.assertNotIn(secret, r.stdout + r.stderr)
        self.assertEqual(self.e("get", "saved-login", "PASSWORD").stdout, secret)
        self.assertIn("saved-login: owner login", self.e("list").stdout)
        self.e("owner@example.test", stdin="alice / dummy with spaces")
        self.assertEqual(self.e("get", "owner@example.test", "USERNAME").stdout, "alice")
        self.assertEqual(self.e("get", "owner@example.test", "PASSWORD").stdout, "dummy with spaces")
        self.e("save", "list", stdin="reserved-command-dummy")  # a label that matches a command
        self.assertEqual(self.e("get", "list", "PASSWORD").stdout, "reserved-command-dummy")
        before = (self.root / "keys.json.age").read_bytes()
        for name, value in (("../escape", "d"), ("bad name", "d"), ("empty-login", ""), ("bad-value", "alice / "),
                            ("tmp.x", "d"), ("demo.local", "d")):
            self.assertNotEqual(self.e(name, stdin=value, ok=False).returncode, 0, name)
        self.assertEqual(before, (self.root / "keys.json.age").read_bytes())
        note = "Needs the authenticator app.\nSecond line."
        self.e("noted-login", "--note", note, stdin="note-password-dummy")
        self.assertEqual(self.e("field", "keys.json", "entries/noted-login/notes").stdout, note)
        self.e("save", "noted-login", stdin="replacement-dummy")
        self.assertEqual(self.e("field", "keys.json", "entries/noted-login/notes").stdout, note)
        for path in (self.root / "keys.json.age", self.root / "index.json"):
            self.assertNotIn(note.encode(), path.read_bytes())

    def in_terminal(self, args, answer=None, env=None):
        """Run elbab on a pseudo-terminal, as a person would; returns (exit code, screen bytes)."""
        import fcntl
        import pty
        import select
        import termios
        master, slave = pty.openpty()

        def terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        proc = subprocess.Popen([sys.executable, "-I", str(ELBAB), *args], stdin=slave, stdout=slave,
                                stderr=slave, env=env or self.env, preexec_fn=terminal)
        os.close(slave)
        output = b""
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:  # keep draining so the child never blocks
                if answer is not None and b"): " in output:
                    os.write(master, answer + b"\n")
                    answer = None
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                elif proc.poll() is not None:
                    break
            return proc.wait(timeout=5), output
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)

    def person(self):
        """The test environment without the variables agent shells set."""
        return {k: v for k, v in self.env.items()
                if k not in ("CLAUDECODE", "AI_AGENT", "CODEX_THREAD_ID", "CODEX_SHELL", "CODEX_SANDBOX")}

    @unittest.skipIf(WINDOWS, "needs a POSIX terminal")
    def test_4e_terminal_prompts(self):
        for args, answer, echoed in ((["terminal-login"], b"visible-terminal-dummy", True),
                                     (["set-key", "terminal.key", "TOKEN"], b"visible-token-dummy", True),
                                     (["hidden-login", "--hidden"], b"hidden-terminal-dummy", False),
                                     (["set-key", "terminal.key", "OTHER", "--hidden"], b"hidden-token-dummy", False)):
            code, screen = self.in_terminal(args, answer, self.person())
            self.assertEqual(code, 0, screen.decode(errors="replace"))
            self.assertIn(b"hidden): " if not echoed else b"visible; not shell history): ", screen)
            self.assertEqual(answer in screen, echoed, args)
        self.assertEqual(self.e("get", "terminal-login", "PASSWORD").stdout, "visible-terminal-dummy")
        self.assertEqual(self.e("get", "hidden-login", "PASSWORD").stdout, "hidden-terminal-dummy")
        self.assertEqual(self.e("get", "terminal.key", "OTHER").stdout, "hidden-token-dummy")

    @unittest.skipIf(WINDOWS, "needs a POSIX terminal")
    def test_4f_terminal_shows_values(self):
        person = self.person()
        for args, secret in ((["show", "keys.json", "entries/demo.local"], FAKE_KEY.encode()),
                             (["csv", "query"], b"hunter2pass")):
            code, screen = self.in_terminal(args, env=person)
            self.assertEqual(code, 0, screen)
            self.assertIn(secret, screen)
            for env, extra in ((person, ["--mask"]), (dict(person, CLAUDECODE="1"), []),
                               (dict(person, CODEX_THREAD_ID="x"), []), (dict(person, AI_AGENT="1"), [])):
                code, screen = self.in_terminal(args + extra, env=env)
                self.assertEqual(code, 0, screen)
                self.assertNotIn(secret, screen)
                self.assertIn("\u2022\u2022\u2022\u2022".encode(), screen)
            self.assertNotIn(secret.decode(), self.e(*args, env=person).stdout)  # piped
            self.assertIn(secret.decode(), self.e(*args, "--reveal", env=person).stdout)
        self.assertNotEqual(self.e("show", "keys.json", "--mask", "--reveal", ok=False).returncode, 0)

    def test_5_rekey_and_verify_guards(self):
        second = self.base / "id2.txt"
        self.e("recipients", "add", keygen(second).strip(), "--name", "second")
        self.e("rekey")
        self.assertEqual(self.e("get", "demo.local", "DEMO_KEY", env=dict(self.env, ELBAB_IDENTITY_FILE=str(second))).stdout,
                         FAKE_KEY)
        (self.root / "index.json").write_text(json.dumps({"oops": FAKE_KEY}))
        self.assertNotEqual(self.e("verify", ok=False).returncode, 0)
        self.e("set-key", "demo.local", "DEMO_KEY", stdin=FAKE_KEY)  # rewrites a clean index
        self.e("verify")


if __name__ == "__main__":
    unittest.main(verbosity=1)
