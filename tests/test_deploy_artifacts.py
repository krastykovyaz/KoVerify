"""The deployment files: scripts parse, and the dangerous behaviours stay fixed."""
import glob
import re
import subprocess

import pytest

SCRIPTS = sorted(glob.glob("deploy/*.sh"))
DEPLOY = open("deploy/deploy.sh").read()


@pytest.mark.parametrize("script", SCRIPTS)
def test_script_parses(script):
    assert subprocess.run(["bash", "-n", script], capture_output=True).returncode == 0


@pytest.mark.parametrize("script", SCRIPTS)
def test_script_is_executable_and_strict(script):
    import os
    assert os.access(script, os.X_OK), f"{script} is not executable"
    assert "set -euo pipefail" in open(script).read() or "set -uo pipefail" in open(script).read()


def test_rollback_does_not_restore_the_database_by_default():
    """Restoring the snapshot discarded every enrolment and revocation since it
    was taken and silently un-revoked people."""
    body = DEPLOY[DEPLOY.index("rollback() {"):DEPLOY.index('if [ "$DO_ROLLBACK" = 1 ]')]
    restore = re.search(r'if \[ "\$WITH_DB" = 1 \][^\n]*\n[^\n]*\n[^\n]*cp -a "\$backup/db.sqlite"', body)
    assert restore, "the database restore must be gated behind --with-db"
    assert "--with-db" in DEPLOY.split("set -euo")[0]


def test_deploy_backups_do_not_copy_the_ca_private_key():
    backup_line = next(l for l in DEPLOY.splitlines() if 'rsync -a --exclude venv/' in l and "BACKUP/code" in l)
    assert "--exclude ca/" in backup_line


def test_deploy_backs_up_and_can_restore_the_nginx_files():
    assert 'cp -a "$NGINX_SITE" "$BACKUP/nginx/verifier"' in DEPLOY
    assert "restore_nginx_from" in DEPLOY
    invalid = DEPLOY[DEPLOY.index("if ! nginx -t; then"):]
    assert invalid.index("restore_nginx_from") < invalid.index("nothing was restarted")


def test_deploy_refuses_to_overwrite_a_site_file_with_different_listeners():
    assert "NOT overwriting it" in DEPLOY and "--force-nginx" in DEPLOY


def test_deploy_prunes_old_backups():
    assert "KEEP_BACKUPS" in DEPLOY and "xargs -r rm -rf" in DEPLOY


def test_deploy_does_not_open_the_production_database_as_root():
    check = DEPLOY[DEPLOY.index("checking the configuration"):DEPLOY.index("# ── Backup")]
    assert "create_app" not in check and "init_db" not in check


def test_repo_nginx_site_matches_the_stream_router_topology():
    """Public 443 belongs to the SNI router, which forwards to 7443 with PROXY
    protocol. A site file listening on 443 would fail at reload."""
    conf = open("deploy/nginx-verifier.conf").read()
    listens = re.findall(r"^\s*listen\s+([^;]+);", conf, re.M)
    assert "7443 ssl http2 proxy_protocol" in listens
    assert not any(l.startswith("443") or l.startswith("[::]:443") for l in listens)
    assert "real_ip_header proxy_protocol" in conf and "set_real_ip_from 127.0.0.1" in conf


def test_service_unit_is_sandboxed_and_cannot_rewrite_its_code():
    unit = open("deploy/verifier.service").read()
    assert "ReadOnlyPaths=/var/www/verifier/verifier" in unit
    assert "/var/www/verifier/venv" in unit.split("ReadOnlyPaths=")[1].splitlines()[0]
    assert "--no-control-socket" in unit
    assert "User=www-data" in unit and "NoNewPrivileges=true" in unit


@pytest.mark.parametrize("name", ["verifier-check", "verifier-backup"])
def test_timer_units_pair_up(name):
    assert "Type=oneshot" in open(f"deploy/{name}.service").read()
    assert "Persistent=true" in open(f"deploy/{name}.timer").read()
    assert f"{name}.timer" in DEPLOY and f"{name}.service" in DEPLOY


def test_health_check_validates_certificates_and_never_uses_insecure_curl():
    check = open("deploy/check-health.sh").read()
    assert "-verify_return_error" in check
    code = "\n".join(l for l in check.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"\bcurl\b[^\n]*\s-k\b|\bcurl\b[^\n]*--insecure", code)


def test_requirements_are_pinned():
    for line in open("requirements.txt"):
        line = line.strip()
        if line and not line.startswith("#"):
            assert "==" in line, f"{line} is not pinned"


def test_key_handling_scripts_refuse_unsafe_states():
    purge = open("deploy/purge-key-copies.sh").read()
    assert "encrypt-ca-key.sh first" in purge and "backup.sh first" in purge
    assert '"--yes"' in purge          # dry run by default
    encrypt = open("deploy/encrypt-ca-key.sh").read()
    assert "trap 'restore' ERR" in encrypt and "shred -u" in encrypt
