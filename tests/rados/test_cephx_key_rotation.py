"""
CephX key rotation (aes -> aes256k) validation.

Automates the "CephX Key Rotation - Internal QE Runbook" (IBM "Rotating CephX keys"
procedure plus the deviations found on the 7.1 -> 8.1z9 413 run).

Workflow:
    1. Confirm the cluster is CephX-capable (no upgrade in progress, aes256k allowed).
    2. Set auth_preferred_cipher to aes256k.
    3. Identify leftover insecure client / service keys from `ceph health detail`.
    4. Rotate client.admin with a backup credential:
        - create + verify client.admin-backup
        - rotate client.admin
        - export the new key via the backup, validate it and only then replace the
          on-disk keyring (never write a possibly failed command onto the live keyring)
        - distribute the keyring to admin / client nodes and verify
        - remove the backup only after the new keyring is confirmed working
    5. Rotate the remaining client entities (reconfigure cephadm managed ones, e.g. RGW).
    6. Rotate service keys (osd.*, mds.*, mgr.*) that did not auto rotate - one OSD first.
    7. Lock the old cipher (auth_allowed_ciphers, auth_service_cipher if required).
    8. Final checks: no insecure key warnings, all ciphers are aes256k, OSDs are up.

Optional services (NFS / SMB / rbd-mirror / RGW multisite) are not driven by this test;
their client.* entities are still rotated by step 5 when they are reported as insecure.

Config (all optional):
    config:
        cipher: aes256k            # target cipher (default aes256k)
        wait_timeout: 600          # seconds to wait for health / daemons to settle
"""

import re
import time
from json import loads

from ceph.ceph import CommandFailed
from utility.log import Log

log = Log(__name__)

ADMIN_KEYRING = "/etc/ceph/ceph.client.admin.keyring"
BACKUP_ENTITY = "client.admin-backup"
BACKUP_KEYRING = "/root/client.admin-backup.keyring"
INSECURE_ENTITY_RE = re.compile(r"entity\s+(\S+)\s+using insecure key type")
CLIENT_WARN = "AUTH_INSECURE_CLIENT_KEY_TYPE"
SERVICE_WARN = "AUTH_INSECURE_SERVICE_KEY_TYPE"
RECONFIG_TYPES = ("osd", "mds", "mgr", "rgw")


class CephxRotation:
    """Helper that runs ceph commands through cephadm shell on the installer node."""

    def __init__(self, ceph_cluster, cipher="aes256k", wait_timeout=600):
        self.cluster = ceph_cluster
        self.installer = ceph_cluster.get_nodes(role="installer")[0]
        self.cipher = cipher
        self.wait_timeout = wait_timeout
        # (entity name, host keyring path) once client.admin has been rotated
        self.identity = None

    # ------------------------------------------------------------------ helpers
    def ceph(self, args, as_json=False, check=True, timeout=300):
        """Run `ceph <args>` in a cephadm shell and return stdout (or parsed JSON)."""
        if self.identity:
            name, keyring = self.identity
            base = (
                f"cephadm shell --mount {keyring} -- ceph -n {name} "
                f"-k /mnt/{keyring.split('/')[-1]}"
            )
        else:
            base = "cephadm shell -- ceph"
        cmd = f"{base} {args}" + (" -f json" if as_json else "")
        out, err, rc, _ = self.installer.exec_command(
            sudo=True, cmd=cmd, check_ec=False, verbose=True, timeout=timeout
        )
        if check and rc != 0:
            raise CommandFailed(f"{cmd} returned {err} and code {rc}")
        if not as_json:
            return out
        return loads(out) if out.strip() else {}

    def rotate(self, entity):
        """Rotate an entity's key. IBM documents --key-type, some builds need --key_type."""
        last_err = None
        for flag in ("--key-type", "--key_type"):
            try:
                self.ceph(f"auth rotate {entity} {flag} {self.cipher}")
                log.info(f"Rotated {entity} using {flag}")
                return
            except CommandFailed as err:
                log.warning(f"auth rotate {entity} {flag} failed: {err}")
                last_err = err
        raise last_err

    @staticmethod
    def write_remote(node, path, content):
        """Write content to a file on the node and restrict permissions."""
        remote = node.remote_file(sudo=True, file_name=path, file_mode="w")
        remote.write(content)
        remote.flush()
        remote.close()
        node.exec_command(sudo=True, cmd=f"chmod 600 {path}")

    @staticmethod
    def wait_for(condition, timeout, interval=20, msg=""):
        """Poll a condition (not in a tight loop - every cephadm shell call is slow)."""
        end = time.time() + timeout
        while time.time() < end:
            if condition():
                return True
            time.sleep(interval)
        log.error(f"Timed out waiting for: {msg}")
        return False

    # ------------------------------------------------------------ cluster state
    def cipher_settings(self):
        """Return {setting: [ciphers]} for every cipher line in `ceph mon dump`."""
        settings = {}
        for line in self.ceph("mon dump").splitlines():
            if "cipher" not in line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                settings[parts[0]] = [c.strip() for c in parts[1].split(",")]
        log.info(f"Cipher settings: {settings}")
        return settings

    def health_checks(self):
        return self.ceph("health detail", as_json=True).get("checks", {})

    def insecure_entities(self, warning):
        """Entities listed under the given AUTH_INSECURE_* health warning."""
        checks = self.health_checks()
        entities = []
        for item in checks.get(warning, {}).get("detail", []):
            entities.extend(INSECURE_ENTITY_RE.findall(item.get("message", "")))
        log.info(f"{warning}: {entities}")
        return entities

    def daemon_running(self, name):
        daemon_type, daemon_id = name.split(".", 1)
        ps = self.ceph(
            f"orch ps --daemon_type {daemon_type} --daemon_id {daemon_id} --refresh",
            as_json=True,
        )
        return bool(ps) and ps[0].get("status_desc") == "running"

    def down_osds(self):
        osds = self.ceph("osd dump", as_json=True).get("osds", [])
        return [o["osd"] for o in osds if not o.get("up")]

    # -------------------------------------------------------------------- steps
    def is_already_migrated(self):
        """True when ciphers are already locked to the target and no insecure keys remain.

        Fresh IBM/Tentacle deploys often ship already on aes256k-only. The aes->aes256k
        runbook steps do not apply in that state.
        """
        settings = self.cipher_settings()
        target = [self.cipher]
        checks = self.health_checks()
        insecure = [
            name
            for name in checks
            if name.startswith("AUTH_INSECURE")
            and name != "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE"
        ]
        return (
            settings.get("auth_allowed_ciphers") == target
            and settings.get("auth_preferred_cipher") == target
            and settings.get("auth_service_cipher") == target
            and not insecure
        )

    def step1_confirm_upgrade_complete(self):
        log.info("Step 1: confirm upgrade is complete and aes256k is allowed")
        log.info(self.ceph("version"))
        # Some builds print plain text ("There are no upgrades in progress currently.")
        # even with -f json, so only parse the output when it is JSON.
        status = self.ceph("orch upgrade status -f json").strip()
        log.info(f"Upgrade status: {status}")
        if status.startswith("{") and loads(status).get("in_progress"):
            raise AssertionError("Upgrade is still in progress")
        if not status.startswith("{") and "no upgrades in progress" not in status:
            raise AssertionError(f"Unexpected upgrade status output: {status}")
        if self.cipher not in self.cipher_settings().get("auth_allowed_ciphers", []):
            raise AssertionError(
                f"{self.cipher} absent from auth_allowed_ciphers - not a CephX capable build"
            )

    def step2_set_preferred_cipher(self):
        log.info("Step 2: set auth_preferred_cipher")
        self.ceph(f"mon set auth_preferred_cipher {self.cipher}")
        preferred = self.cipher_settings().get("auth_preferred_cipher")
        if preferred != [self.cipher]:
            raise AssertionError(f"auth_preferred_cipher is {preferred}")
        # aes must stay allowed until every client is rotated — but only when a
        # migration is still in progress. Clusters already locked to aes256k-only
        # (common on fresh 9.x deploys) are not "too early"; they are done.
        allowed = self.cipher_settings().get("auth_allowed_ciphers", [])
        if "aes" in allowed:
            return
        checks = self.health_checks()
        if CLIENT_WARN in checks or SERVICE_WARN in checks:
            raise AssertionError(
                "aes removed from auth_allowed_ciphers too early "
                "(insecure key warnings still present)"
            )
        if self.is_already_migrated():
            log.info(
                "aes absent from auth_allowed_ciphers and cluster is already fully "
                "on %s with no insecure keys — migration precondition already met",
                self.cipher,
            )
            return
        raise AssertionError(
            f"aes absent from auth_allowed_ciphers and cluster is not fully on {self.cipher}"
        )

    def step4_rotate_admin(self):
        log.info("Step 4: rotate client.admin with a backup credential")
        # 4a - create backup credential, store it on the installer host
        backup_key = self.ceph(f"auth get-or-create {BACKUP_ENTITY} mon 'allow *'")
        if not backup_key.startswith(f"[{BACKUP_ENTITY}]"):
            raise AssertionError(f"Unexpected backup keyring content: {backup_key}")
        self.write_remote(self.installer, BACKUP_KEYRING, backup_key)

        # 4b - verify backup works (STOP if it does not)
        self.identity = (BACKUP_ENTITY, BACKUP_KEYRING)
        self.ceph("auth ls")
        self.identity = None

        # 4c - rotate client.admin
        self.rotate("client.admin")

        # 4d - export the new key through the backup credential, validate, then replace.
        self.identity = (BACKUP_ENTITY, BACKUP_KEYRING)
        new_key = self.ceph("auth get client.admin")
        if not new_key.startswith("[client.admin]"):
            raise AssertionError(f"Exported admin key is invalid: {new_key}")
        self.write_remote(self.installer, ADMIN_KEYRING, new_key)

        # 4f - distribute to every admin / client node
        nodes = {}
        for role in ("_admin", "client"):
            for node in self.cluster.get_nodes(role=role):
                nodes[node.hostname] = node
        for hostname, node in nodes.items():
            _, _, rc, _ = node.exec_command(
                sudo=True, cmd="test -d /etc/ceph", check_ec=False, verbose=True
            )
            if rc != 0:
                log.info(f"Skipping {hostname}: /etc/ceph not present")
                continue
            self.write_remote(node, ADMIN_KEYRING, new_key)
            log.info(f"Admin keyring updated on {hostname}")

        # 4e - verify with the NEW admin keyring
        self.identity = ("client.admin", ADMIN_KEYRING)
        self.ceph("auth ls")
        self.ceph("-s")

        # 4g - the new keyring is confirmed working, remove the backup
        self.ceph(f"auth rm {BACKUP_ENTITY}")
        self.installer.exec_command(sudo=True, cmd=f"rm -f {BACKUP_KEYRING}")

    def reconfig_and_verify(self, entity):
        """Reconfigure the cephadm daemon behind an entity; redeploy if it does not recover."""
        daemon = (
            entity.replace("client.", "", 1) if entity.startswith("client.") else entity
        )
        if daemon.split(".", 1)[0] not in RECONFIG_TYPES:
            return
        self.ceph(f"orch daemon reconfig {daemon}")
        if self.wait_for(
            lambda: self.daemon_running(daemon), 180, msg=f"{daemon} running"
        ):
            return
        log.warning(f"{daemon} not running after reconfig, redeploying")
        self.ceph(f"orch daemon redeploy {daemon}")
        if not self.wait_for(
            lambda: self.daemon_running(daemon),
            self.wait_timeout,
            msg=f"{daemon} running",
        ):
            raise AssertionError(f"{daemon} is not running after rotation")

    def step5_rotate_clients(self):
        log.info("Step 5: rotate remaining client entities")
        for entity in self.insecure_entities(CLIENT_WARN):
            if entity in ("client.admin", BACKUP_ENTITY):
                continue
            self.rotate(entity)
            self.reconfig_and_verify(entity)
        if not self.wait_for(
            lambda: CLIENT_WARN not in self.health_checks(),
            self.wait_timeout,
            msg=f"{CLIENT_WARN} to clear",
        ):
            raise AssertionError(f"{CLIENT_WARN} still reported after rotation")

    def step6_rotate_services(self):
        """Service keys are expected to auto rotate on upgrade; rotate the ones that did not."""
        log.info("Step 6: rotate service keys that did not auto rotate")
        entities = self.insecure_entities(SERVICE_WARN)
        if not entities:
            log.info("No insecure service keys reported")
            return
        # Rotate one OSD first, confirm it stays up and leaves the insecure list
        entities.sort(key=lambda e: (not e.startswith("osd."), e))
        for position, entity in enumerate(entities):
            self.rotate(entity)
            self.reconfig_and_verify(entity)
            if position == 0 and entity.startswith("osd."):
                if entity in self.insecure_entities(SERVICE_WARN):
                    raise AssertionError(f"{entity} still insecure after rotation")
        if not self.wait_for(
            lambda: SERVICE_WARN not in self.health_checks(),
            self.wait_timeout,
            msg=f"{SERVICE_WARN} to clear",
        ):
            raise AssertionError(f"{SERVICE_WARN} still reported after rotation")

    def step7_lock_cipher(self):
        log.info("Step 7: disable the old cipher")
        checks = self.health_checks()
        if CLIENT_WARN in checks or SERVICE_WARN in checks:
            raise AssertionError(
                "Insecure client/service keys remain - refusing to lock the old cipher"
            )
        self.ceph(f"mon set auth_allowed_ciphers {self.cipher}")
        settings = self.cipher_settings()
        # IBM text only sets auth_allowed_ciphers; auth_service_cipher was also required on 413
        if settings.get("auth_service_cipher") != [self.cipher]:
            log.info("auth_service_cipher not updated, setting it explicitly")
            self.ceph(f"mon set auth_service_cipher {self.cipher}")

    def recover_osds(self):
        """Side effect seen after locking: OSDs go down / cephadm status unknown."""
        down = self.down_osds()
        for osd in down:
            log.warning(f"osd.{osd} is down after locking ciphers, restart + redeploy")
            self.ceph(f"orch daemon restart osd.{osd}", check=False)
            self.ceph(f"orch daemon redeploy osd.{osd}", check=False)
        if not self.wait_for(
            lambda: not self.down_osds(), self.wait_timeout, msg="all OSDs up"
        ):
            raise AssertionError(f"OSDs still down: {self.down_osds()}")

    def step8_final_checks(self):
        log.info("Step 8: final checks")
        self.recover_osds()
        checks = self.health_checks()
        log.info(f"Final health checks: {list(checks)}")
        # AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE is a known 413 finding that may clear on
        # its own; do not fail the run for it and do not re-rotate to chase it.
        insecure = [
            c
            for c in checks
            if c.startswith("AUTH_INSECURE")
            and c != "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE"
        ]
        if insecure:
            raise AssertionError(f"Insecure key warnings remain: {insecure}")
        if "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE" in checks:
            log.warning(
                "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE still reported (known finding)"
            )
        settings = self.cipher_settings()
        for name in (
            "auth_allowed_ciphers",
            "auth_preferred_cipher",
            "auth_service_cipher",
        ):
            if settings.get(name) != [self.cipher]:
                raise AssertionError(
                    f"{name} is {settings.get(name)}, expected {self.cipher}"
                )
        if "RECENT_CRASH" in checks:
            raise AssertionError("Daemon crash reported after key rotation")


def run(ceph_cluster, **kw):
    """Validate the CephX aes -> aes256k key rotation workflow.

    Returns:
        0 -> Pass, 1 -> Fail
    """
    log.info(run.__doc__)
    config = kw.get("config", {})
    rotation = CephxRotation(
        ceph_cluster,
        cipher=config.get("cipher", "aes256k"),
        wait_timeout=config.get("wait_timeout", 600),
    )
    try:
        rotation.step1_confirm_upgrade_complete()
        if rotation.is_already_migrated():
            log.info(
                "Cluster already fully on %s with no insecure key warnings; "
                "skipping aes->%s rotation steps and verifying final state",
                rotation.cipher,
                rotation.cipher,
            )
            rotation.step8_final_checks()
            log.info("CephX key rotation completed successfully (already migrated)")
            return 0
        rotation.step2_set_preferred_cipher()
        log.info("Step 3: leftover keys before rotation")
        rotation.insecure_entities(CLIENT_WARN)
        rotation.insecure_entities(SERVICE_WARN)
        rotation.step4_rotate_admin()
        rotation.step5_rotate_clients()
        rotation.step6_rotate_services()
        rotation.step7_lock_cipher()
        rotation.step8_final_checks()
    except Exception as err:
        log.error(f"CephX key rotation failed: {err}")
        log.exception(err)
        log.error(
            f"If client.admin was rotated, {BACKUP_ENTITY} and {BACKUP_KEYRING} are retained "
            "for recovery - re-export client.admin with it, validate, then copy to /etc/ceph."
        )
        return 1
    log.info("CephX key rotation completed successfully")
    return 0
