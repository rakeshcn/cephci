"""
IBMCEPH-17981 / Polarion CEPH-83632955 / tracker #79962

Malformed subvolume names ('.', '..', '', '/') path-join onto the group or
/volumes. SubvolumeV2.open() then mark_subvolume(), stamping
ceph.dir.subvolume=1 on the parent. Later valid creates fail with:
    EINVAL: invalid value specified for ceph.dir.subvolume

Expected FAIL on unfixed 9.1.2; PASS after PR 71507.
"""

import random
import shlex
import string
import traceback

from tests.cephfs.cephfs_utilsV1 import FsUtils
from utility.log import Log

log = Log(__name__)

NESTED_EINVAL = "invalid value specified for ceph.dir.subvolume"
INVALID_NAMES = [".", "..", "", "/", "../x", "./x"]
VALID_DOT_NAME_PREFIX = "sub.vol"

SUBCOMMANDS = [
    ("info", ""),
    ("getpath", ""),
    ("rm", ""),
    ("resize", " inf"),
    ("metadata set", " csi.storage.k8s.io/pv/name dummy"),
    ("snapshot create", " snap_ibmceph17981"),
    ("snapshot rm", " snap_ibmceph17981"),
    ("authorize", " client.ibmceph17981"),
    ("create", ""),
]


def _rand(n=8):
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(n)
    )


def _run(client, cmd, check_ec=False):
    """Return (stdout, stderr, exit_code). Never raises on non-zero."""
    result = client.exec_command(sudo=True, cmd=cmd, check_ec=check_ec, verbose=True)
    if isinstance(result, tuple) and len(result) >= 3:
        out, err, rc = result[0], result[1], result[2]
    else:
        out, err = result if isinstance(result, tuple) else (result, "")
        rc = getattr(client, "exit_status", None)
    return out or "", err or "", rc


def _combined(out, err):
    return f"{out}\n{err}"


def _group_gone(text):
    return "does not exist" in text and "subvolume group" in text


def _argparse_rejected(text):
    return "invalid chars" in text or "Error EINVAL: invalid command" in text


def _quote_cmd(fs_name, verb, name, group, extra=""):
    return (
        f"ceph fs subvolume {verb} {shlex.quote(fs_name)} {shlex.quote(name)}"
        f"{extra} --group_name {shlex.quote(group)}"
    )


def _get_xattr(client, path):
    out, err, rc = _run(
        client,
        f"getfattr --absolute-names --only-values -n ceph.dir.subvolume "
        f"{shlex.quote(path)}",
    )
    val = (out or "").strip()
    text = _combined(out, err)
    if rc not in (0, None) or "No such attribute" in text or "No such file" in text:
        return "UNSET"
    return val or "UNSET"


def _clear_parent_xattr(client, path):
    out, err, rc = _run(
        client, f"setfattr -n ceph.dir.subvolume -v 0 {shlex.quote(path)}"
    )
    log.info("recover setfattr %s rc=%s out=%s err=%s", path, rc, out, err)


def _probe_create(client, fs_name, group, probe_name):
    """Try a valid create. Returns (poisoned, group_missing, rc, text)."""
    out, err, rc = _run(
        client,
        f"ceph fs subvolume create {shlex.quote(fs_name)} {shlex.quote(probe_name)}"
        f" --group_name {shlex.quote(group)}",
    )
    text = _combined(out, err)
    poisoned = NESTED_EINVAL in text
    missing = _group_gone(text)
    if rc in (0, None) and not poisoned:
        _run(
            client,
            f"ceph fs subvolume rm {shlex.quote(fs_name)} {shlex.quote(probe_name)}"
            f" --group_name {shlex.quote(group)} --force",
        )
    return poisoned, missing, rc, text


def _recover_parents(client, mnt, group):
    """Clear xattr only on /, /volumes, /volumes/<group>."""
    for rel in ("/", "volumes", f"volumes/{group}"):
        path = mnt.rstrip("/") + ("" if rel == "/" else "/" + rel)
        log.info("xattr %s = %s", path, _get_xattr(client, path))
        _clear_parent_xattr(client, path)


def _ensure_group(fs_util, client, fs_name, group):
    """Recreate the group if a pre-fix `rm .` / `rm ''` removed it."""
    _, err, rc = _run(
        client,
        f"ceph fs subvolumegroup info {shlex.quote(fs_name)} {shlex.quote(group)}",
    )
    if rc not in (0, None):
        log.warning("group %s missing (rc=%s %s); recreating", group, rc, err)
        fs_util.create_subvolumegroup(
            client, fs_name, group, validate=False, check_ec=False
        )


def _stabilize(fs_util, client, fs_name, group, mnt, recover=False):
    if recover:
        _recover_parents(client, mnt, group)
    _ensure_group(fs_util, client, fs_name, group)


def _log_banner(title):
    bar = "=" * 72
    log.info(bar)
    log.info(title)
    log.info(bar)


def _log_test_start(tc_id, title, doing, expect):
    bar = "-" * 72
    log.info(bar)
    log.info("TEST %s : %s", tc_id, title)
    log.info("  Doing  : %s", doing)
    log.info("  Expect : %s", expect)
    log.info(bar)


def _log_test_result(tc_id, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    suffix = f" — {detail}" if detail else ""
    log.info("RESULT %s : %s%s", tc_id, status, suffix)


def _name_label(name):
    return "empty-string" if name == "" else name


def run(ceph_cluster, **kw):
    """
    1. Dedicated subvolumegroup (not production 'csi').
    2. Kernel-mount FS root for xattr recover.
    3. Invalid-name x subcommand matrix: reject name, do not poison parent.
    4. Customer trigger: metadata set with empty subvolume name.
    5. Adjacent: 'sub.vol.<rand>' must still create.
    6. Recover parents must not break a real subvolume.
    """
    fs_util = None
    client1 = None
    fs_name = None
    group = f"ibmceph17981_{_rand(4)}"
    mnt = None
    failures = []
    real_subvol = f"real_{_rand()}"
    results = []

    def _dump_summary():
        nfail = sum(1 for _, passed in results if not passed)
        _log_banner(f"SUMMARY IBMCEPH-17981 : {len(results)} tests ran, {nfail} failed")
        for tc_id, passed in results:
            log.info("  %s : %s", tc_id, "PASS" if passed else "FAIL")
        for item in failures:
            log.error("FAIL: %s", item)

    try:
        _log_banner(
            "IBMCEPH-17981 : invalid subvolume name must not stamp parent "
            "ceph.dir.subvolume"
        )
        log.info(
            "Plan: %d matrix cells (Phase A), empty metadata set (B), "
            "sub.vol adjacent (C), recover-safety (D).",
            len(INVALID_NAMES) * len(SUBCOMMANDS),
        )
        test_data = kw.get("test_data")
        fs_util = FsUtils(ceph_cluster, test_data=test_data)
        erasure = (
            FsUtils.get_custom_config_value(test_data, "erasure")
            if test_data
            else False
        )
        client1 = ceph_cluster.get_ceph_objects("client")[0]
        fs_name = "cephfs" if not erasure else "cephfs-ec"
        if not fs_util.get_fs_info(client1, fs_name):
            log.info("Step 0: filesystem %s missing; creating", fs_name)
            fs_util.create_fs(client1, fs_name)
        fs_util.auth_list([client1])

        log.info("Step 1: create dedicated subvolumegroup %s", group)
        fs_util.create_subvolumegroup(client1, fs_name, group)

        mnt = f"/mnt/cephfs_ibmceph17981_{_rand()}"
        log.info("Step 2: kernel-mount FS root at %s", mnt)
        fs_util.kernel_mount(
            [client1],
            mnt,
            ",".join(fs_util.get_mon_node_ips()),
            extra_params=f",fs={fs_name}",
        )
        log.info(
            "Step 3: baseline xattr group=%s volumes=%s",
            _get_xattr(client1, f"{mnt}/volumes/{group}"),
            _get_xattr(client1, f"{mnt}/volumes"),
        )

        matrix_total = len(INVALID_NAMES) * len(SUBCOMMANDS)
        _log_banner(f"Phase A : invalid-name matrix ({matrix_total} cells)")
        cell = 0
        for name in INVALID_NAMES:
            nlabel = _name_label(name)
            log.info("---- name=%r (%s) ----", name, nlabel)
            for verb, extra in SUBCOMMANDS:
                cell += 1
                tc_id = f"A.{cell:02d}/{matrix_total}"
                _ensure_group(fs_util, client1, fs_name, group)

                label = f"{verb!r} name={name!r}"
                cmd = _quote_cmd(fs_name, verb, name, group, extra)
                _log_test_start(
                    tc_id,
                    f"subvolume {verb} name={nlabel!r}",
                    f"run `{cmd}` then probe a valid subvolume create",
                    "reject invalid name; follow-up create must not nested-EINVAL; "
                    "group must still exist",
                )
                out, err, rc = _run(client1, cmd)
                text = _combined(out, err)
                log.info("  Command rc=%s text=%s", rc, text.strip()[:300])

                argparse_ok = _argparse_rejected(text)
                cell_fails = []

                if (
                    name in (".", "..", "")
                    and verb == "info"
                    and rc == 0
                    and not argparse_ok
                ):
                    cell_fails.append(
                        f"{label}: command succeeded (rc=0); expected EINVAL"
                    )

                if verb == "rm" and name in (".", "..", "", "/") and not argparse_ok:
                    if rc == 0:
                        cell_fails.append(
                            f"{label}: rm of invalid name succeeded "
                            "(may have deleted the group/parent)"
                        )
                    elif "EBUSY" in text or "error in rename" in text:
                        cell_fails.append(
                            f"{label}: rm attempted to rename parent: "
                            f"{text.strip()[:160]}"
                        )

                probe = f"probe_{_rand()}"
                log.info("  Probe: create valid subvolume %s", probe)
                poisoned, missing, prc, ptext = _probe_create(
                    client1, fs_name, group, probe
                )
                log.info(
                    "  Probe result: poisoned=%s group_missing=%s rc=%s text=%s",
                    poisoned,
                    missing,
                    prc,
                    ptext.strip()[:200],
                )
                if poisoned:
                    cell_fails.append(
                        f"{label}: parent poisoned — subsequent create rc={prc} "
                        f"text={ptext.strip()[:200]}"
                    )
                    log.info("  Recover: clear parent xattr and recreate group")
                    _stabilize(fs_util, client1, fs_name, group, mnt, recover=True)
                    poisoned2, _, _, ptext2 = _probe_create(
                        client1, fs_name, group, f"probe2_{_rand()}"
                    )
                    if poisoned2:
                        cell_fails.append(
                            f"{label}: recover failed, still nested EINVAL: "
                            f"{ptext2[:200]}"
                        )
                        failures.extend(cell_fails)
                        results.append((tc_id, False))
                        _log_test_result(tc_id, False, "; ".join(cell_fails))
                        _dump_summary()
                        return 1
                elif missing:
                    cell_fails.append(
                        f"{label}: group deleted after command "
                        f"(probe rc={prc} {ptext.strip()[:160]})"
                    )
                    log.info("  Recover: recreate group and clear parent xattr")
                    _stabilize(fs_util, client1, fs_name, group, mnt, recover=True)
                elif argparse_ok:
                    log.info("  Note: argparse rejected name with '/' (expected)")

                passed = not cell_fails
                results.append((tc_id, passed))
                if cell_fails:
                    failures.extend(cell_fails)
                _log_test_result(
                    tc_id,
                    passed,
                    "; ".join(cell_fails) if cell_fails else "no parent poison",
                )

        _stabilize(fs_util, client1, fs_name, group, mnt, recover=True)

        _log_banner("Phase B : customer CSI trigger — empty metadata set")
        tc_id = "B.01"
        cmd = (
            f"ceph fs subvolume metadata set {shlex.quote(fs_name)} '' "
            f"csi.storage.k8s.io/pv/name dummy --group_name {shlex.quote(group)}"
        )
        _log_test_start(
            tc_id,
            "customer-like metadata set with empty subvolume name",
            f"run `{cmd}` then probe a valid create",
            "must reject empty name; must not stamp or delete the group",
        )
        out, err, rc = _run(client1, cmd)
        log.info("  Command rc=%s text=%s", rc, _combined(out, err).strip()[:300])
        b_fails = []
        if rc == 0:
            b_fails.append("customer metadata set '' succeeded; expected reject")
        poisoned, missing, prc, ptext = _probe_create(
            client1, fs_name, group, f"probe_empty_{_rand()}"
        )
        log.info(
            "  Probe result: poisoned=%s group_missing=%s rc=%s text=%s",
            poisoned,
            missing,
            prc,
            ptext.strip()[:200],
        )
        if poisoned:
            b_fails.append(
                f"customer metadata set '': parent poisoned rc={prc} {ptext[:200]}"
            )
        elif missing:
            b_fails.append(
                f"customer metadata set '': group deleted rc={prc} {ptext[:160]}"
            )
        results.append((tc_id, not b_fails))
        if b_fails:
            failures.extend(b_fails)
        _log_test_result(
            tc_id, not b_fails, "; ".join(b_fails) if b_fails else "rejected empty name"
        )
        _stabilize(fs_util, client1, fs_name, group, mnt, recover=True)

        _log_banner("Phase C : adjacent valid name — 'sub.vol.*' must create")
        tc_id = "C.01"
        valid_dot = f"{VALID_DOT_NAME_PREFIX}_{_rand(4)}"
        _log_test_start(
            tc_id,
            f"create valid name {valid_dot}",
            "create + info a name with a dot in the middle",
            "create and info must succeed",
        )
        out, err, rc = _run(
            client1,
            f"ceph fs subvolume create {shlex.quote(fs_name)} {shlex.quote(valid_dot)}"
            f" --group_name {shlex.quote(group)}",
        )
        log.info("  Create rc=%s text=%s", rc, _combined(out, err).strip()[:200])
        c_fails = []
        if rc not in (0, None) or NESTED_EINVAL in _combined(out, err):
            c_fails.append(
                f"valid name {valid_dot} failed to create rc={rc} "
                f"{_combined(out, err)[:200]}"
            )
        else:
            log.info("  Info on %s after create", valid_dot)
            info_out, info_err, info_rc = _run(
                client1,
                f"ceph fs subvolume info {shlex.quote(fs_name)} "
                f"{shlex.quote(valid_dot)} --group_name {shlex.quote(group)}",
            )
            log.info(
                "  Info rc=%s text=%s",
                info_rc,
                _combined(info_out, info_err).strip()[:200],
            )
            if info_rc not in (0, None):
                c_fails.append(
                    f"valid name {valid_dot} created but info failed: "
                    f"{_combined(info_out, info_err)[:200]}"
                )
            _run(
                client1,
                f"ceph fs subvolume rm {shlex.quote(fs_name)} {shlex.quote(valid_dot)}"
                f" --group_name {shlex.quote(group)} --force",
            )
        results.append((tc_id, not c_fails))
        if c_fails:
            failures.extend(c_fails)
        _log_test_result(
            tc_id, not c_fails, "; ".join(c_fails) if c_fails else f"{valid_dot} ok"
        )

        _log_banner("Phase D : recover must not break a real subvolume")
        tc_id = "D.01"
        _log_test_start(
            tc_id,
            f"recover parents with real subvolume {real_subvol} present",
            "create a real subvol, clear xattr on /, /volumes, /volumes/<group>, "
            "then info the real subvol",
            "real subvolume keeps ceph.dir.subvolume=1 and remains usable",
        )
        _ensure_group(fs_util, client1, fs_name, group)
        create_out, create_err, create_rc = _run(
            client1,
            f"ceph fs subvolume create {shlex.quote(fs_name)} "
            f"{shlex.quote(real_subvol)} --group_name {shlex.quote(group)}",
        )
        log.info(
            "  Create rc=%s text=%s",
            create_rc,
            _combined(create_out, create_err).strip()[:200],
        )
        d_fails = []
        if create_rc not in (0, None) or NESTED_EINVAL in _combined(
            create_out, create_err
        ):
            d_fails.append(
                f"real subvolume create failed rc={create_rc} "
                f"{_combined(create_out, create_err)[:200]}"
            )
        else:
            subvol_root = f"{mnt.rstrip('/')}/volumes/{group}/{real_subvol}"
            before = _get_xattr(client1, subvol_root)
            log.info("  wrapper xattr before recover: %s path=%s", before, subvol_root)
            _recover_parents(client1, mnt, group)
            after = _get_xattr(client1, subvol_root)
            log.info("  wrapper xattr after recover: before=%s after=%s", before, after)
            info_out, info_err, info_rc = _run(
                client1,
                f"ceph fs subvolume info {shlex.quote(fs_name)} "
                f"{shlex.quote(real_subvol)} --group_name {shlex.quote(group)}",
            )
            log.info(
                "  Info rc=%s text=%s",
                info_rc,
                _combined(info_out, info_err).strip()[:200],
            )
            if info_rc not in (0, None):
                d_fails.append(
                    f"real subvolume unusable after parent recover: "
                    f"{_combined(info_out, info_err)[:200]}"
                )
            if before == "1" and after == "0":
                d_fails.append(f"recovery incorrectly cleared xattr on {subvol_root}")
        results.append((tc_id, not d_fails))
        if d_fails:
            failures.extend(d_fails)
        _log_test_result(
            tc_id, not d_fails, "; ".join(d_fails) if d_fails else "real subvol intact"
        )

        _dump_summary()
        if failures:
            return 1
        log.info("IBMCEPH-17981 negative coverage passed")
        return 0

    except Exception as e:
        log.error(e)
        log.error(traceback.format_exc())
        _dump_summary()
        return 1
    finally:
        log.info("Cleanup: recover parent xattr, rm real subvol, rm group, unmount")
        try:
            if client1 and mnt and group:
                _recover_parents(client1, mnt, group)
        except Exception as e:
            log.warning("parent recover in finally: %s", e)
        try:
            if client1 and fs_name:
                _run(
                    client1,
                    f"ceph fs subvolume rm {shlex.quote(fs_name)} "
                    f"{shlex.quote(real_subvol)} --group_name {shlex.quote(group)} "
                    "--force",
                )
        except Exception:
            pass
        try:
            if fs_util and client1 and fs_name:
                fs_util.remove_subvolumegroup(
                    client1, fs_name, group, validate=False, check_ec=False, force=True
                )
        except Exception as e:
            log.warning("group cleanup: %s", e)
        try:
            if client1 and mnt:
                # FS-root mount: umount -l then rmdir only (never rm -rf).
                client1.exec_command(
                    sudo=True,
                    cmd=f"umount -l {shlex.quote(mnt)}",
                    check_ec=False,
                    timeout=600,
                )
                client1.exec_command(
                    sudo=True,
                    cmd=f"rmdir {shlex.quote(mnt)}",
                    check_ec=False,
                    timeout=600,
                )
        except Exception as e:
            log.warning("unmount cleanup: %s", e)
