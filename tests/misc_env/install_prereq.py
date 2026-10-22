import base64
import json
import re
import time

from packaging.version import InvalidVersion, Version

from ceph.parallel import parallel
from ceph.utils import config_ntp, enable_coredump, update_ca_cert
from ceph.waiter import WaitUntil
from cli.exceptions import ConfigError
from cli.utilities.packages import Package
from cli.utilities.packages import SubscriptionManager as sm
from cli.utilities.packages import SubscriptionManagerError
from cli.utilities.utils import (
    enable_fips_mode,
    get_service_state,
    is_fips_mode_enabled,
    os_major_version,
    reboot_node,
    set_service_state,
)
from utility.log import Log
from utility.utils import (
    get_cephci_config,
    is_unsecured_registry,
    parse_custom_config_list,
    resolve_registry_login,
)

log = Log(__name__)


class ConfigNotFoundError(Exception):
    pass


class RepoConfigError(Exception):
    pass


class FIPSConfigError(Exception):
    pass


rpm_packages = {
    "7": [
        "wget",
        "git-core",
        "python-virtualenv",
        "python-nose",
        "ntp",
        "python2-pip",
        "chrony",
    ],
    "all": [
        "wget",
        "git-core",
        "python3-devel",
        "python3-pip",
        "chrony",
        "yum-utils",
        "net-tools",
        "lvm2",
        "podman",
        "rpcbind",
        "net-snmp-utils",
        "net-snmp",
        "kernel-modules-extra",
        "iproute-tc",
        "firewalld",
    ],
}
deb_packages = ["wget", "git-core", "python-virtualenv", "lsb-release", "ntp"]
deb_all_packages = " ".join(deb_packages)


def run(**kw):
    log.info("Running test")
    ceph_nodes = kw.get("ceph_nodes")

    # skip subscription manager if testing beta RHEL
    config = kw.get("config")
    skip_subscription = config.get("skip_subscription", False)
    enable_eus = config.get("enable_eus", False)
    repo = config.get("add-repo", False)
    skip_enabling_rhel_rpms = config.get("skip_enabling_rhel_rpms", False)
    fips_mode = config.get("enable_fips_mode", False)
    firewall = config.get("enable_firewall", False)

    cloud_type = config.get("cloud-type", "openstack")

    # Extract test_data from kw
    test_data = kw.get("test_data", None)

    # Validate podman auth file once before parallel execution
    podman_auth_file = config.get("podman_auth_file")
    if podman_auth_file:
        from utility.registry_auth import validate_podman_auth_file

        try:
            validate_podman_auth_file(podman_auth_file)
            log.info(f"Successfully validated podman auth file: {podman_auth_file}")
        except Exception as e:
            log.error(f"Failed to validate podman auth file: {e}")
            raise

    with parallel() as p:
        for ceph in ceph_nodes:
            p.spawn(
                install_prereq,
                ceph,
                test_data,
                skip_subscription,
                repo,
                enable_eus,
                skip_enabling_rhel_rpms,
                cloud_type,
                fips_mode,
                firewall,
                config,
            )
            time.sleep(20)

    # TODO: remove once BaseOS openssl provides OPENSSL_3.4.0 / >= 3.5.1
    # on all supported RHEL 9 minors (upstream tentacle + IBM client installs).
    # Applied to every RHEL 9 node, not only client-only nodes: suites such as RGW
    # install ceph-common on server nodes as well. The workaround is a no-op when
    # openssl is already >= OPENSSL_MIN_VERSION.
    # https://tracker.ceph.com/issues/71250
    base_url = config.get("base_url")
    with parallel() as p:
        for ceph in ceph_nodes:
            try:
                if int(os_major_version(ceph)) != 9:
                    continue
            except Exception:
                continue
            p.spawn(workaround_openssl_issue, ceph, base_url=base_url)
    return 0


def install_prereq(
    ceph,
    test_data=None,  # Default value for test_data
    skip_subscription=False,
    repo=False,
    enable_eus=False,
    skip_enabling_rhel_rpms=False,
    cloud_type="openstack",
    fips_mode=False,
    firewall=False,
    config=None,
):
    log.info("Waiting for cloud config to complete on " + ceph.hostname)
    ceph.exec_command(cmd="while [ ! -f /ceph-qa-ready ]; do sleep 15; done")
    log.info("cloud config to completed on " + ceph.hostname)
    _is_client = len(ceph.role.role_list) == 1 and "client" in ceph.role.role_list

    if cloud_type.lower() == "baremetal":
        # Update certs
        update_ca_cert(
            node=ceph,
            cert_url="https://certs.corp.redhat.com/certs/Current-IT-Root-CAs.pem",
            out_file="RH-IT-Root-CA.crt",
            check_ec=False,
        )

        # Update CephCI Cert to all nodes. Useful when creating self-signed certificates.
        update_ca_cert(
            node=ceph,
            cert_url="http://magna002.ceph.redhat.com/cephci-jenkins/.cephqe-ca.pem",
            out_file="cephqe-ca.pem",
            check_ec=False,
        )
    distro_info = ceph.distro_info
    distro_ver = distro_info["VERSION_ID"]
    log.info("distro name: {name}".format(name=distro_info["NAME"]))
    log.info("distro id: {id}".format(id=distro_info["ID"]))
    log.info(
        "distro version_id: {version_id}".format(version_id=distro_info["VERSION_ID"])
    )
    log_host_environment(ceph, stage="prereq-start")

    # Remove apache-arrow.repo for baremetal
    cmd_remove_apache_arrow = "sudo rm -f /etc/yum.repos.d/apache-arrow.repo"
    ceph.exec_command(cmd=cmd_remove_apache_arrow)

    # Max SSH Sessions
    if cloud_type == "onecloud":
        sshd_configs = [
            "sed -i '/MaxSessions*/d' /etc/ssh/sshd_config",
            "echo 'MaxSessions 150' | tee -a /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ]
    else:
        sshd_configs = [
            "sudo sed -i '/MaxSessions*/d' /etc/ssh/sshd_config",
            "echo 'MaxSessions 150' | sudo tee -a /etc/ssh/sshd_config",
            "sudo systemctl restart sshd",
        ]
    for sshd_cfg in sshd_configs:
        ceph.exec_command(cmd=sshd_cfg, sudo=True)

    if ceph.pkg_type == "deb":
        ceph.exec_command(
            cmd="sudo apt-get install -y " + deb_all_packages, long_running=True
        )
    else:
        if distro_ver.startswith("7"):
            ceph.exec_command(cmd="sudo systemctl restart NetworkManager.service")

        if not skip_subscription:
            if not setup_subscription_manager(ceph, "cdn"):
                log.info("Trying to subscribe to stage server")
                setup_subscription_manager(ceph, "stage")

            status = subscription_manager_status(ceph)
            if status == "Unknown" or skip_enabling_rhel_rpms:
                log.info("Enabling local RHEL repositories")
                if not setup_local_repos(ceph):
                    raise RepoConfigError("Failed to enable local RHEL repositories")

            elif enable_eus:
                enable_rhel_eus_rpms(ceph, distro_ver)

            else:
                enable_rhel_rpms(ceph, distro_ver)

        if repo:
            setup_addition_repo(ceph, repo)

        ceph.exec_command(cmd="sudo yum -y upgrade", timeout=600, check_ec=False)

        rpm_all_packages = " ".join(rpm_packages.get("all"))
        if distro_ver.startswith("7"):
            rpm_all_packages = " ".join(rpm_packages.get("7"))

        cmd = f"sudo dnf install --setopt install_weak_deps=False -y {rpm_all_packages}"
        ceph.exec_command(cmd=cmd, long_running=True)

        # Restarting the node for qdisc filter to be loaded. This is required for
        # RHEL-8
        if not distro_ver.startswith("7"):
            # Avoiding early channel close and ignoring channel exception thrown during
            # reboot
            time.sleep(10)
            ceph.exec_command(sudo=True, cmd="reboot", check_ec=False)

            # Sleep before and after reconnect
            time.sleep(60)
            ceph.reconnect()
            time.sleep(10)

        if skip_enabling_rhel_rpms and skip_subscription:
            # Ansible is required for RHCS 4.x
            if distro_ver.startswith("8") and not _is_client:
                # TODO(vamahaja): Temporary changes. Revert ansible package with latest epel repo.
                ansible_pkg = (
                    "http://download-node-02.eng.bos.redhat.com/nightly/rhel-8/ANSIBLE/latest-ANSIBLE-2-RHEL-8/"
                    "compose/Base/x86_64/os/Packages/ansible-2.9.27-1.el8ae.noarch.rpm"
                )
                ceph.exec_command(
                    sudo=True,
                    cmd=f"yum install -y {ansible_pkg}",
                    check_ec=False,
                )

            if distro_ver.startswith("7") and not _is_client:
                ceph.exec_command(
                    sudo=True,
                    cmd="yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm",
                    check_ec=False,
                )
                ceph.exec_command(sudo=True, cmd="yum install -y ansible-2.9.27-1.el7")

        if _is_client:
            ceph.exec_command(cmd="sudo yum install -y attr gcc", long_running=True)
            ceph.exec_command(cmd="sudo pip install crefi", long_running=True)

        ceph.exec_command(cmd="sudo yum clean all")
        config_ntp(ceph, cloud_type)

    update_iptables(ceph)

    if fips_mode:
        # Enable FIPS mode
        if not enable_fips_mode(ceph):
            raise FIPSConfigError("Failed to enable FIPS mode")
        log.info("Enable FIPS mode config set successfully")

        # Restart node and wait
        reboot_node(ceph)

        # Check for FIPS mode setting
        if not is_fips_mode_enabled(ceph):
            raise FIPSConfigError("FIPS mode not enabled after reboot")
        log.info("FIPS mode is enabled")

    if firewall:
        # Start Firewall
        if not set_service_state(ceph, "firewalld", "start"):
            raise ConfigError("Failed to start Firewall")
        log.info("Firewall start successfully")

        # Check for Firewall
        if get_service_state(ceph, "firewalld").strip() != "active":
            raise ConfigError("Firewall not active")
        log.info("Firewall is active")

    # Login to CDN (+ optional custom-config) registries after any reboot
    # (RHEL-8+ qdisc / FIPS) so docker/podman auth survives restarts and is
    # present on every node before bootstrap / monitoring pulls.
    registry_login(ceph, distro_ver, test_data, cloud_type=cloud_type)

    # Enable coredump collection
    enable_coredump(ceph)
    # Distribute podman auth file if specified in config
    # Note: File is validated once before parallel execution in run()
    if config:
        podman_auth_file = config.get("podman_auth_file")
        if podman_auth_file:
            from utility.registry_auth import distribute_podman_auth_file

            try:
                distribute_podman_auth_file(ceph, podman_auth_file)
                log.info(
                    f"Successfully distributed podman auth file to {ceph.hostname}"
                )
            except Exception as e:
                log.error(
                    f"Failed to distribute podman auth file to {ceph.hostname}: {e}"
                )

    # Final snapshot after FIPS / firewall / registry work.
    log_host_environment(ceph, stage="prereq-end")


def _cmd_out(node, cmd, sudo=False):
    """Run a command for logging; never raise. Returns stripped stdout/stderr."""
    try:
        out, err = node.exec_command(cmd=cmd, sudo=sudo, check_ec=False)
        text = (out or err or "").strip()
        return text.splitlines()[0].strip() if text else "n/a"
    except Exception as exc:
        log.debug("env probe failed on %s (%s): %s", node.hostname, cmd, exc)
        return "n/a"


def log_host_environment(node, stage=""):
    """
    Log OS / kernel / OpenSSL / FIPS and related host details.

    Safe for parallel prereq runs; probes use check_ec=False so logging cannot
    fail the suite.
    """
    stage_tag = f" [{stage}]" if stage else ""
    try:
        distro = getattr(node, "distro_info", None) or {}
    except Exception:
        distro = {}

    pretty = distro.get("PRETTY_NAME") or _cmd_out(
        node, "grep ^PRETTY_NAME= /etc/os-release | cut -d= -f2- | tr -d '\"'"
    )
    name = distro.get("NAME") or "n/a"
    version_id = distro.get("VERSION_ID") or "n/a"
    distro_id = distro.get("ID") or "n/a"

    kernel = _cmd_out(node, "uname -r")
    arch = _cmd_out(node, "uname -m")
    openssl_rpm = _cmd_out(node, "rpm -q openssl")
    openssl_libs = _cmd_out(node, "rpm -q openssl-libs")
    openssl_ver = _cmd_out(node, "openssl version")
    fips_proc = _cmd_out(node, "cat /proc/sys/crypto/fips_enabled", sudo=True)
    if fips_proc == "1":
        fips_state = "enabled"
    elif fips_proc == "0":
        fips_state = "disabled"
    else:
        fips_state = f"unknown ({fips_proc})"
    podman = _cmd_out(node, "podman --version")
    roles = (
        ",".join(getattr(getattr(node, "role", None), "role_list", []) or []) or "n/a"
    )

    log.info("=" * 72)
    log.info("Host environment%s — %s", stage_tag, node.hostname)
    log.info("  distro          : %s (%s %s)", pretty, distro_id, version_id)
    log.info("  distro name     : %s", name)
    log.info("  kernel          : %s (%s)", kernel, arch)
    log.info("  openssl rpm     : %s", openssl_rpm)
    log.info("  openssl-libs    : %s", openssl_libs)
    log.info("  openssl version : %s", openssl_ver)
    log.info("  fips            : %s (fips_enabled=%s)", fips_state, fips_proc)
    log.info("  podman          : %s", podman)
    log.info("  roles           : %s", roles)
    log.info("=" * 72)


def setup_addition_repo(ceph, repo):
    log.info("Adding addition repo {repo} to {sn}".format(repo=repo, sn=ceph.shortname))
    ceph.exec_command(
        sudo=True,
        cmd="curl -o /etc/yum.repos.d/rh_add_repo.repo {repo}".format(repo=repo),
    )
    ceph.exec_command(sudo=True, cmd="yum update metadata", check_ec=False)


def setup_subscription_manager(ceph, server, timeout=300, interval=60):
    # Get configuration details from `~/.cephci.yaml`
    configs = get_cephci_config()

    # Get credentials and validate
    creds = configs.get(f"{server}_credentials")
    if not creds:
        raise ConfigNotFoundError(f"{server} credentials are not provided")

    # Subscribe to server
    for w in WaitUntil(timeout=timeout, interval=interval):
        try:
            sm(ceph).register(
                username=creds.get("username"),
                password=creds.get("password"),
                serverurl=creds.get("serverurl"),
                baseurl=creds.get("baseurl"),
                force=True,
            )
            log.info(f"Subscribed to {server} server successfully")
            return True
        except SubscriptionManagerError:
            log.info(f"Failed to subscribe to {server} server. Retrying")

    if w.expired:
        log.info(f"Failed to subscribe to {server} server.")

    return False


def subscription_manager_status(ceph):
    expr = ".*Overall Status:(.*).*"
    status = sm(ceph).status()

    match = re.search(expr, status)
    if not match:
        raise SubscriptionManagerError("Unexpected subscription manager status")

    return match.group(0)


def setup_local_repos(ceph):
    # Get configuration details from `~/.cephci.yaml`
    configs = get_cephci_config()

    # Get distro version
    os_version = os_major_version(ceph)

    # Get local repositories
    repos = configs.get("repo")
    if not repos:
        raise ConfigNotFoundError("Repos are not provided")

    # Get local repositories
    local_repos = repos.get("local", {}).get(f"rhel-{os_version}")
    if not local_repos:
        raise ConfigNotFoundError("local repositories are not provided")

    # Add local repositories
    for repo in local_repos:
        Package(ceph).add_repo(repo=repo)

    log.info("Added local RHEL repos successfully")
    return True


def enable_rhel_rpms(ceph, distro_ver):
    """
    Setup cdn repositories for rhel systems
    Args:
        ceph:       cluster instance
        distro_ver: distro version details
    """
    sm_cmd = "subscription-manager"

    # The latest minor version is available in CDN repos
    # N-x versions would be available in EUS or AUS repos depending on EOL
    # EUS when a newer minor version is available else AUS if older.
    # This would help us avoid the need for --enable-rhel-eus-rpms
    repos = {
        "8": ["rhel-8-for-x86_64-appstream-rpms", "rhel-8-for-x86_64-baseos-rpms"],
        "9": ["rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"],
        "10": ["rhel-10-for-x86_64-appstream-rpms", "rhel-10-for-x86_64-baseos-rpms"],
        "8.10": ["rhel-8-for-x86_64-appstream-rpms", "rhel-8-for-x86_64-baseos-rpms"],
        "9.2": [
            "rhel-9-for-x86_64-appstream-aus-rpms",
            "rhel-9-for-x86_64-baseos-aus-rpms",
        ],
        "9.4": [
            "rhel-9-for-x86_64-appstream-aus-rpms",
            "rhel-9-for-x86_64-baseos-aus-rpms",
        ],
        "9.6": [
            "rhel-9-for-x86_64-appstream-eus-rpms",
            "rhel-9-for-x86_64-baseos-eus-rpms",
        ],
        "9.8": ["rhel-9-for-x86_64-appstream-rpms", "rhel-9-for-x86_64-baseos-rpms"],
        "10.0": [
            "rhel-10-for-x86_64-appstream-eus-rpms",
            "rhel-10-for-x86_64-baseos-eus-rpms",
        ],
        "10.2": ["rhel-10-for-x86_64-appstream-rpms", "rhel-10-for-x86_64-baseos-rpms"],
    }

    rs = repos.get(distro_ver, repos.get(distro_ver.split(".")[0]))
    if not rs:
        log.warning(
            "No RHEL repository configuration found for OS release: %s", distro_ver
        )
        return

    log.info("The provided OS release is %s", distro_ver)
    log.debug("The retrieve repo details are %s", rs)
    ceph.exec_command(sudo=True, cmd=f"{sm_cmd} release --set {distro_ver}")

    for repo in rs:
        ceph.exec_command(
            sudo=True,
            cmd="{sm_cmd} repos --enable={r}".format(sm_cmd=sm_cmd, r=repo),
            long_running=True,
        )


def enable_rhel_eus_rpms(ceph, distro_ver):
    """
    Setup cdn repositories for rhel systems
    reference: http://wiki.test.redhat.com/CEPH/SubscriptionManager
    Args:
        distro_ver:     distro version - example: 7.7
        ceph:           ceph object
    """
    sm_cmd = "subscription-manager"

    eus_repos = {"7": ["rhel-7-server-eus-rpms", "rhel-7-server-extras-rpms"]}

    for repo in eus_repos.get(distro_ver[0]):
        ceph.exec_command(
            sudo=True,
            cmd="{sm_cmd} repos --enable={r}".format(sm_cmd=sm_cmd, r=repo),
            long_running=True,
        )

    rhel_major_version = distro_ver[0]

    if rhel_major_version == "7":
        # We only support one EUS release for RHEL 7:
        release = "7.7"
    else:
        raise NotImplementedError("cannot set EUS repos for %s", rhel_major_version)

    cmd = f"{sm_cmd} release --set={release}"

    ceph.exec_command(
        sudo=True,
        cmd=cmd,
        long_running=True,
    )

    ceph.exec_command(sudo=True, cmd="yum clean all", long_running=True)


# CDN registries logged into on every node during install_prereq (post-reboot).
# Avoids unauthorized pulls when monitoring defaults still target cp.icr.io while
# bootstrap authenticates against preprod / stage hosts.
CDN_REGISTRY_HOSTS = (
    "registry.redhat.io",
    "cp.icr.io",
)


def registry_login(ceph, distro_ver, test_data=None, cloud_type="openstack"):
    """
    Login to CDN (+ optional run-specific) container registries on this node.

    Always attempts CDN hosts (``registry.redhat.io``, ``cp.icr.io``) so auth is
    present before bootstrap / monitoring pulls. Additional hosts come from
    --custom-config keys:
      - bootstrap-registry
      - upgrade-registry
      - registries (comma-separated list)

    Credentials are loaded from the host-keyed ``registries:`` section in
    ~/.cephci.yaml. Called after any install_prereq reboot so credentials
    survive qdisc / FIPS restarts.
    """
    _ = cloud_type  # retained for call-site compatibility
    container = "podman"
    if distro_ver.startswith("7"):
        container = "docker"

    ceph.exec_command(
        cmd="sudo yum install -y {c}".format(c=container), long_running=True
    )

    if container == "docker":
        ceph.exec_command(cmd="sudo systemctl restart docker", long_running=True)

    custom_dict = {}
    if test_data:
        custom_dict = test_data.get("custom_config_dict") or {}
        if not custom_dict and test_data.get("custom-config"):
            custom_dict = parse_custom_config_list(test_data.get("custom-config"))

    # Explicit custom-config hosts (fail hard if credentials missing).
    explicit_hosts = set()
    for key in ("bootstrap-registry", "upgrade-registry"):
        if custom_dict.get(key):
            explicit_hosts.add(custom_dict[key].strip())
    if custom_dict.get("registries"):
        for host in str(custom_dict["registries"]).split(","):
            host = host.strip()
            if host:
                explicit_hosts.add(host)

    auths = {}

    # CDN hosts: best-effort so missing YAML keys do not abort prereq.
    for host in CDN_REGISTRY_HOSTS:
        try:
            reg_args = resolve_registry_login(host)
        except KeyError as err:
            log.warning("Skipping CDN registry %s: %s", host, err)
            continue
        user = reg_args.get("registry-username")
        passwd = reg_args.get("registry-password")
        if not user or not passwd:
            log.warning(
                "Skipping CDN registry %s: username/password missing in cephci config",
                host,
            )
            continue
        b64_auth = base64.b64encode(f"{user}:{passwd}".encode("ascii"))
        auths[host] = {"auth": b64_auth.decode("utf-8")}
        log.info("Prepared CDN registry auth for %s", host)

    # Explicit hosts from custom-config (required when requested).
    for host in sorted(explicit_hosts):
        if host in auths:
            continue
        try:
            reg_args = resolve_registry_login(host)
        except KeyError as err:
            raise ConfigError(str(err)) from err
        user = reg_args["registry-username"]
        passwd = reg_args["registry-password"]
        b64_auth = base64.b64encode(f"{user}:{passwd}".encode("ascii"))
        auths[host] = {"auth": b64_auth.decode("utf-8")}
        log.info("Prepared auth for registry host %s", host)

    if not auths:
        log.warning(
            "No registry credentials resolved; skipping registry login on %s",
            ceph.hostname,
        )
        return

    auths_dict = {"auths": auths}
    ceph.exec_command(sudo=True, cmd="mkdir -p ~/.docker")
    ceph.exec_command(cmd="mkdir -p ~/.docker")

    if is_unsecured_registry(test_data):
        ceph.exec_command(
            cmd=(
                "echo -e '\\n[[registry]]\\n"
                'location = "registry-proxy.engineering.redhat.com"\\n'
                "insecure = true'"
                " | sudo tee -a /etc/containers/registries.conf"
            )
        )

    auths_file_sudo = ceph.remote_file(
        sudo=True, file_name="/root/.docker/config.json", file_mode="w"
    )
    auths_file = ceph.remote_file(
        file_name="/home/cephuser/.docker/config.json", file_mode="w"
    )
    files = [auths_file_sudo, auths_file]
    for file in files:
        file.write(json.dumps(auths_dict, indent=4))
        file.flush()
        file.close()

    log.info(
        "Registry login written on %s for: %s",
        ceph.hostname,
        ", ".join(sorted(auths)),
    )


def update_iptables(node):
    """update ip-tables rules.

    Drop ip-table rule which matches the list of reject entries,
     which ensures no side-effects at Ceph configuration.

     Reference:
     https://docs.ceph.com/en/latest/rados/configuration/network-config-ref/#ip-tables

    Args:
        node: CephNode object
    """
    drop_rules = ["INPUT -j REJECT --reject-with icmp-host-prohibited"]
    try:
        out, _ = node.exec_command(cmd="$(which iptables) --list-rules", sudo=True)
        for rule in drop_rules:
            if rule in out:
                node.exec_command(cmd=f"$(which iptables) -D {rule}", sudo=True)
    except Exception as err:
        log.error(f"iptables rpm do not exist... error : {err}")


# Minimum openssl that provides libcrypto.so.3(OPENSSL_3.4.0) for ceph-common.
OPENSSL_MIN_VERSION = Version("3.5.1")

# UBI CDN RPMs used when the IBM/lab compose does not ship openssl >= 3.5.1.
# (IBM-CEPH / repo.qe.ceph.lab build trees ship ceph-* only.)
OPENSSL_CDN_NVR = "3.5.8-2.el9_8"
OPENSSL_CDN_BASEOS = (
    "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/"
    "x86_64/baseos/os/Packages/o"
)
OPENSSL_CDN_APPSTREAM = (
    "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/"
    "x86_64/appstream/os/Packages/o"
)

# Temporary yum repo used while attempting an openssl upgrade.
_OPENSSL_REPO_DEST = "/etc/yum.repos.d/ceph-openssl-workaround.repo"


def _installed_openssl_version(node):
    """Return installed openssl Version, or None if not installed / unparsable."""
    out, err = node.exec_command(cmd="rpm -q openssl", check_ec=False)
    pkg = (out or err or "").strip().splitlines()
    pkg = pkg[0] if pkg else ""
    if not pkg or "not installed" in pkg:
        log.info("openssl package not installed on %s", node.hostname)
        return None
    # e.g. openssl-3.2.2-6.el9_4.x86_64
    match = re.search(r"^openssl-(\d+\.\d+\.\d+)", pkg)
    if not match:
        log.warning("Unable to parse openssl RPM query output: %s", pkg)
        return None
    try:
        return Version(match.group(1))
    except InvalidVersion:
        log.warning("Invalid openssl version from RPM query: %s", pkg)
        return None


def _is_lab_manifest_compose(base_url):
    """True for QE lab / manifest eu-de compose roots (not a .repo file).

    Examples:
      http://repo.qe.ceph.lab/repos/ceph/testing/ibm/9/rhel9/20.2.2-349/
      http://mirror/.../repos/ceph/testing/ibm/9/rhel9/20.2.2-349/
    """
    if not base_url:
        return False
    lowered = base_url.lower().rstrip("/")
    if lowered.endswith(".repo"):
        return False
    return "repo.qe.ceph.lab" in lowered or "/repos/ceph/" in lowered


def _build_repo_url(base_url):
    """Return a remote .repo URL for public.dhe / manifest default repos.

    Accepted forms:
      1. Full .repo URL (manifest ``repositories.default``), e.g.
         https://public.dhe.ibm.com/.../IBM-CEPH-9.9.2-.../IBM-CEPH-9.9.2-...-rhel9.repo
      2. public.dhe compose directory ending in IBM-CEPH-*, e.g.
         https://public.dhe.ibm.com/.../IBM-CEPH-9.9.2-202609300703.ci.0
         → <base>/<build_id>-rhel9.repo

    Lab/manifest eu-de compose roots are handled by
    ``_write_lab_compose_repo`` instead (no remote .repo file).

    Returns None when base_url is falsy or not a public.dhe-style URL.
    """
    if not base_url:
        return None
    trimmed = base_url.strip().rstrip("/")
    if trimmed.endswith(".repo"):
        return trimmed
    build_id = trimmed.rsplit("/", 1)[-1]
    if build_id.startswith("IBM-CEPH-"):
        return f"{trimmed}/{build_id}-rhel9.repo"
    if _is_lab_manifest_compose(trimmed):
        return None
    log.debug(
        "base_url %r is not a public.dhe .repo / IBM-CEPH compose URL; "
        "remote openssl repo skipped",
        base_url,
    )
    return None


def _write_lab_compose_repo(node, base_url):
    """Write a temporary yum repo pointing at a lab/manifest compose root.

    Manifest eu-de URLs rewrite public.dhe
    ``.../IBM-CEPH-.../rhel9/$basearch/`` trees to
    ``http://repo.qe.ceph.lab/repos/ceph/testing/ibm/<maj>/rhel9/<nvr>/``.
    Use ``$basearch`` when the path already ends at the rhelN level (same
    layout as the public.dhe .repo baseurl).
    """
    root = base_url.rstrip("/")
    # .../rhel9/<nvr> or .../rhel10/<nvr> → packages under $basearch/
    if re.search(r"/rhel\d+/[^/]+$", root, re.I):
        yum_baseurl = f"{root}/$basearch/"
    else:
        yum_baseurl = f"{root}/"
    content = (
        "[ceph-openssl-workaround]\n"
        "name=ceph-openssl-workaround\n"
        f"baseurl={yum_baseurl}\n"
        "gpgcheck=0\n"
        "enabled=1\n"
    )
    log.info(
        "Writing lab/manifest compose repo on %s (baseurl=%s)",
        node.hostname,
        yum_baseurl,
    )
    # Single-quoted heredoc so $basearch is preserved for yum.
    node.exec_command(
        sudo=True,
        cmd=f"cat > {_OPENSSL_REPO_DEST} <<'EOF'\n{content}EOF",
        long_running=True,
    )
    return True


def _add_openssl_workaround_repo(node, base_url):
    """Add a temporary yum repo from public.dhe or lab/manifest base_url.

    Returns True when a temporary repo file was installed (caller must remove it).
    """
    repo_url = _build_repo_url(base_url)
    if repo_url:
        log.info("Adding public.dhe/manifest .repo from %s on %s", repo_url, node.hostname)
        node.exec_command(
            sudo=True,
            cmd=f"curl -sSLo {_OPENSSL_REPO_DEST} {repo_url}",
            long_running=True,
        )
        return True
    if _is_lab_manifest_compose(base_url):
        return _write_lab_compose_repo(node, base_url)
    log.info(
        "No public.dhe or lab/manifest base_url on %s; "
        "trying upgrade via already-enabled repos",
        node.hostname,
    )
    return False


def _upgrade_openssl_from_cdn(node) -> None:
    """Force-install openssl >= 3.5.1 from the RHEL 9 UBI CDN."""
    log.info(
        "Installing openssl %s from UBI CDN on %s",
        OPENSSL_CDN_NVR,
        node.hostname,
    )
    rpms = [
        f"{OPENSSL_CDN_BASEOS}/openssl-libs-{OPENSSL_CDN_NVR}.x86_64.rpm",
        f"{OPENSSL_CDN_BASEOS}/openssl-{OPENSSL_CDN_NVR}.x86_64.rpm",
        f"{OPENSSL_CDN_APPSTREAM}/openssl-devel-{OPENSSL_CDN_NVR}.x86_64.rpm",
    ]
    rpm_names = [url.rsplit("/", 1)[-1] for url in rpms]
    for url in rpms:
        node.exec_command(cmd=f"wget -q {url}", sudo=True, long_running=True)
    node.exec_command(
        cmd=f"rpm --force -Uvh {' '.join(rpm_names)}",
        sudo=True,
        long_running=True,
    )


def workaround_openssl_issue(node, base_url=None) -> None:
    """
    Ensure openssl >= 3.5.1 is installed so ceph-common can resolve
    libcrypto.so.3(OPENSSL_3.4.0) on RHEL 9 nodes.

    Strategy (tried in order until openssl reaches the minimum version):
      1. Add a temporary yum repo from config[base_url] when it is:
         - a public.dhe / manifest ``*.repo`` URL, or
         - a public.dhe ``IBM-CEPH-*`` compose directory, or
         - a lab/manifest eu-de compose root (``repo.qe.ceph.lab`` /
           ``/repos/ceph/...``).
         Then ``yum install openssl openssl-libs openssl-devel``.
      2. Fallback: same yum install against already-enabled repos.
      3. Final fallback: force-install openssl from the RHEL 9 UBI CDN.
         IBM/lab compose trees ship ceph packages only, not openssl 3.5.x.

    NOTE:
        Remove once supported RHEL 9 BaseOS streams provide OPENSSL_3.4.0.
        https://tracker.ceph.com/issues/71250

    Args:
        node:     cluster node object
        base_url: compose / .repo URL (config["base_url"] / --rhs-ceph-repo).
    """
    log_host_environment(node, stage="openssl-check")
    current = _installed_openssl_version(node)
    if current is not None and current >= OPENSSL_MIN_VERSION:
        log.info(
            "openssl %s on %s already >= %s; skip upgrade",
            current,
            node.hostname,
            OPENSSL_MIN_VERSION,
        )
        return

    log.info(
        "openssl %s on %s is below %s; attempting upgrade",
        current if current is not None else "missing",
        node.hostname,
        OPENSSL_MIN_VERSION,
    )

    added_repo = _add_openssl_workaround_repo(node, base_url)
    try:
        node.exec_command(
            sudo=True,
            cmd="yum install -y --nogpgcheck openssl openssl-libs openssl-devel",
            long_running=True,
        )
    finally:
        if added_repo:
            node.exec_command(sudo=True, cmd=f"rm -f {_OPENSSL_REPO_DEST}")

    upgraded = _installed_openssl_version(node)
    log.info("openssl after repo upgrade on %s: %s", node.hostname, upgraded)

    if upgraded is None or upgraded < OPENSSL_MIN_VERSION:
        log.warning(
            "openssl still at %s on %s after repo attempt; falling back to UBI CDN",
            upgraded,
            node.hostname,
        )
        try:
            _upgrade_openssl_from_cdn(node)
        except Exception as exc:
            log.error("UBI CDN openssl install failed on %s: %s", node.hostname, exc)
        upgraded = _installed_openssl_version(node)
        log.info("openssl after CDN upgrade on %s: %s", node.hostname, upgraded)

    if upgraded is None or upgraded < OPENSSL_MIN_VERSION:
        log.error(
            "openssl upgrade failed on %s: still at %s (need >= %s)",
            node.hostname,
            upgraded,
            OPENSSL_MIN_VERSION,
        )
    log_host_environment(node, stage="openssl-upgraded")
