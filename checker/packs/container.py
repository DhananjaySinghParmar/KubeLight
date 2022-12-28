import re

from checker.rule import Rule
from checker.settings import q, SPEC_DICT, INSECURE_CAP, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX, \
    DANGEROUS_CAP, TRUSTED_REGISTRY, UNTRUSTED_REGISTRY


class K005(Rule):
    # dangerousCapabilities
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def scan(self):
        self.message = "Container %s has added dangerous capabilities " + ",".join(DANGEROUS_CAP)
        check_cap = lambda add: bool(set(map(str.upper, add)) & set(DANGEROUS_CAP))
        self.query = (q.securityContext.capabilities.add != None) & \
                     (q.securityContext.capabilities.add.test(check_cap))
        self.scan_workload_any_container()


class K006(Rule):
    # linuxHardening
    def scan(self):
        self.wl_func = "linux_hardening"
        self.scan_workload_any_container()


class K007(Rule):
    # insecureCapabilities
    def scan(self):
        self.message = "Container {c.name} has insecure capabilities"
        check_cap = lambda drop: (set(map(str.upper, drop)) == set(INSECURE_CAP)) or \
                                 "ALL" in list(map(str.upper, drop))
        self.query = ~(q.securityContext.capabilities.drop.test(check_cap))
        self.scan_workload_any_container()


class K008(Rule):
    # sensitiveContainerEnvVar
    def scan(self):
        key_combined = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_combined = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([(bool(re.search(key_combined, kv.get("name", ""), flags=re.IGNORECASE)) |
                                         bool(re.search(val_combined, kv.get("value", ""), flags=re.IGNORECASE))) &
                                        (not bool(kv.get("valueFrom")))
                                        for kv in data])
        self.query = q.env.test(check_regex)
        self.wl_func = "insensitive_env"
        self.scan_workload_any_container(key_combined, val_combined)


class K0031(Rule):
    def scan(self):
        self.message = "Container {c.name} has hostPort set"
        self.query = (q.ports.exists() & q.ports.any(q.hostPort.exists()))
        self.scan_workload_any_container()


class K0032(Rule):
    def scan(self):
        self.message = "Container {c.name} is privileged"
        self.query = (q.securityContext.privileged.exists() & (q.securityContext.privileged == True)) | \
                     (q.securityContext.capabilities.add.test(lambda add: "SYS_ADMIN" in [c.upper() for c in add]))
        self.scan_workload_any_container()


class K0033(Rule):
    def scan(self):
        self.message = "AllowPrivilegeEscalation is not explicitly set on Container {c.name}"
        self.query = ~(q.securityContext.allowPrivilegeEscalation.exists() & (
                q.securityContext.allowPrivilegeEscalation == False))
        self.scan_workload_any_container()


class K0034(Rule):
    def scan(self):
        self.message = "readOnlyRootFilesystem is not enabled on Container {c.name}"
        self.query = ~(q.securityContext.readOnlyRootFilesystem.exists() & (
                q.securityContext.readOnlyRootFilesystem == True))
        self.scan_workload_any_container()


class K0035(Rule):
    def scan(self):
        self.wl_func = "non_root"
        self.scan_workload_any_container()


class K0037(Rule):
    # Untrusted registry
    def scan(self):
        self.message = "Container {c.name}: Image from untrusted registry {c.image}"
        extract_registry = lambda image_string: next((part for part in re.split('/', image_string) if part),
                                                     'docker.io')
        check_regex = lambda image: (extract_registry(image) not in TRUSTED_REGISTRY) or \
                                    (extract_registry(image) in UNTRUSTED_REGISTRY)
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0046(Rule):
    # CVE-2022-47633 kyverno-signature-bypass
    def scan(self):
        self.message = "Container {c.name}: Image is vulnerable to CVE-2022-47633   {c.image}"
        pattern = r".*kyverno:.*1\.8\.([3-4])"
        check_regex = lambda image: bool(re.search(pattern, image))
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0047(Rule):
    # CVE-2022-39328 grafana auth
    def scan(self):
        self.message = "Container {c.name}: Image is vulnerable to CVE-2022-39328 {c.image}"
        pattern = r".*grafana:.*9\.2\.([0-3])"
        check_regex = lambda image: bool(re.search(pattern, image))
        self.query = (q.image.test(check_regex))
        self.scan_workload_any_container()


class K0051(Rule):
    # host mount rw
    def scan(self):
        self.wl_func = "host_path_rw"
        self.scan_workload_any_container()
