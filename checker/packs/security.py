import re

from checker.rule import Rule
from checker.utils import  label_in_lst
from checker.settings import q, SPEC_DICT, SPEC_TEMPLATE_DICT, SENSITIVE_KEY_REGEX, SENSITIVE_VALUE_REGEX, \
    DANGEROUS_PATH, DOCKER_PATH, CLOUD_UNSAFE_MOUNT_PATHS
from checker.workload import Workload


class K001(Rule):
    def scan(self):
        sa = self.db.ServiceAccount.search(~(q.automountServiceAccountToken.exists()) |
                                           (q.automountServiceAccountToken == True))
        serviceAccounts = list(set([item["metadata"]["name"] for item in sa]))
        for workload, Spec in SPEC_DICT.items():
            query = ~(Spec.automountServiceAccountToken.exists()) & Spec.serviceAccountName.one_of(serviceAccounts) \
                    | (Spec.automountServiceAccountToken == True)
            self.output[workload] = getattr(self.db, workload).search(query)


class K002(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostIPC == True)


class K003(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostPID == True)


class K004(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostNetwork == True)


class K005(Rule):
    def scan(self):
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search(Spec.hostPort == True)


class K009(Rule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configmap_output = []

    def scan(self):
        key_comb = "(" + ")|(".join(SENSITIVE_KEY_REGEX) + ")"
        val_comb = "(" + ")|(".join(SENSITIVE_VALUE_REGEX) + ")"
        check_regex = lambda data: any([bool(re.search(key_comb, k, flags=re.IGNORECASE)) |
                                        bool(re.search(val_comb, v, flags=re.IGNORECASE))
                                        for k, v in data.items()])
        wc = Workload()
        self.output["ConfigMap"] = self.db.ConfigMap.search(q.metadata.name.test(wc.set_name) &
                                                            q.data.test(check_regex) & q.data.test(wc.insensitive_cm,
                                                                                                   key_comb, val_comb))
        self.configmap_output = wc.output


class K0030(Rule):
    def scan(self):
        self.output["Ingress"] = self.db.Ingress.search(~q.spec.tls.exists())


class K0036(Rule):
    def scan(self):
        pods = self.db.Pod.search(q.metadata.labels.exists())
        pod_labels = [pod["metadata"]["labels"] for pod in pods]
        check_label = lambda labels: label_in_lst(labels, pod_labels)
        check_pt = lambda pt: set(map(str.upper, pt)) == {"INGRESS", "EGRESS"}
        Spec = q.spec
        condition = (
                Spec.podSelector.matchLabels.exists() & Spec.ingress.exists() & Spec.egress.exists() &
                Spec.policyTypes.exists() & Spec.policyTypes.test(check_pt) &
                Spec.podSelector.matchLabels.test(check_label))
        self.output["NetworkPolicy"] = self.db.NetworkPolicy.search(~condition)


class K0043(Rule):
    # CronJob exists
    def scan(self):
        self.output["CronJob"] = self.db.CronJob.all()


class K0044(Rule):
    # ValidatingWebhookConfiguration
    def scan(self):
        self.output["ValidatingWebhookConfiguration"] = \
            self.db.ValidatingWebhookConfiguration.all()


class K0045(Rule):
    # MutatingWebhookConfiguration
    def scan(self):
        self.output["MutatingWebhookConfiguration"] = \
            self.db.MutatingWebhookConfiguration.all()


class K0052(Rule):
    # dangerous host path
    def scan(self):
        check_path = lambda path: bool(path and any([path == item for item in DANGEROUS_PATH]))
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search \
                (Spec.volumes.any(q.hostPath.path.test(check_path)))

class K0053(Rule):
    # alert-mount-credentials-path
    @staticmethod
    def fix_path(path):
        if not re.match(r'[\w-]+\.', path) and not path.endswith("/"):
            return f"{path}/"
        return path

    def scan(self):
        check_path = lambda path: K0053.fix_path(path) in \
                                  [item for v in CLOUD_UNSAFE_MOUNT_PATHS.values() for item in v]
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search \
                (Spec.volumes.any(q.hostPath.path.exists() & q.hostPath.path.test(check_path)))



class K0054(Rule):
    def scan(self):
        check_ssh = lambda port: int(port) in [22, 2222]
        services = self.db.Service.search(
            q.spec.selector.exists() & q.spec.ports.any(q.port.test(check_ssh) | q.targetPort.test(check_ssh)))
        service_labels = [item["spec"]["selector"] for item in services]
        check_label = lambda labels: label_in_lst(labels, service_labels)
        for workload, Spec in SPEC_DICT.items():
            template = SPEC_TEMPLATE_DICT[workload]
            self.output[workload] = getattr(self.db, workload).search(template.metadata.labels.exists() &
                                                                      template.metadata.labels.test(check_label))


class K0055(Rule):
    # dangerous host path
    def scan(self):
        check_path = lambda path: bool(path and any([path.startswith(item) for item in DOCKER_PATH]))
        for workload, Spec in SPEC_DICT.items():
            self.output[workload] = getattr(self.db, workload).search \
                (Spec.volumes.any(q.hostPath.path.test(check_path)))
