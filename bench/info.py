class C_1_1_1:
    title = "Ensure that the API server pod specification file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The API server pod specification file controls various parameters that set the behavior of the API server.\
                 You should restrict its file permissions to maintain the integrity of the file. The file should be writable\
                 by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml "
    

class C_1_1_2:
    title = "Ensure that the API server pod specification file ownership is set to root:root (Automated)"
    rationale = "The API server pod specification file controls various parameters that set the behaviorof the API server.\
                 You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml"


class C_1_1_3:
    title = "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The controller manager pod specification file controls various parameters that set the behavior of the Controller\
                 Manager on the master node. You should restrict its file permissions to maintain the integrity of the file.\
                 The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/manifests/kube-controller-manager.yaml"


class C_1_1_4:
    title = "Ensure that the controller manager pod specification file ownership is set to root:root (Automated)"
    rationale = "The controller manager pod specification file controls various parameters that set the behavior of various\
                 components of the master node. You should set its file ownership to maintain the integrity of the file.\
                 The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/manifests/kube-controller-manager.yaml"


class C_1_1_5:
    title = "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The scheduler pod specification file controls various parameters that set the behavior ofthe Scheduler\
                service in the master node. You should restrict its file permissions to maintain the integrity of the file.\
                The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/manifests/kube-scheduler.yaml"


class C_1_1_6:
    title = "Ensure that the scheduler pod specification file ownership is set to root:root (Automated)"
    rationale = "The scheduler pod specification file controls various parameters that set the behavior of the kube-scheduler\
                service in the master node. You should set its file ownership to maintain the integrity of the file.\
                The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/manifests/kube-scheduler.yaml"


class C_1_1_7:
    title = "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the\
                behavior of the etcd service in the master node. etcd is a highlyavailable key-value store which Kubernetes uses\
                for persistent storage of all of its REST API object. You should restrict its file permissions to maintain the \
                integrity of the file. The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/manifests/etcd.yaml"


class C_1_1_8:
    title = "Ensure that the etcd pod specification file ownership is set to root:root (Automated)"
    rationale = "The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the behavior\
                of the etcd service in the master node. etcd is a highly available key-value store which Kubernetes uses for persistent\
                storage of all of its REST API object. You should set its file ownership to maintain the integrity of the file.\
                The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/manifests/etcd.yaml"


class C_1_1_9:
    title = "Ensure that the Container Network Interface file permissions are set to 600 or more restrictive (Manual)"
    rationale = "Container Network Interface provides various networking options for overlay networking. You should consult their\
                documentation and restrict their respective file permissions tomaintain the integrity of those files.\
                Those files should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 <path/to/cni/files>"


class C_1_1_10:
    title = "Ensure that the Container Network Interface file ownership is set to root:root (Manual)"
    rationale = "Container Network Interface provides various networking options for overlay networking. You should consult\
                their documentation and restrict their respective file permissions to maintain the integrity of those files.\
                Those files should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root <path/to/cni/files>"


class C_1_1_11:
    title = "Ensure that the etcd data directory permissions are set to 700 or more restrictive (Automated)"
    rationale = "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all\
                of its REST API objects. This data directory should be protected from any unauthorized reads or writes.\
                It should not be readable or writable by any group members or the world."
    remediation = "On the etcd server node, get the etcd data directory, passed as an argument --datadir,from the below command:"
    command = "ps -ef | grep etcd"
    "Run the below command (based on the etcd data directory found above)."
    command = "chmod 700 /var/lib/etcd"


class C_1_1_12:
    title = "Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)"
    rationale = "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all\
                of its REST API objects. This data directory should be protected from any unauthorized reads or writes.\
                It should be owned by etcd:etcd."
    remediation = "On the etcd server node, get the etcd data directory, passed as an argument --datadir,from the below command:"
    command = "ps -ef | grep etcd"
    "Run the below command (based on the etcd data directory found above)."
    command = "chown etcd:etcd /var/lib/etcd"


class C_1_1_13:
    title = "Ensure that the admin.conf file permissions are set to 600 (Automated)"
    rationale = "The admin.conf is the administrator kubeconfig file defining various settings for theadministration of the cluster.\
                This file contains private key and respective certificate allowed to fully manage the cluster. You should restrict its\
                file permissions to maintain the integrity and confidentiality of the file. The file should be readable and writable\
                by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/admin.conf"


class C_1_1_14:
    title = "Ensure that the admin.conf file ownership is set to root:root (Automated)"
    rationale = "The admin.conf file contains the admin credentials for the cluster. You should set its file ownership to maintain the\
                integrity and confidentiality of the file. The file should beowned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/admin.conf"


class C_1_1_15:
    title = "Ensure that the scheduler.conf file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The scheduler.conf file is the kubeconfig file for the Scheduler. You should restrict its file permissions to maintain\
                the integrity of the file. The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/scheduler.conf"


class C_1_1_16:
    title = "Ensure that the scheduler.conf file ownership is set to root:root (Automated)"
    rationale = "The scheduler.conf file is the kubeconfig file for the Scheduler. You should set its file ownership to maintain\
                the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/scheduler.conf"


class C_1_1_17:
    title = "Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should restrict its file\
                permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod 600 /etc/kubernetes/controller-manager.conf"


class C_1_1_18:
    title = "Ensure that the controller-manager.conf file ownership is set to root:root (Automated)"
    rationale = "The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should set its file ownership\
                to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown root:root /etc/kubernetes/controller-manager.conf"


class C_1_1_19:
    title = "Ensure that the Kubernetes PKI directory and file ownership is set to root:root (Automated)"
    rationale = "Kubernetes makes use of a number of certificates as part of its operation. You should set the ownership of the\
                directory containing the PKI information and all files in that directory to maintain their integrity.\ 
                The directory and files should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chown -R root:root /etc/kubernetes/pki/"


class C_1_1_20:
    title = "Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive (Manual)"
    rationale = "Kubernetes makes use of a number of certificate files as part of the operation of its components.\
                The permissions on these files should be set to 600 or more restrictive toprotect their integrity."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod -R 600 /etc/kubernetes/pki/*.crt"


class C_1_1_21:
    title = "Ensure that the Kubernetes PKI key file permissions are set to 600 (Manual)"
    rationale = "Kubernetes makes use of a number of key files as part of the operation of its components.\
                The permissions on these files should be set to 600 to protect their integrity and confidentiality."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "chmod -R 600 /etc/kubernetes/pki/*.key"
    
    
class C_1_2_1:
    title = "Ensure that the --anonymous-auth argument is set to false (Manual)"
    rationale = "When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests.\
                These requests are then served by theAPI server. You should rely on authentication to authorize access and disallow anonymous requests.\
                If you are using RBAC authorization, it is generally considered reasonable to allow anonymous access to the API Server for health checks\
                and discovery purposes, and hence this recommendation is not scored. However, you should consider whether anonymous discovery is an\
                acceptable risk for your purposes."
    impact = "Anonymous requests will be rejected."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the below parameter."
    command = "--anonymous-auth=false"
    
    
class C_1_2_2:
    title = "Ensure that the --token-auth-file parameter is not set (Automated)"
    rationale = "The token-based authentication utilizes static tokens to authenticate requests to the apiserver. The tokens are\
                stored in clear-text in a file on the apiserver, and cannot be revoked or rotated without restarting the apiserver.\
                Hence, do not use static tokenbased authentication."
    impact = "You will have to configure and use alternate authentication mechanisms such as certificates. Static token based authentication could not be used."
    remediation = "Follow the documentation and configure alternate mechanisms for authentication. Then, edit the API server pod specification file\
                /etc/kubernetes/manifests/kubeapiserver.yaml on the master node and remove the --token-auth-file=<filename> parameter."


class C_1_2_3:
    title = "Ensure that the --DenyServiceExternalIPs is not set (Automated)"
    rationale = "This admission controller rejects all net-new usage of the Service field externalIPs. This feature is very powerful\
                (allows network traffic interception) and not well controlled by policy. When enabled, users of the cluster may not create new Services\
                which use externalIPs and may not add new values to externalIPs on existing Service objects. Existing uses of externalIPs are not \
                affected, and users may remove values from externalIPs on existing Service objects.\
                Most users do not need this feature at all, and cluster admins should consider disabling it. Clusters that do need to use this feature\
                should consider using some custom policy to manage usage of it."
    impact = "When enabled, users of the cluster may not create new Services which use externalIPs and may not add new values to externalIPs on existing Service objects."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the master node and remove the\
                `--DenyServiceExternalIPs'parameter or The Kubernetes API server flag disable-admission-plugins takes a comma-delimited list\
                of admission control plugins to be disabled, even if they are in the list of plugins enabled by default.\
                kube-apiserver --disable-admission-plugins=DenyServiceExternalIPs,AlwaysDeny"


class C_1_2_4:
    title = "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate (Automated)"
    rationale = "The apiserver, by default, does not authenticate itself to the kubelet's HTTPS endpoints. The requests from the apiserverare\
                treated anonymously. You should set up certificatebased kubelet authentication to ensure that the apiserver authenticates itself to\
                kubelets when submitting requests."
    impact = "You require TLS to be configured on apiserver as well as kubelets."
    remediation = "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets.\
                   Then, edit API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set\
                   the kubelet client certificate and key parameters as below."
    command = "--kubelet-client-certificate=<path/to/client-certificate-file> \
               --kubelet-client-key=<path/to/client-key-file>"


class C_1_2_5:
    title = "Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)"
    rationale = "The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods,\
                and using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default,\
                the apiserver does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks,\
                and unsafe to run over untrusted and/or public networks."
    impact = "You require TLS to be configured on apiserver as well as kubelets."
    remediation = "Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the API server\
                   pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the\
                   --kubelet-certificate-authority parameter to the path to the cert file for the certificate authority."
    command = "--kubelet-certificate-authority=<ca-string>"


class C_1_2_6:
    title = "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)"
    rationale = "The API Server, can be configured to allow all requests. This mode should not be used on any production cluster."
    impact = "Only authorized requests will be served."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node\
                   and set the --authorization-mode parameter to values other than AlwaysAllow."
    command = "--authorization-mode=RBAC"


class C_1_2_7:
    title = "Ensure that the --authorization-mode argument includes Node (Automated)"
    rationale = "The Node authorization mode only allows kubelets to read Secret, ConfigMap, PersistentVolume, and PersistentVolumeClaim\
                objects associated with their nodes."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver. yaml on the Control Plane node and\
                set the --authorization-mode parameter to a value that includes Node."
    command = "--authorization-mode=Node,RBAC"


class C_1_2_8:
    title = "Ensure that the --authorization-mode argument includes RBAC (Automated)"
    rationale = "Role Based Access Control (RBAC) allows fine-grained control over the operations that different entities can perform on\
                different objects in the cluster. It is recommended to  use the RBAC authorization mode."
    impact = "When RBAC is enabled you will need to ensure that appropriate RBAC settings (including Roles, RoleBindings and ClusterRoleBindings)\
            are configured to allow appropriate access."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
    set the --authorization-mode parameter to a value that includes RBAC."
    command = "--authorization-mode=Node,RBAC"

    
class C_1_2_9:
    title = "Ensure that the admission control plugin EventRateLimit is set (Manual)"
    rationale = "Using EventRateLimit admission control enforces a limit on the number of events that the API Server will accept in a given time slice.\
                A misbehaving workload could overwhelm and DoS the API Server, making it unavailable. This particularly applies to a multi-tenant cluster,\
                where there might be a small percentage of misbehaving tenants which could have a significant impact on the performance of the cluster overall.\
                Hence, it is recommended to limit the rate of events that the API server will accept.\
                Note: This is an Alpha feature in the Kubernetes 1.15 release."
    impact = "You need to carefully tune in limits as per your environment."
    remediation = "Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod\
                   specification file /etc/kubernetes/manifests/kubeapiserver.yaml and set the below parameters."
    command = "--enable-admission-plugins=...,EventRateLimit,...\
               --admission-control-config-file=<path/to/configuration/file>"


class C_1_2_10:
    title = "Ensure that the admission control plugin AlwaysAdmit is not set (Automated)"
    rationale = "Setting admission control plugin AlwaysAdmit allows all requests and do not filter any requests.\
                The AlwaysAdmit admission controller was deprecated in Kubernetes v1.13. Its behavior was equivalent to turning off all admission controllers."
    impact ="Only requests explicitly allowed by the admissions control plugins would be served."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
                  either remove the --enable-admissionplugins parameter, or set it to a value that does not include AlwaysAdmit."


class C_1_2_11:
    title = "Ensure that the admission control plugin AlwaysPullImages is set (Manual)"
    rationale = "Setting admission control policy to AlwaysPullImages forces every new pod to pull the required images every time.\
                In a multi-tenant cluster users can be assured that their private images can only be used by those who have the credentials to pull them.\
                Without this admission control policy, once an image has been pulled to a node, any pod from any user can use it simply by knowing the\
                image’s name, without any authorization check against the image ownership. When this plug-in is enabled, images are always pulled prior\
                to starting containers, which means valid credentials are required."
    impact ="Credentials would be required to pull the private images every time. Also, in trusted environments, this might increases load on network,\
            registry, and decreases speed. This setting could impact offline or isolated clusters, which have images pre-loaded and do not have access\
            to a registry to pull in-use images. This setting is not appropriate for clusters which use this configuration."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
                  set the --enable-admission-plugins parameter to include AlwaysPullImages."
    command = "--enable-admission-plugins=...,AlwaysPullImages,..."


class C_1_2_12:
    title = "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used (Manual)"
    rationale = "SecurityContextDeny can be used to provide a layer of security for clusters which do not have PodSecurityPolicies enabled."
    impact = "This admission controller should only be used where Pod Security Policies cannot be used on the cluster,\
              as it can interact poorly with certain Pod Security Policies"
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
    set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place."
    command = "--enable-admission-plugins=...,SecurityContextDeny,..."


class C_1_2_13:
    title = "Ensure that the admission control plugin ServiceAccount is set (Automated)"
    rationale = "When you create a pod, if you do not specify a service account, it is automatically assigned the default service account in the same\
                namespace. You should create your own service account and let the API server manage its security tokens."
    remediation = "RFollow the documentation and create ServiceAccount objects as per your environment. Then, edit the API server pod specification\
                   file /etc/kubernetes/manifests/kubeapiserver.yaml on the master node and ensure that the --disable-admission-plugins parameter is\
                   set to a value that does not include ServiceAccount."


class C_1_2_14:
    title = "Ensure that the admission control plugin NamespaceLifecycle is set (Automated)"
    rationale = "Setting admission control policy to NamespaceLifecycle ensures that objects cannot be created in non-existent namespaces,\
                and that namespaces undergoing termination are not used for creating the new objects. This is recommended to enforce the integrity of\
                the namespace termination process and also for the availability of the newer objects."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
                   set the --disable-admission-plugins parameter to ensure it does not include NamespaceLifecycle."


class C_1_2_15:
    title = "Ensure that the admission control plugin NodeRestriction is set (Automated)"
    rationale = "Using the NodeRestriction plug-in ensures that the kubelet is restricted to the Node and Pod objects that it could modify as defined.\
                Such kubelets will only be allowed to modify their own Node API object, and only modify Pod API objects that are bound to their node."
    remediation = "Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification\
                 file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that\
                 includes NodeRestriction."
    command = "--enable-admission-plugins=...,NodeRestriction,..."


class C_1_2_16:
    title = "Ensure that the --secure-port argument is not set to 0 (Automated)"
    rationale = "The secure port is used to serve https with authentication and authorization. If you disable it, no https traffic is served and\
                all traffic is served unencrypted."
    impact =" You need to set the API Server up with the right TLS certificates."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and\
                  either remove the --secure-port parameter or set it to a different (non-zero) desired port."


class C_1_2_17:
    title = "Ensure that the --profiling argument is set to false (Automated)"
    rationale = "Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that\
                could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the\
                profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface."
    impact = "Profiling information would not be available."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the below parameter."
    command = "--profiling=false"


class C_1_2_18:
    title = "Ensure that the --audit-log-path argument is set (Automated)"
    rationale = "Auditing the Kubernetes API Server provides a security-relevant chronological set of records documenting the sequence of activities that\
                have affected system by individual users, administrators or other components of the system. Even though currently, Kubernetes provides\
                only basic audit capabilities, it should be enabled. You can enable it by setting an appropriate audit log path."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the\
                  --audit-log-path parameter to a suitable path"
    command = "--audit-log-path=/var/log/apiserver/audit.log"


class C_1_2_19:
    title = "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Automated)"
    rationale = "Retaining logs for at least 30 days ensures that you can go back in time and investigate or correlate any events.\
                Set your audit log retention period to 30 days or as per your business requirements."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the\
                 --audit-log-maxage parameter to 30 or as an appropriate number of days:"
    command = "--audit-log-maxage=30"


class C_1_2_20:
    title = "Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Automated)"
    rationale = "Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for\
                carrying out any investigation or correlation. If you have set file size of 100 MB and the number of old log files to keep\
                as 10, you would approximate have 1 GB of log data that you could potentially use for your analysis."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the\
                 --audit-log-maxbackup parameter to 10 or to an appropriate value."
    command = "--audit-log-maxbackup=10"


class C_1_2_21:
    title = "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Automated)"
    rationale = "Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for\
                carrying out any investigation or correlation. If you have set file size of 100 MB and the number of old log files to keep as 10,\
                you would approximate have 1 GB of log data that you could potentially use for your analysis."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the\
                 --audit-log-maxsize parameter to an appropriate size in MB. To set it as 100 MB:"
    command = "--audit-log-maxsize=100"
    
    
class C_1_2_22:
    title = "Ensure that the --request-timeout argument is set as appropriate (Manual)"
    rationale = "Setting global request timeout allows extending the API server request timeout limit to a duration appropriate to the user's\
                connection speed. By default, it is set to 60 seconds which might be problematic on slower connections making cluster resources\
                inaccessible once the data volume for requests exceeds what can be transmitted in 60seconds. But, setting this timeout limit to\
                be too large can exhaust the API server resources making it prone to Denial-of-Service attack. Hence, it is recommended to set\
                this limit as appropriate and change the default limit of 60 seconds only if needed."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml and set the below parameter as appropriate."
    command = "--request-timeout=300s"


class C_1_2_23:
    title = "Ensure that the --service-account-lookup argument is set to true (Automated)"
    rationale = "If --service-account-lookup is not enabled, the apiserver only verifies that the authentication token is valid, and does not validate\
                that the service account tokenmentioned in the request is actually present in etcd. This allows using a service accounttoken even after\
                the corresponding service account is deleted. This is an example of time of check to time of use security issue."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the below parameter."
    command = "--service-account-lookup=true"
     "Alternatively, you can delete the --service-account-lookup parameter from this file so that the default takes effect."


class C_1_2_24:
    title = "Ensure that the --service-account-key-file argument is set as appropriate (Automated)"
    rationale = "By default, if no --service-account-key-file is specified to the apiserver, it uses the private key from the TLS serving certificate\
                to verify service account tokens. To ensure that the keys for service account tokens could be rotated as needed, a separate\
                public/private key pair should be used for signing service account tokens. Hence, the public key should be specified to the apiserver\
                with --service-account-key-file."
    impact = "The corresponding private key must be provided to the controller manager. You would need to securely maintain the key file and rotate\
            the keys based on your organization's key rotation policy."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kubeapiserver.yaml on the Control Plane node and set the\
                 --service-account-key-file parameter to the public key file for service accounts:"
    command = "--service-account-key-file=<filename>"


class C_1_2_25:
    title = "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be protected by client authentication. This requires the API server to identify\
                itself to the etcd server using a client certificate and key."
    impact = "TLS and client certificate authentication must be configured for etcd."
    remediation = "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod\
    specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate and key file parameters."
    command = "--etcd-certfile=<path/to/client-certificate-file>\
              --etcd-keyfile=<path/to/client-key-file>"
   

class C_1_2_26:
    title = "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Automated)"
    rationale = "API server communication contains sensitive parameters that should remain encrypted in transit.\
                Configure the API server to serve only HTTPS traffic."
    impact = "TLS and client certificate authentication must be configured for your Kubernetes cluster deployment."
    remediation = "Follow the Kubernetes documentation and set up the TLS connection on the apiserver.Then, edit the API server pod specification\
                  file /etc/kubernetes/manifests/kubeapiserver.yaml on the master node and set the TLS certificate and private key file parameters."
    command = "--tls-cert-file=<path/to/tls-certificate-file>\
               --tls-private-key-file=<path/to/tls-key-file>"


class C_1_2_27:
    title = "Ensure that the --client-ca-file argument is set as appropriate (Automated)"
    rationale = "API server communication contains sensitive parameters that should remain encrypted in transit. Configure the API server to serve\
                only HTTPS traffic. If --client-ca-file argument is set, any request presenting a client certificate signed by one of the authorities\
                in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate."
    impact = "TLS and client certificate authentication must be configured for your Kubernetes cluster deployment."
    remediation = "Follow the Kubernetes documentation and set up the TLS connection on the apiserver. Then, edit the API server pod specification\
                  file /etc/kubernetes/manifests/kubeapiserver.yaml on the master node and set the client certificate authority file."
    command = "--client-ca-file=<path/to/client-ca-file>"


class C_1_2_28:
    title = "Ensure that the --etcd-cafile argument is set as appropriate (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in natureand should be protected by client authentication. This requires the API server to identify\
                itself to the etcd server using a SSL Certificate Authority file."
    impact = "TLS and client certificate authentication must be configured for etcd."
    remediation = "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and etcd. Then, edit the API server pod\
                  specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the etcd certificate authority file parameter."
    command = "--etcd-cafile=<path/to/ca-file>"


class C_1_2_29:
    title = "Ensure that the --encryption-provider-config argument is set as appropriate (Manual)"
    rationale = "etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be encrypted at rest to avoid any disclosures."
    remediation = "Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file\
                  /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the\
                  path of that file:"
    command = "--encryption-provider-config=</path/to/EncryptionConfig/File>"


class C_1_2_30:
    title = "Ensure that encryption providers are appropriately configured (Manual)"
    rationale = "Where etcd encryption is used, it is important to ensure that the appropriate set of encryption providers is used.\
                Currently, the aescbc, kms and secretbox are likely to be appropriate options."
    remediation = "Follow the Kubernetes documentation and configure a EncryptionConfig file. In this file, choose aescbc, kms or secretbox\
               as the encryption provider."


class C_1_2_31:
    title = "Ensure that the API Server only makes use of Strong Cryptographic Ciphers (Manual)"
    rationale = "TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them.\
                By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided."
    impact = "API server clients that cannot support modern cryptographic ciphers will not be able to make connections to the API server."
    remediation = "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and\
                  set the below parameter."
    command = "--tls-cipher-suites=TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,\
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,\
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,\ 
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,\
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,\
            TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA,\
            TLS_RSA_WITH_AES_256_GCM_SHA384."
    
class C_1_3_1:
    title  = "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate (Manual)"
    rationale = "Garbage collection is important to ensure sufficient resource availability and avoiding degraded performance and availability.\
                In the worst case, the system might crash or just be unusable for a long period of time. The current setting for garbage collection is\
                12,500 terminated pods which might be too high for your system to sustain. Based on your system resources and tests, choose an\
                appropriate threshold value to activate garbage collection."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and set the --terminated-pod-gcthreshold to an appropriate threshold."
    command = "--terminated-pod-gc-threshold=10"
    

class C_1_3_2:
    title = "Ensure that the --profiling argument is set to false (Automated)"
    rationale = "Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that\
                could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the\
                profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface."
    impact = "Profiling information would not be available."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and set the below parameter."
    command = "--profiling=false"


class C_1_3_3:
    title = "Ensure that the --use-service-account-credentials argument is set to true (Automated)"
    rationale = "The controller manager creates a service account per controller in the kube-system namespace, generates a credential for it, and builds a\
                 dedicated API client with that service account credential for each controller loop to use. Setting the --use-serviceaccount-credentials\
                 to true runs each control loop within the controller manager using a separate service account credential.  When used in combination with\
                 RBAC, thisensures that the control loops run with the minimum permissions required to perform their intended tasks."
    impact = "Whatever authorizer is configured for the cluster, it must grant sufficient permissions to the service accounts to perform their intended\
            tasks. When using the RBAC authorizer, those roles are created and bound to the appropriate service accounts in the kubesystem namespace\
            automatically with default roles and rolebindings that are autoreconciled on startup.\
            If using other authorization methods (ABAC, Webhook, etc), the cluster deployer is responsible for granting appropriate permissions to the\
            service accounts (the required permissions can be seen by inspecting the controller-roles.yaml and controllerrole-bindings.yaml files for\
            the RBAC roles."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                to set the below parameter."
    command = "--use-service-account-credentials=true"


class C_1_3_4:
    title = "Ensure that the --service-account-private-key-file argument is set as appropriate (Automated)"
    rationale = "To ensure that keys for service account tokens can be rotated as needed, a separate public/private key pair should be used for signing\
                service account tokens. The private key should be specified to the controller manager with\
                --service-account-privatekey-file as appropriate."
    impact = "You would need to securely maintain the key file and rotate the keys based on your organization's key rotation policy."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and set the --service-accountprivate-key-file parameter to the private key file for service accounts."
    command = "--service-account-private-key-file=<filename>"


class C_1_3_5:
    title = "Ensure that the --root-ca-file argument is set as appropriate (Automated)"
    rationale = "Processes running within pods that need to contact the API server must verify the API server's serving certificate.\
                Failing to do so could be a subject to man-in-the-middle attacks.\
                Providing the root certificate for the API server's serving certificate to the controller manager with the --root-ca-file argument\
                allows the controller manager to inject the trusted bundle into pods so that they can verify TLS connections to the API server."
    impact = "You need to setup and maintain root certificate authority file."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and set the --root-ca-file parameter to the certificate bundle file."
    command = "--root-ca-file=<path/to/file>"


class C_1_3_6:
    title = "Ensure that the RotateKubeletServerCertificate argument is set to true (Automated)"
    rationale = "RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials\
                and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes\
                due to expired certificates and thus addressing availability in the CIA security triad.\
                Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates\
                come from an outside authority/tool (e.g. Vault) then you need to take care of rotation yourself."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and set the --feature-gates parameter to include RotateKubeletServerCertificate=true."
    command = "--feature-gates=RotateKubeletServerCertificate=true"


class C_1_3_7:
    title = "Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)"
    rationale = "The Controller Manager API service which runs on port 10252/TCP by default is used for health and metrics information and is available\
                without authentication or encryption. As such it should only be bound to a localhost interface, to minimize the cluster's attack surface."
    remediation = "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kubecontroller-manager.yaml on the Control Plane node\
                and ensure the correct value for the --bind-address parameter"

class C_1_4_1:
    title "Ensure that the --profiling argument is set to false (Automated)"
    rationale = "Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that\
              could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the\
              profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface."
    impact = "Profiling information would not be available."
    remediation = "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kubescheduler.yaml file on the Control Plane node and set below parameter."
    command = "--profiling=false"
    

class C_1_4_2:
    title = "Ensure that the --bind-address argument is set to 127.0.0.1 (Automated)"
    rationale = "The Scheduler API service which runs on port 10251/TCP by default is used for healthand metrics information and is available without\
                authentication or encryption. As such it should only be bound to a localhost interface, to minimize the cluster's attack surface."
    remediation = "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kubescheduler.yaml on the Control Plane node and ensure\
                the correct value for the --bindaddress parameter."
    
  
class C_2_1:
    title = "Ensure that the --cert-file and --key-file arguments are set as appropriate (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be encrypted in transit."
    impact = "Client connections only over TLS would be served."
    remediation = "Follow the etcd service documentation and configure TLS encryption. Then, edit the etcd pod specification file\
                /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
    command = "--cert-file=</path/to/ca-file>\
               --key-file=</path/to/key-file>"
    

class C_2_2:
    title = "Ensure that the --client-cert-auth argument is set to true (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication\
                via valid certificates to secure the access to the etcd service."
    impact ="All clients attempting to access the etcd server will require a valid client certificate."
    remediation = "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
    command = "--client-cert-auth="true""


class C_2_3:
    title = "Ensure that the --auto-tls argument is not set to true (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication\
                via valid certificates to secure the access to the etcd service."
    impact = "Clients will not be able to use self-signed certificates for TLS."
    remediation = "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the --auto-tls parameter\
                or set it to false."
    command = "--auto-tls=false"


class C_2_4:
    title = "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be encrypted in transit and also amongst peers in the etcd clusters."
    impact = "etcd cluster peers would need to set up TLS for their communication."
    remediation = "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster. Then, edit the etcd\
                pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameters."
    command = "--peer-client-file=</path/to/peer-cert-file>\
               --peer-key-file=</path/to/peer-key-file>"


class C_2_5:
    title = "Ensure that the --peer-client-cert-auth argument is set to true (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster."
    impact = "All peers attempting to communicate with the etcd server will require a valid client certificate for authentication."
    remediation = "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
    command = "--peer-client-cert-auth=true"


class C_2_6:
    title = "Ensure that the --peer-auto-tls argument is not set to true (Automated)"
    rationale = "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. Hence, do not\
                use self-signed certificates for authentication."
    impact ="All peers attempting to communicate with the etcd server will require a valid client certificate for authentication."
    remediation = "Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and either remove the\
                --peer-auto-tls parameter or set it to false."
    command = "--peer-auto-tls=false"


class C_2_7:
    title = "Ensure that a unique Certificate Authority is used for etcd (Manual)"
    rationale = "etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects.\
                Its access should be restricted to specifically designated clients and peers only.\
                Authentication to etcd is based on whether the certificate presented was issued by a trusted certificate authority. There is no checking\
                of certificate attributes such as common name or subject alternative name. As such, if any attackers were able to gain access to any\
                certificate issued by the trusted certificate authority, they would be able to gain full access to the etcd database."
    impact = "Additional management of the certificates and keys for the dedicated certificate authority will be required."
    remediation = "Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service.\
                  Then, edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master node and set the below parameter."
    command = "--trusted-ca-file=</path/to/ca-file>" 
    
    
 class C_3_1_1:
    title = "3.1.1 Client certificate authentication should not be used for users (Manual)"
    rationale = "With any authentication mechanism the ability to revoke credentials if they are compromised or no longer required, is a key control.\
                Kubernetes client certificate authentication does not allow for this due to a lack of support for certificate revocation."
    impact = "External mechanisms for authentication generally require additional software to be deployed."
    remediation = "Alternative mechanisms provided by Kubernetes such as the use of OIDC should be implemented in place of client certificates."
    

class C_3_2_1:
    title = "Ensure that a minimal audit policy is created (Manual)"
    rationale = "Logging is an important detective control for all systems, to detect potential unauthorised access."
    impact = "Audit logs will be created on the master nodes, which will consume disk space. Care should be taken to avoid generating too large volumes\
            of log information as this could impact the available of the cluster nodes."
    remediation = "Create an audit policy file for your cluster."
    

class C_3_2_2:
    title = "Ensure that the audit policy covers key security concerns (Manual)"
    rationale = "Security audit logs should cover access and modification of key resources in the cluster, to enable them to form an effective part of\
                a security environment."
    impact = "Increasing audit logging will consume resources on the nodes or other log destination."
    remediation = "Consider modification of the audit policy in use on the cluster to include these items, at a minimum."
    
    
 class C_4_1_1:
    title = "Ensure that the kubelet service file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should\
                restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chmod 600 /etc/systemd/system/kubelet.service.d/kubeadm.conf"
    

class C_4_1_2:
    title = "Ensure that the kubelet service file ownership is set to root:root (Automated)"
    rationale = "The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should\
                set its file ownership to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chown root:root /etc/systemd/system/kubelet.service.d/kubeadm.conf"


class C_4_1_3:
    title = "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive (Manual)"
    rationale = "The kube-proxy kubeconfig file controls various parameters of the kube-proxy service in the worker node. You should restrict its file\
                permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.\
                It is possible to run kube-proxy with the kubeconfig parameters configured as a Kubernetes ConfigMap instead of a file. In this case,\
                there is no proxy kubeconfig file."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chmod 600 <proxy kubeconfig file>"


class C_4_1_4:
    title = "If proxy kubeconfig file exists ensure ownership is set to root:root (Manual)"
    rationale = "The kubeconfig file for kube-proxy controls various parameters for the kube-proxy service in the worker node. You should set its file\
                ownership to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chown root:root <proxy kubeconfig file>"


class C_4_1_5:
    title = "Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive (Automated)"
    rationale = "The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the\
                worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the\
                administrators on the system."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chmod 600 /etc/kubernetes/kubelet.conf"


class C_4_1_6:
    title = "Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root (Automated)"
    rationale = "The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the\
                worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the below command (based on the file location on your system) on the each worker node."
    command = "chown root:root /etc/kubernetes/kubelet.conf"


class C_4_1_7:
    title = "Ensure that the certificate authorities file permissions are set to 600 or more restrictive (Manual)"
    rationale = "The certificate authorities file controls the authorities used to validate API requests. You should restrict its file permissions to\
                maintain the integrity of the file. The file should be writable by only the administrators on the system."
    remediation = "Run the following command to modify the file permissions of the --client-ca-file"
    command = "chmod 600 <filename>"


class C_4_1_8:
    title = "Ensure that the client certificate authorities file ownership is set to root:root (Manual)"
    rationale = "The certificate authorities file controls the authorities used to validate API requests. You should set its file ownership to maintain\
                the integrity of the file. The file should be owned by root:root."
    remediation = "Run the following command to modify the ownership of the --client-ca-file."
    command = "chown root:root <filename>"


class C_4_1_9:
    title = "If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive (Manual)"
    rationale = "The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file\
                is specified you should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the\
                administrators on the system."
    remediation = "Run the following command (using the config file location)"
    command = "chmod 600 /var/lib/kubelet/config.yaml"


class C_4_1_10:
    title = "If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root (Manual)"
    rationale = "The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file\
                is specified you should restrict its file permissions to maintain the integrity of the file. The file should be owned by root:root."
    remediation = "Run the following command (using the config file location)"
    command = "chown root:root /etc/kubernetes/kubelet.conf"

    
class C_4_2_1:
    title = "Ensure that the --anonymous-auth argument is set to false (Automated)"
    rationale = "When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These\
                requests are then served by the Kubelet server. You should rely on authentication to authorize access and disallow anonymous requests."
    impact ="Anonymous requests will be rejected."
    remediation = "If using a Kubelet config file, edit the file to set authentication: anonymous: enabled to false.\
                If using executable arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below parameter\
                in KUBELET_SYSTEM_PODS_ARGS variable."
    command = "--anonymous-auth=false"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"

class C_4_2_2:
    title = "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)"
    rationale = "Kubelets, by default, allow all authenticated requests (even anonymous ones) without needing explicit authorization checks from the\
                apiserver. You should restrict this behavior and only allow explicitly authorized requests."
    impact ="Unauthorized requests will be denied."
    remediation = "If using a Kubelet config file, edit the file to set authorization: mode to Webhook.\
                  If using executable arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below\
                  parameter in KUBELET_AUTHZ_ARGS variable."
    command = "--authorization-mode=Webhook"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"


class C_4_2_3:
    title = "Ensure that the --client-ca-file argument is set as appropriate (Automated)"
    rationale = "The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and\
                using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default, the apiserver\
                does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run\
                over untrusted and/or public networks. Enabling Kubelet certificate authentication ensures that the apiserver could authenticate the\
                Kubelet before submitting any requests."
    impact ="You require TLS to be configured on apiserver as well as kubelets."
    remediation = "If using a Kubelet config file, edit the file to set authentication: x509: clientCAFile to the location of the client CA file. If\
                using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below parameter\
                in KUBELET_AUTHZ_ARGS variable."
    command = "--client-ca-file=<path/to/client-ca-file>"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"


class C_4_2_4:
    title = "Verify that the --read-only-port argument is set to 0 (Manual)"
    rationale = "The Kubelet process provides a read-only API in addition to the main Kubelet API.\
                Unauthenticated access is provided to this read-only API which could possibly retrieve potentially sensitive information about the cluster."
    impact = "Removal of the read-only port will require that any service which made use of it will need to be re-configured to use the main Kubelet API."
    remediation = "If using a Kubelet config file, edit the file to set readOnlyPort to 0. If using command line arguments, edit the kubelet service file\
                /etc/kubernetes/kubelet.conf on each worker node and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable."
    command = "--read-only-port=0"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"


class C_4_2_5:
    title = "Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Manual)"
    rationale = "Setting idle timeouts ensures that you are protected against Denial-of-Service attacks, inactive connections and running out of ephemeral ports."
    impact = "Long-lived connections could be interrupted."
    remediation = "If using a Kubelet config file, edit the file to set streamingConnectionIdleTimeout to a value other than 0.\
                If using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below\
                parameter in KUBELET_SYSTEM_PODS_ARGS variable."
    command = "--streaming-connection-idle-timeout=5m"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"


class C_4_2_6:
    title = "Ensure that the --protect-kernel-defaults argument is set to true (Automated)"
    rationale = "Kernel parameters are usually tuned and hardened by the system administrators before putting the systems into production. These\
                parameters protect the kernel and the system. Your kubelet kernel defaults that rely on such parameters should be appropriately set to\
                match the desired secured system state. Ignoring this could potentially lead to running pods with undesired kernel behavior."
    impact ="You would have to re-tune kernel parameters to match kubelet parameters."
    remediation = "If using a Kubelet config file, edit the file to set protectKernelDefaults: true.\
                If using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below\
                parameter in KUBELET_SYSTEM_PODS_ARGS variable."
    command = "--protect-kernel-defaults=true"
    "Based on your system, restart the kubelet service."
    command ="systemctl daemon-reload\
              systemctl restart kubelet.service"


class C_4_2_7:
    title = "Ensure that the --make-iptables-util-chains argument is set to true (Automated)"
    rationale = "Kubelets can automatically manage the required changes to iptables based on how you choose your networking options for the pods. It is\
                recommended to let kubelets manage the changes to iptables. This ensures that the iptables configuration remains in sync with pods\
                networking configuration. Manually configuring iptables with dynamic pod network configuration changes might hamper the communication\
                between pods/containers and to the outside world. You might have iptables rules too restrictive or too open."
    Impact : "Kubelet would manage the iptables on the system and keep it in sync. If you are using any other iptables management solution, then there\
            might be some conflicts."
    remediation = "If using a Kubelet config file, edit the file to set makeIPTablesUtilChains: true.\
                If using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and remove the\
                --makeiptables-util-chains argument from the KUBELET_SYSTEM_PODS_ARGS variable.\
                Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"


class C_4_2_8:
    title = "Ensure that the --hostname-override argument is not set (Manual)"
    rationale = "Overriding hostnames could potentially break TLS setup between the kubelet and the apiserver. Additionally, with overridden hostnames,\
                it becomes increasingly difficult to associate logs with a particular node and process them for security analytics. Hence, you should\
                setup your kubelet nodes with resolvable FQDNs and avoid overriding the hostnames with IPs."
    impact ="Some cloud providers may require this flag to ensure that hostname matches names issued by the cloud provider. In these environments, this\
            recommendation should not apply."
    remediation = "Edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node and remove the\
                --hostname-override argument from the KUBELET_SYSTEM_PODS_ARGS variable.\
                Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"


class C_4_2_9:
    title = "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture(Manual)"
    rationale = "It is important to capture all events and not restrict event creation. Events are an important source of security information and\
                analytics that ensure that your environment is consistently monitored using the event data."
    impact = "Setting this parameter to 0 could result in a denial of service condition due to excessive events being created. The cluster's event\
             processing and storage systems should be scaled to handle expected event loads."
    remediation = "If using a Kubelet config file, edit the file to set eventRecordQPS: to an appropriate level.\
                If using command line arguments, edit the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf on each worker node\
                and set the below parameter in KUBELET_SYSTEM_PODS_ARGS variable.\
                Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"


class C_4_2_10:
    title = "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Manual)"
    rationale = "The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and\
    using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default, the apiserver does not\
    verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or\
    public networks."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "If using a Kubelet config file, edit the file to set tlsCertFile to the location of the certificate file to use to identify this Kubelet,\
            and tlsPrivateKeyFile to the location of the corresponding private key file.\
            If using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below parameters\
            in KUBELET_CERTIFICATE_ARGS variable.\
            --tls-cert-file=<path/to/tls-certificate-file> --tls-private-key-file=<path/to/tls-key-file>\
            Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"
    
    
class C_4_2_11:
    title = "Ensure that the --rotate-certificates argument is not set to false (Automated)"
    rationale = "The --rotate-certificates setting causes the kubelet to rotate its client certificates by creating new CSRs as its existing credentials\
                expire. This automated periodic rotation ensures that the there is no downtime due to expired certificates and thus addressing\
                availability in the CIA security triad.\
                Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates\
                come from an outside authority/tool (e.g. Vault) then you need to take care of rotation yourself.\
                Note: This feature also require the RotateKubeletClientCertificate feature gate to be enabled (which is the default since Kubernetes v1.7)"
    remediation = "If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value.\
                 If using command line arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and remove\
                 --rotatecertificates= false argument from the KUBELET_CERTIFICATE_ARGS variable.\
                Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"

class C_4_2_12:
    title = "Verify that the RotateKubeletServerCertificate argument is set to true (Manual)"
    rationale = "RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and\
                rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due\
                to expired certificates and thus addressing availability in the CIA security triad.\
                Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates\
                come from an outside authority/tool (e.g. Vault) then you need to take care of rotation yourself."
    remediation = "Edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the below parameter in\
                KUBELET_CERTIFICATE_ARGS variable."
    command = "--feature-gates=RotateKubeletServerCertificate=true"
                "Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"


class C_4_2_13:
    title = "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers (Manual)"
    rationale = "TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default\
                Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided."
    impact = "Kubelet clients that cannot support modern cryptographic ciphers will not be able to make connections to the Kubelet API."
    remediation = "If using a Kubelet config file, edit the file to set TLSCipherSuites: to TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,\
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,\
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_256_GCM_SHA384,\
                TLS_RSA_WITH_AES_128_GCM_SHA256 or to a subset of these values.\
                If using executable arguments, edit the kubelet service file /etc/kubernetes/kubelet.conf on each worker node and set the\
                --tls-cipher-suites parameter as follows, or to a subset of these values."
    command = "--tls-ciphersuites=  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,\
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,\
            TLS_RSA_WITH_AES_128_GCM_SHA256"
            "Based on your system, restart the kubelet service."
    command = "systemctl daemon-reload\
               systemctl restart kubelet.service"
    
class C_5_1_1:
    title = "Ensure that the cluster-admin role is only used where required"
    rationale = "Kubernetes provides a set of default roles where RBAC is used. Some of these roles such as cluster-admin provide wide-ranging\
                privileges which should only be applied where absolutely necessary. Roles such as cluster-admin allow super-user access to perform any\
                action on any resource. When used in a ClusterRoleBinding, it gives full control over every resource in the cluster and in all namespaces.\
                When used in a RoleBinding, it gives full control over every resource in the rolebinding's namespace, including the namespace itself."
    impact = "Care should be taken before removing any clusterrolebindings from the environment to ensure they were not required for operation of the\
            cluster. Specifically, modifications should not be made to clusterrolebindings with the system: prefix as they are required for the operation\
            of system components."
    remediation = "Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a\
                role with fewer privileges. Where possible, first bind users to a lower privileged role and then remove the clusterrolebinding to the\
                cluster-admin role :"
    command = "kubectl delete clusterrolebinding [name]"
    

class C_5_1_2:
    title = "Minimize access to secrets (Manual)"
    rationale = "Inappropriate access to secrets stored within the Kubernetes cluster can allow for an attacker to gain additional access to the\
                Kubernetes cluster or external resources whose credentials are stored as secrets."
    impact = "Care should be taken not to remove access to secrets to system components which require this for their operation."
    remediation = "Where possible, remove get, list and watch access to secret objects in the cluster."


class C_5_1_3:
    title = "Minimize wildcard use in Roles and ClusterRoles (Manual)"
    rationale = "The principle of least privilege recommends that users are provided only the access required for their role and nothing more. The use of\
                wildcard rights grants is likely to provide excessive rights to the Kubernetes API."
    remediation = "Where possible replace any use of wildcards in clusterroles and roles with specific objects or actions."


class C_5_1_4:
    title = "Minimize access to create pods (Manual)"
    rationale = "The ability to create pods in a cluster opens up possibilities for privilege escalation and should be restricted, where possible."
    impact = "Care should be taken not to remove access to pods to system components which require this for their operation."
    remediation = "Where possible, remove create access to pod objects in the cluster."


class C_5_1_5:
    title = "Ensure that default service accounts are not actively used (Manual)"
    rationale = "Kubernetes provides a default service account which is used by cluster workloads where no specific service account is assigned to the pod.\
                Where access to the Kubernetes API from a pod is required, a specific service account should be created for that pod, and rights granted\
                to that service account.\
                The default service account should be configured such that it does not provide a service account token and does not have any explicit\
                rights assignments."
    impact = "All workloads which require access to the Kubernetes API will require an explicit service account to be created."
    remediation = "Create explicit service accounts wherever a Kubernetes workload requires specific access to the Kubernetes API server.\
                Modify the configuration of each default service account to include this value"
    command = "automountServiceAccountToken: false"


class C_5_1_6:
    title = "Ensure that Service Account Tokens are only mounted where necessary (Manual)"
    rationale = "Mounting service account tokens inside pods can provide an avenue for privilege escalation attacks where an attacker is able to\
                compromise a single pod in the cluster.\
                Avoiding mounting these tokens removes this attack avenue."
    impact = "Pods mounted without service account tokens will not be able to communicate with the API server, except where the resource is available\
            to unauthenticated principals."
    remediation = "Modify the definition of pods and service accounts which do not need to mount service account tokens to disable it."


class C_5_1_7:
    title = "Avoid use of system:masters group (Manual)"
    rationale = "The system:masters group has unrestricted access to the Kubernetes API hard-coded into the API server source code. An authenticated user\
             who is a member of this group cannot have their access reduced, even if all bindings and cluster role bindings which mention it, are removed.\
             When combined with client certificate authentication, use of this group can allow for irrevocable cluster-admin level credentials to exist\
             for a cluster"
    impact =" Once the RBAC system is operational in a cluster system:masters should not be specifically required, as ordinary bindings from principals\
            to the cluster-admin cluster role can be made where unrestricted access is required."
    remediation = "Remove the system:masters group from all users in the cluster."


class C_5_1_8:
    title = "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster (Manual)"
    rationale = "The impersonate privilege allows a subject to impersonate other users gaining their rights to the cluster. The bind privilege allows the\
                subject to add a binding to a cluster role or role which escalates their effective permissions in the cluster. The escalate privilege\
                allows a subject to modify cluster roles to which they are bound, increasing their rights to that level.\
                Each of these permissions has the potential to allow for privilege escalation to clusteradmin level.
    impact = "There are some cases where these permissions are required for cluster service operation, and care should be taken before removing these\
            permissions from system service accounts."
    remediation = "Where possible, remove the impersonate, bind and escalate rights from subjects."

    
class C_5_2_1:
    title = "Ensure that the cluster has at least one active policy control mechanism in place (Manual)"
    rationale = "Without an active policy control mechanism, it is not possible to limit the use of containers with access to underlying cluster nodes,\
                via mechanisms like privileged containers, or the use of hostPath volume mounts."
    impact = "Where policy control systems are in place, there is a risk that workloads required for the operation of the cluster may be stopped from\
            running. Care is required when implementing admission control policies to ensure that this does not occur."
    remediation = "Ensure that either Pod Security Admission or an external policy control system is in place for every namespace which contains\
                user workloads."
    

class C_5_2_2:
    title = "Minimize the admission of privileged containers (Manual)"
    rationale = "Privileged containers have access to all Linux Kernel capabilities and devices. A container running with full privileges can do almost\
                everything that the host can do. This flag exists to allow special use-cases, like manipulating the network stack and accessing devices.\
                There should be at least one admission control policy defined which does not permit privileged containers.\
                If you need to run privileged containers, this should be defined in a separate policy and you should carefully check to ensure that only\
                limited service accounts and users are given permission to use that policy."
    impact = "Pods defined with spec.containers[].securityContext.privileged: true, spec.initContainers[].securityContext.privileged: true and\
            spec.ephemeralContainers[].securityContext.privileged: true will not be permitted."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of privileged containers."


class C_5_2_3:
    title = "Minimize the admission of containers wishing to share the host process ID namespace (Automated)"
    rationale = "A container running in the host's PID namespace can inspect processes running outside the container. If the container also has access to\
                ptrace capabilities this can be used to escalate privileges outside of the container.\
                There should be at least one admission control policy defined which does not permit containers to share the host PID namespace.\
                If you need to run containers which require hostPID, this should be defined in a separate policy and you should carefully check to ensure\
                that only limited service accounts and users are given permission to use that policy."
    impact = "Pods defined with spec.hostPID: true will not be permitted unless they are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of hostPID containers."


class C_5_2_4:
    title = "Minimize the admission of containers wishing to share the host IPC namespace (Automated)"
    rationale = "A container running in the host's IPC namespace can use IPC to interact with processes outside the container.\
                There should be at least one admission control policy defined which does not permit containers to share the host IPC namespace.\
                If you need to run containers which require hostIPC, this should be defined in a separate policy and you should carefully check to ensure\
                that only limited service accounts and users are given permission to use that policy."
    impact =" Pods defined with spec.hostIPC: true will not be permitted unless they are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of hostIPC containers."


class C_5_2_5:
    title = "Minimize the admission of containers wishing to share the host network namespace (Automated)"
    rationale = "A container running in the host's network namespace could access the local loopback device, and could access network traffic to and\
                from other pods.\
                There should be at least one admission control policy defined which does not permit containers to share the host network namespace.\
                If you need to run containers which require access to the host's network namesapces, this should be defined in a separate policy and\
                you should carefully check to ensure that only limited service accounts and users are given permission to use that policy."
    impact = "Pods defined with spec.hostNetwork: true will not be permitted unless they are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of hostNetwork containers."


class C_5_2_6:
    title = "Minimize the admission of containers with allowPrivilegeEscalation (Automated)"
    rationale = "A container running with the allowPrivilegeEscalation flag set to true may have processes that can gain more privileges than their parent.\
                There should be at least one admission control policy defined which does not permit containers to allow privilege escalation. The option\
                exists (and is defaulted to true) to permit setuid binaries to run. If you have need to run containers which use setuid binaries or\
                require privilege escalation, this should be defined in a separate policy and you should carefully check to ensure that only limited\
                service accounts and users are given permission to use that policy."
    impact = "Pods defined with spec.allowPrivilegeEscalation: true will not be permitted unless they are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with\
    .spec.allowPrivilegeEscalationset to true."


class C_5_2_7:
    title = "Minimize the admission of root containers (Automated)"
    rationale = "Containers may run as any Linux user. Containers which run as the root user, whilst constrained by Container Runtime security\
                features still have a escalated likelihood of container breakout.\
                Ideally, all containers should run as a defined non-UID 0 user.\
                There should be at least one admission control policy defined which does not permit root containers.\
                If you need to run root containers, this should be defined in a separate policy and you should carefully check to ensure that only\
                limited service accounts and users are given permission to use that policy."
    impact ="Pods with containers which run as the root user will not be permitted."
    remediation = "Create a policy for each namespace in the cluster, ensuring that either MustRunAsNonRoot or MustRunAs with the range of UIDs\
                not including 0, is set."


class C_5_2_8:
    title = "Minimize the admission of containers with the NET_RAW capability (Automated)"
    rationale = "Containers run with a default set of capabilities as assigned by the Container Runtime. By default this can include potentially\
                dangerous capabilities. With Docker as the container runtime the NET_RAW capability is enabled which may be misused by malicious containers.\
                Ideally, all containers should drop this capability.\
                There should be at least one admission control policy defined which does not permit containers with the NET_RAW capability.\
                If you need to run containers with this capability, this should be defined in a separate policy and you should carefully check to ensure\
                that only limited service accounts and users are given permission to use that policy."
    impact = "Pods with containers which run with the NET_RAW capability will not be permitted."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers with the NET_RAW capability."


class C_5_2_9:
    title = "Minimize the admission of containers with added capabilities (Automated)"
    rationale = "Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities outside this set can be added to\
                containers which could expose them to risks of container breakout attacks.\
                There should be at least one policy defined which prevents containers with capabilities beyond the default set from launching.\
                If you need to run containers with additional capabilities, this should be defined in a separate policy and you should carefully check to\
                ensure that only limited service accounts and users are given permission to use that policy."
    impact = "Pods with containers which require capabilities outside the default set will not be permitted."
    remediation = "Ensure that allowedCapabilities is not present in policies for the cluster unless it is set to an empty array."


class C_5_2_10:
    title = "Minimize the admission of containers with capabilities assigned (Manual)"
    rationale = "Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities are parts of the rights generally\
                granted on a Linux system to the root user.\
                In many cases applications running in containers do not require any capabilities to operate, so from the perspective of the principal\
                of least privilege use of capabilities should be minimized."
    impact = "Pods with containers require capabilities to operate will not be permitted."
    remediation = "Review the use of capabilities in applications running on your cluster. Where a namespace contains applications which do not require\
                any Linux capabilities to operateconsider adding a policy which forbids the admission of containers which do not drop all capabilities."
    
    
class C_5_2_11:
    title = "Minimize the admission of Windows HostProcess Containers (Manual)"
    rationale = "A Windows container making use of the hostProcess flag can interact with the underlying Windows cluster node. As per the Kubernetes\
                documentation, this provides privileged access to the Windows node.\
                Where Windows containers are used inside a Kubernetes cluster, there should be at least one admission control policy which does not \
                permit hostProcess Windows containers.\
                If you need to run Windows containers which require hostProcess, this should be defined in a separate policy and you should carefully\
                check to ensure that only limited service accounts and users are given permission to use that policy."
    impact = "permitted unless they are run under a specific policy."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of hostProcess containers."


class C_5_2_12:
    title = "Minimize the admission of HostPath volumes (Manual)"
    rationale = "A container which mounts a hostPath volume as part of its specification will have access to the filesystem of the underlying cluster\
                node. The use of hostPath volumes may allow containers access to privileged areas of the node filesystem.\
                There should be at least one admission control policy defined which does not permit containers to mount hostPath volumes.\
                If you need to run containers which require hostPath volumes, this should be defined in a separate policy and you should carefully check\
                to ensure that only limited service accounts and users are given permission to use that policy."
    impact = "Pods defined which make use of hostPath volumes will not be permitted unless they are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict theadmission of containers which use hostPath volumes."


class C_5_2_13:
    title = "Minimize the admission of containers which use HostPorts (Manual)"
    rationale = "Host ports connect containers directly to the host's network. This can bypass controls such as network policy.\
                There should be at least one admission control policy defined which does not permit containers which require the use of HostPorts.\
                If you need to run containers which require HostPorts, this should be defined in a separate policy and you should carefully check to\
                ensure that only limited service accounts and users are given permission to use that policy."
    impact = "Pods defined with hostPort settings in either the container, initContainer or ephemeralContainer sections will not be permitted unless they\
            are run under a specific policy."
    remediation = "Add policies to each namespace in the cluster which has user workloads to restrict the admission of containers which use hostPort sections."

    
class C_5_3_1:
    title = "Ensure that the CNI in use supports Network Policies (Manual)"
    rationale = "Kubernetes network policies are enforced by the CNI plugin in use. As such it is important to ensure that the CNI plugin supports both\
                Ingress and Egress network policies."
    remediation = "Run the below command (based on the file location on your system) on the Control Plane node."
    command = "If the CNI plugin in use does not support network policies, consideration should be given to making use of a different plugin, or finding\
            an alternate mechanism for restricting traffic in the Kubernetes cluster."
    

class C_5_3_2:
    title = "Ensure that all Namespaces have Network Policies defined (Manual)"
    rationale = "Running different applications on the same Kubernetes cluster creates a risk of one compromised application attacking a neighboring\
                application. Network segmentation is important to ensure that containers can communicate only with those they are supposed to.\
                A network policy is a specification of how selections of pods are allowed to communicate with each other and other network endpoints.\
                Network Policies are namespace scoped. When a network policy is introduced to a given namespace, all traffic not allowed by the policy is\
                denied. However, if there are no network policies in a namespace all traffic will be allowed into and out of the pods in that namespace."
    impact = "Once network policies are in use within a given namespace, traffic not explicitly allowed by a network policy will be denied. As such it is\
            important to ensure that, when introducing network policies, legitimate traffic is not blocked."
    remediation = "Follow the documentation and create NetworkPolicy objects as you need them."
    
    
class C_5_4_1:
    title = "Prefer using secrets as files over secrets as environment variables (Manual)"
    rationale = "It is reasonably common for application code to log out its environment (particularly in the event of an error). This will include any\
            secret values passed in as environment variables, so secrets can easily be exposed to any user or entity who has access to the logs."
    impact = "Application code which expects to read secrets in the form of environment variables would need modification"
    remediation = "If possible, rewrite application code to read secrets from mounted secret files, rather than from environment variables."
    

class C_5_4_2:
    title = "Consider external secret storage (Manual)"
    rationale = "Kubernetes supports secrets as first-class objects, but care needs to be taken to ensure that access to secrets is carefully limited.\
                Using an external secrets provider can ease the management of access to secrets, especially where secrets are used across both Kubernetes\
                and non-Kubernetes environments."
    remediation = "Refer to the secrets management options offered by your cloud provider or a third-party secrets management solution."
    
    
class C_5_5_1:
    title = "Configure Image Provenance using ImagePolicyWebhook admission controller (Manual)"
    rationale = "Kubernetes supports plugging in provenance rules to accept or reject the images in your deployments. You could configure such rules to\
                ensure that only approved images are deployed in the cluster."
    impact = "You need to regularly maintain your provenance configuration based on container image updates."
    remediation = "Follow the Kubernetes documentation and setup image provenance."
    

 class C_5_7_1:
    title = "Create administrative boundaries between resources using namespaces (Manual)"
    rationale = "Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. A Kubernetes namespace allows you to\
                partition created resources into logically named groups. Resources created in one namespace can be hidden from other namespaces.\
                By default, each resource created by a user in Kubernetes cluster runs in a default namespace, called default. You can create additional\
                namespaces and attach resources and users to them. You can use Kubernetes Authorization plugins to create policies that segregate access\ 
                to namespace resources between different users."
    remediation = "Follow the documentation and create namespaces for objects in your deployment as you need them."
    

class C_5_7_2:
    title = "Ensure that the seccomp profile is set to docker/default in your pod definitions (Manual)"
    rationale = "Seccomp (secure computing mode) is used to restrict the set of system calls applications can make, allowing cluster administrators\
                greater control over the security of workloads running in the cluster. Kubernetes disables seccomp profiles by default for historical\
                reasons. You should enable it to ensure that the workloads have restricted actions available within the container."
    impact = "If the docker/default seccomp profile is too restrictive for you, you would have to create/manage your own seccomp profiles."
    remediation = "Use security context to enable the docker/default seccomp profile in your pod definitions. An example is as below:"
    command = "securityContext:\
               seccompProfile:\
               type: RuntimeDefault"


class C_5_7_3:
    title = "Apply Security Context to Your Pods and Containers (Manual)"
    rationale = "A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container.\
                When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes.\
                A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the\
                pod/container/volume. There are two levels of security context: pod level security context, and container level security context."
    impact = "If you incorrectly apply security contexts, you may have trouble running the pods."
    remediation = "Follow the Kubernetes documentation and apply security contexts to your pods. For a suggested list of security contexts, you may\
                refer to the CIS Security Benchmark for Docker Containers."


class C_5_7_4:
    title = "The default namespace should not be used (Manual)"
    rationale = "Resources in a Kubernetes cluster should be segregated by namespace, to allow for security controls to be applied at that level and \
                to make it easier to manage resources."
    remediation = "Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace."
    
    
