import argparse
import json
import base64
import sys
import yaml
import time
import subprocess
from datetime import datetime, timezone
import logging
import semver
from semver.version import Version
import pprint
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives import serialization
from kubernetes import client, config


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

falco_pod_label_selector = "app.kubernetes.io/name=falco"
falcosidekick_pod_label_selector = "app.kubernetes.io/name=falcosidekick"
all_falco_pod_label_selector = "app.kubernetes.io/name in (falco,falcosidekick)"
minimum_usable_falco_version = Version.parse("0.39.2")


def pod_logs(shoot_api_client, namespace, pod_name):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.read_namespaced_pod_log(
        namespace=namespace,
        name=pod_name,
        limit_bytes=90000000,
        since_seconds=10000, 
        _preload_content=True)
    return ret


def retry_api_call(func, *args, **kwargs):
    counter = 0
    while True:
        try:
            return func(*args, **kwargs)
        except client.exceptions.ApiException as e:
            if e.status == 503:
                counter += 1
                if counter > 10:
                    # give up
                    raise e                
                logger.info("Kubernetes API is not available, retrying...")
                time.sleep(5)
                continue
            else:
                raise e


def pod_logs_from_label_selector(shoot_api_client, namespace, label_selector):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)
    logs = {}
    for pod in ret.items:
        # pod_logs(shoot_api_client, namespace, pod.metadata.name)
        logs[pod.metadata.name] = pod_logs(
                                    shoot_api_client,
                                    namespace,
                                    pod.metadata.name)
    return logs


def get_controllerdeployment(garden_api_client, name):
    resource_path = f"/apis/core.gardener.cloud/v1/controllerdeployments/{name}"
    header_params = {
         "Accept": "application/json, */*"
    }
    # Authentication setting
    auth_settings = ['BearerToken']
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        auth_settings=auth_settings,
        header_params=header_params,
        response_type=object)
    return data


def get_token_lifetime(garden_api_client):
    controller_deployment = get_controllerdeployment(garden_api_client, "extension-shoot-falco-service")
    expiration_date = controller_deployment["helm"]["values"]["falco"]["tokenLifetime"]
    if expiration_date[-1] == 'h':
        expiration_date = int(expiration_date[:-1]) * 3600
    elif str.isnumeric(expiration_date[-1]):
        expiration_date = int(expiration_date)
    else:
        raise Exception("Invalid token lifetime format")
    return expiration_date


def get_token_public_key(garden_api_client):
    controller_deployment = get_controllerdeployment(
                                        garden_api_client,
                                        "extension-shoot-falco-service")
    key_raw = controller_deployment["helm"]["values"]["falco"]["tokenIssuerPrivateKey"].encode('utf-8')
    private_key = serialization.load_pem_private_key(data=key_raw, password=None)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key


def get_configmap(shoot_api_client, namespace, configmap_name):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.read_namespaced_config_map(namespace=namespace, name=configmap_name)
    return ret


def get_secret(shoot_api_client, namespace, secret_name):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.read_namespaced_secret(namespace=namespace, name=secret_name)
    return ret


def get_shoot(garden_api_client, project_namespace: str, shoot_name: str):
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    header_params = {
         "Accept": "application/json, */*"
    }
    # Authentication setting
    auth_settings = ['BearerToken']
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        auth_settings=auth_settings,
        header_params=header_params,
        response_type=object)
    return data

    
def get_falco_extension(garden_api_client, project_namespace: str, shoot_name: str):
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    header_params = {
         "Accept": "application/json, */*"
    }
    # Authentication setting
    auth_settings = ['BearerToken']
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        auth_settings=auth_settings,
        header_params=header_params,
        response_type=object)

    extension_spec = None
    if "extensions" in data["spec"]:
        extensions = data["spec"]["extensions"]
        for extension in extensions:
            if extension["type"] == "shoot-falco-service":
                extension_spec = extension

    custom_rule_resources = None
    rule_resources = []
    if extension_spec is not None and \
            "rules" in extension_spec["providerConfig"] and \
            "custom" in extension_spec["providerConfig"]["rules"]:
        cr = []
        for r in extension_spec["providerConfig"]["rules"]["custom"]:
            cr.append(r["resourceName"])
        custom_rule_resources = set(cr)

    if custom_rule_resources is not None and "resources" in data["spec"]:
        resources = data["spec"]["resources"]
        idx = 0
        for resource in resources:
            if resource["name"] in custom_rule_resources:
                rule_resources.append(idx)
            idx += 1
    return extension_spec, rule_resources


def _falco_extension_deployed(shoot_spec):
    if "extensions" in shoot_spec["spec"]:
        extensions = shoot_spec["spec"]["extensions"]
        for extension in extensions:
            if extension["type"] == "shoot-falco-service":
                return extension
    return None


def ensure_extension_not_deployed(
                    garden_api_client,
                    shoot_api_client,
                    project_namespace: str,
                    shoot_name: str):

    extension, rule_resources = get_falco_extension(
                        garden_api_client,
                        project_namespace,
                        shoot_name)
    if extension is not None:
        logger.info("Falco extension is deployed, undeploying")
        remove_falco_from_shoot(
                            garden_api_client,
                            project_namespace,
                            shoot_name,
                            rule_resources)
        wait_for_extension_undeployed(shoot_api_client)


def falco_extension_deployed(garden_api_client, shoot_namespace: str, shoot_name: str):
    extension, _ = get_falco_extension(garden_api_client, shoot_namespace, shoot_name)
    return extension is not None


def get_shoot_kubeconfig(garden_api_client, project_namespace: str, shoot_name: str):
    request = {
        "spec": {
            "expirationSeconds": 900000
        }
    }
    header_params = {
         "Accept": "application/json, */*"
    }
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}/adminkubeconfig"
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="POST",
        header_params=header_params,
        body=request,
        response_type=object)
    kubeconfig = base64.b64decode(data["status"]["kubeconfig"])
    kc = yaml.safe_load(kubeconfig)
    return config.new_client_from_config_dict(kc)


def remove_falco_from_shoot(garden_api_client, project_namespace: str, shoot_name: str, rule_resources=None):
    shoot = get_shoot(garden_api_client, project_namespace, shoot_name)
    idx= 0
    found = False
    for extension in shoot["spec"]["extensions"]:
        if extension["type"] == "shoot-falco-service":
            found = True
            break
    if found:
        patch = [{
            "op": "remove",
            "path": "/spec/extensions/" + str(idx)
        }]
        if rule_resources is not None:
            res_patch = []
            for idx in rule_resources:
                res_patch.append({
                    "op": "remove",
                    "path": "/spec/resources/" + str(idx)
                })
            res_patch.reverse()
            patch.extend(res_patch)
        logger.debug(f"Removing falco extension from shoot {shoot_name}, patch {patch}")
        header_params = {
            "Accept": "application/json, */*",
            "Content-Type": "application/json-patch+json"
        }
        query_params = {
            "fieldManager": "kubectl-patch"
        }
        # Authentication setting
        auth_settings = ['BearerToken']
        # debug_requests_on()
        resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
        data, status, headers = garden_api_client.call_api(
            resource_path=resource_path,
            method="PATCH",
            header_params=header_params,
            query_params=query_params,
            auth_settings=auth_settings,
            body=patch,
            response_type=object)


def create_configmap(garden_api_client, namespace, name, configmap_data):
    logger.info(f"Creating configmap {name} in namespace {namespace}")
    v1 = client.CoreV1Api(garden_api_client)
    cfg = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=client.V1ObjectMeta(name=name),
        data=configmap_data,
    )
    v1.create_namespaced_config_map(namespace=namespace, body=cfg)


def delete_configmaps(garden_api_client, namespace):
    configmaps = [
        "custom-rules-configmap",
        "rules-map-1",
        "rules-map-2"
    ]
    for n in configmaps:
        v1 = client.CoreV1Api(garden_api_client)
        try:
            v1.delete_namespaced_config_map(namespace=namespace, name=n)
            logger.info(f"ConfigMap {n} deleted")
        except client.exceptions.ApiException as e:
            logger.debug(f"ConfigMap {n} deletion failed: {e}")
            pass


def add_falco_to_shoot(
                garden_api_client,
                project_namespace: str,
                shoot_name: str,
                falco_version=None,
                extension_config=None,
                custom_rules=None):
    shoot = get_shoot(garden_api_client, project_namespace, shoot_name)
    if _falco_extension_deployed(shoot):
        raise Exception("Falco extension already deployed") 
    header_params = {
        "Accept": "application/json, */*",
        "Content-Type": "application/json-patch+json"
    }
    query_params = {
        "fieldManager": "kubectl-patch"
    }
    if extension_config is None:
        extension_config = {
                "type": "shoot-falco-service",
                "providerConfig": {
                    "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
                    "kind": "FalcoServiceConfig"
                }
            }
        if falco_version is not None:
            extension_config["providerConfig"]["falcoVersion"] = falco_version

    custom_rule_resources = []
    custom_rule_configmaps = []
    if custom_rules is not None:
        if type(custom_rules) is str:
            extension_config["providerConfig"]["gardener"]["customRules"] = ["custom-rules"]
            custom_rule_resources = {
                "name": "custom-rules",
                "resourceRef": {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "name": "custom-rules-configmap"
                }
            }
            custom_rule_configmaps.append({
                "name": "custom-rules-configmap",
                "value": {
                    "myrules.yaml": custom_rules
                }
            })
        elif type(custom_rules) is dict:
            extension_config["providerConfig"]["gardener"]["customRules"] = []
            custom_rule_resources = []
            for k, v in custom_rules.items():
                extension_config["providerConfig"]["gardener"]["customRules"].append(k)
                custom_rule_resources.append({
                    "name": k,
                    "resourceRef": {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "name": k
                    }
                })
                custom_rule_configmaps.append(
                    {
                        "name": k,
                        "value": v
                    }
                )
    pretty_config = json.dumps(extension_config, indent=4)
    logger.debug(f"Adding falco extension to shoot:\n{pretty_config}")
    patch = {
        "spec": {
            "extensions": [extension_config]
        }
    }
    if custom_rules is not None:
        patch["spec"]["resources"] = custom_rule_resources
        for cfgmap in custom_rule_configmaps:
            try:
                create_configmap(
                            garden_api_client,
                            project_namespace,
                            cfgmap["name"],
                            cfgmap["value"])
            except client.exceptions.ApiException as e:
                return e

    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    logger.info(f"Adding falco extension to shoot {shoot_name}, resource {resource_path}, patch {patch}")
    try:
        auth_settings = ['BearerToken']
        data, status, headers = garden_api_client.call_api(
            resource_path=resource_path,
            method="PATCH",
            header_params=header_params,
            auth_settings=auth_settings,
            query_params=query_params,
            body=patch,
            response_type=object)
        
    except client.exceptions.ApiException as e:
        logger.error(f"Error adding falco extension to shoot {shoot_name}: {e}")
        return e
    
    return None


def annotate_shoot(garden_api_client, project_namespace: str, shoot_name: str, annotation):
    a = annotation.split("=")
    patch = {
                "metadata":{
                    "annotations":{
                       a[0]: a[1]
                    }
                }
            }
    header_params = {
        "Accept": "application/json, */*",
        "Content-Type": "application/json-patch+json"
    }
    query_params = {
        "fieldManager": "kubectl-patch"
    }
    # Authentication setting
    auth_settings = ['BearerToken']
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="PATCH",
        header_params=header_params,
        query_params=query_params,
        auth_settings=auth_settings,
        body=patch,
        response_type=object)


def wait_for_extension_undeployed(shoot_api_client):
    logger.info("Waiting for falco extension to be undeployed")
    cv1 = client.CoreV1Api(shoot_api_client)
    ls = all_falco_pod_label_selector
    while True:
        pods = cv1.list_namespaced_pod(
                                namespace="kube-system", label_selector=ls)
        if len(pods.items) == 0:
            logging.info("Falco pods are not running anymore")
            return
        logging.info("Falco pods are still running")
        for pod in pods.items:
            logging.info(f"Pod {pod.metadata.name}:  {pod.status.phase}")
        time.sleep(10)


def get_node_count(shoot_api_client):
    cv1 = client.CoreV1Api(shoot_api_client)
    nodes = cv1.list_node()
    return len(nodes.items)


def has_excessive_pod_restarts(shoot_api_client, pods):
    for pod in pods.items:
        if pod.status.restart_count > 2:
            logger.info(f"Pod {pod.metadata.name} has excessive restarts: "
                        f"{pod.status.restart_count}")
            return True
    return False


def all_containers_running(shoot_api_client, ls, pod_count):
    logger.info(f"Checking if all pods ({pod_count}) and containers are "
                "running")
    cv1 = client.CoreV1Api(shoot_api_client)
    try:
        pods = cv1.list_namespaced_pod(
                            namespace="kube-system",
                            label_selector=ls)
    except client.exceptions.ApiException:
        return False

    if len(pods.items) == pod_count:
        for pod in pods.items:
            logger.debug(f"Pod {pod.status}")
            if pod.status.phase != "Running":
                logging.info(f"Pod {pod.metadata.name} is not running yet")
                return False
    else:
        # no pods, not acceptable
        logging.info(f"Only {len(pods.items)} pods found, expected {pod_count}")
        return False

    # check that all containers are running
    for pod in pods.items:
        for container in pod.status.container_statuses:
            if container.state.running is None:
                logging.info(f"Container {container.name} in pod"
                             f"{pod.metadata.name} is not running yet")
                return False
    return True


def wait_for_extension_deployed(shoot_api_client, falcosidekick=True):
    logger.info("Waiting for falco extension to be deployed")
    node_count = get_node_count(shoot_api_client)
    if falcosidekick:
        pod_count = node_count + 2
    else:
        pod_count = node_count
    cv1 = client.CoreV1Api(shoot_api_client)
    ls = all_falco_pod_label_selector
    counter = 0
    max_iteratins = 100
    all_running = False
    while True and counter <= max_iteratins:
        all_running = all_containers_running(
                            shoot_api_client,
                            all_falco_pod_label_selector,
                            pod_count)
        if all_running:
            break
        else:
            counter += 1
            logging.info("Not all expected falco pods are running or deployed")
            time.sleep(5)

    if not all_running:
        raise Exception("Not all expected falco pods are running or deployed")

    logging.info(
                "All falco pods are running, waiting a bit longer "
                "to re-check")
    time.sleep(20)
    pods = cv1.list_namespaced_pod(
                            namespace="kube-system",
                            label_selector=ls)
    if len(pods.items) == 0:
        raise Exception("Falco pods are not running or deployed")
    for pod in pods.items:
        logging.info(f"Pod {pod.metadata.name}:  {pod.status.phase}")
    return


def get_falco_sidekick_pods(shoot_api_client):
    logger.info("Getting falco sidekick pods")
    cv1 = client.CoreV1Api(shoot_api_client)
    ls = falcosidekick_pod_label_selector
    pods = cv1.list_namespaced_pod(namespace="kube-system", label_selector=ls)
    return pods.items


def get_falco_profile(garden_api_client, profile_name):
    resource_path = "/apis/falco.gardener.cloud/v1alpha1/falcoprofiles/falco"
    header_params = {
        "Accept": "application/json, */*"
    }
    auth_settings = ['BearerToken']
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        auth_settings=auth_settings,
        header_params=header_params,
        response_type=object)
    return data


def get_deprecated_falco_version(falco_profile):
    # get falco version that is not the latest supported version
    for version in falco_profile["spec"]["versions"]["falco"]:
        logger.info(f"Version: {version['version']}, ")
        v = Version.parse(version["version"])
        if v < minimum_usable_falco_version:
            continue
        if ("expirationDate" in version and
                version["classification"] == "deprecated"):
            expiration_date = datetime.fromisoformat(version["expirationDate"])
            if expiration_date > datetime.now(timezone.utc):
                return version["version"]
        elif version["classification"] == "deprecated":
            return version["version"]
    
    # try to find an older "supported" version
    latest_supported = Version.parse(get_latest_supported_falco_version(falco_profile))
    for version in falco_profile["spec"]["versions"]["falco"]:
        v = Version.parse(version["version"])
        if v < minimum_usable_falco_version:
            continue
        if version["classification"] == "supported" and v < latest_supported:
            return version["version"]
    return None


def get_latest_supported_falco_version(falco_profile):
    latest_supported = None
    for version in falco_profile["spec"]["versions"]["falco"]:
        if version["classification"] == "supported":
            if latest_supported is None:
                latest_supported = version["version"]
            else:
                if semver.compare(version["version"], latest_supported) > 0:
                    latest_supported = version["version"]
    return latest_supported


def get_falco_profile2(garden_api_client, profile_name):
    resource_path = "/apis/falco.gardener.cloud/v1alpha1/falcoprofiles/falco"
    header_params = {
        "Accept": "application/json, */*"
    }
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        header_params=header_params,
        response_type=object)
    return json.loads(data)


def delete_event_generator_pod(shoot_api_client):
    try:
        cv1 = client.CoreV1Api(shoot_api_client)
        cv1.delete_namespaced_pod(namespace="default", name="sample-events")
        logger.info("Pod 'sample-events' deleted")
    except client.exceptions.ApiException as e:
        logger.debug(f"Pod 'sample-events' not found, ignoring: {e}")
        pass


def run_falco_event_generator(shoot_api_client):
    cv1 = client.CoreV1Api(shoot_api_client)
    pod = {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {
            "name": "sample-events",
            "labels": {
                "test_falco": "sample-events"
            }
        },
        "spec": {
            "containers": [{
                "name": "sample-events",
                "image": "falcosecurity/event-generator",
                "args": ["run", "syscall", "--all"],
                "resources": {},
            }],
            "restartPolicy": "Always",
            "dnsPolicy": "ClusterFirst"
        },
    }
    # Create a pod
    pod = cv1.create_namespaced_pod("default", pod)
    logger.info(f"Pod 'sample-events' created. Pod status: {pod.status.phase}")
    time.sleep(5)
    logs = ""
    start = datetime.now()
    while logs.count("\n") < 50 and (datetime.now() - start).seconds < 60:
        logs += retry_api_call(pod_logs, shoot_api_client, "default", "sample-events")
        time.sleep(1)

    logger.debug(f"Logs: {logs}")

    delete_event_generator_pod(shoot_api_client)
    return logs
