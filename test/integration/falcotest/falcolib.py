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
from kubernetes import client, config


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

falco_pod_label_selector = "app.kubernetes.io/name=falco"
falcosidekick_pod_label_selector = "app.kubernetes.io/name=falcosidekick"
all_falco_pod_label_selector = "app.kubernetes.io/name in (falco,falcosidekick)"



def pod_logs(shoot_api_client, namespace, pod_name):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.read_namespaced_pod_log(namespace=namespace, name=pod_name)
    return ret


def pod_logs_from_label_selector(shoot_api_client, namespace, label_selector):
    v1 = client.CoreV1Api(shoot_api_client)
    ret = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)
    logs = {}
    for pod in ret.items:
        pod_logs(shoot_api_client, namespace, pod.metadata.name)
        logs[pod.metadata.name] = pod_logs(shoot_api_client, namespace, pod.metadata.name)
    return logs


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

    if "extensions" in data["spec"]:
        extensions = data["spec"]["extensions"]
        for extension in extensions:
            if extension["type"] == "shoot-falco-service":
                return extension
    return None


def _falco_extension_deployed(shoot_spec):
    if "extensions" in shoot_spec["spec"]:
        extensions = shoot_spec["spec"]["extensions"]
        for extension in extensions:
            if extension["type"] == "shoot-falco-service":
                return extension
    return None


def ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace: str, shoot_name: str):
    if falco_extension_deployed(garden_api_client, project_namespace, shoot_name):
        logger.info("Falco extension is deployed, undeploying")
        remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
        wait_for_extension_undeployed(shoot_api_client)


def falco_extension_deployed(garden_api_client, shoot_namespace: str, shoot_name: str):
    extension = get_falco_extension(garden_api_client, shoot_namespace, shoot_name)
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


def remove_falco_from_shoot(garden_api_client, project_namespace: str, shoot_name: str):
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
        header_params = {
            "Accept": "application/json, */*",
            "Content-Type": "application/json-patch+json"
        }
        query_params = {
            "fieldManager": "kubectl-patch"
        }
        # Authentication setting
        auth_settings = ['BearerToken']
        #debug_requests_on()
        resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
        data, status, headers = garden_api_client.call_api(
            resource_path=resource_path,
            method="PATCH",
            header_params=header_params,
            query_params = query_params,
            auth_settings=auth_settings,
            body=patch,
            response_type=object)


def add_falco_to_shoot(garden_api_client, project_namespace: str, shoot_name: str, falco_version=None, extension_config=None):
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

    patch = {
        "spec": {
            "extensions": [ extension_config ]
        }
    }
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    try:
        auth_settings = ['BearerToken']
        data, status, headers = garden_api_client.call_api(
            resource_path=resource_path,
            method="PATCH",
            header_params=header_params,
            auth_settings=auth_settings,
            query_params = query_params,
            body=patch,
            response_type=object)
        
    except client.exceptions.ApiException as e:
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
        query_params = query_params,
        auth_settings=auth_settings,
        body=patch,
        response_type=object)


def wait_for_extension_undeployed(shoot_api_client):
    logger.info("Waiting for falco extension to be undeployed")
    cv1 = client.CoreV1Api(shoot_api_client)
    ls =  all_falco_pod_label_selector
    while True:
        pods = cv1.list_namespaced_pod(namespace="kube-system", label_selector=ls)
        if len(pods.items) == 0:
            logging.info("Falco pods are not running anymore")
            return
        logging.info("Falco pods are still running")
        for pod in pods.items:
            logging.info(f"Pod {pod.metadata.name}:  {pod.status.phase}")
        time.sleep(10)
    

def wait_for_extension_deployed(shoot_api_client):
    logger.info("Waiting for falco extension to be deployed")
    cv1 = client.CoreV1Api(shoot_api_client)
    ls = all_falco_pod_label_selector
    counter = 0
    max_iteratins = 200
    while True and counter <= max_iteratins:
        pods = cv1.list_namespaced_pod(namespace="kube-system", label_selector=ls)
        allRunning = False
        if len(pods.items) != 0:
            allRunning = True
            for pod in pods.items:
                if pod.status.phase != "Running":
                    logging.info(f"Pod {pod.metadata.name} is not running yet")
                    allRunning = False
                    break                
        if not allRunning:
            logging.info("Not all expected falco pods are running or deployed")
            time.sleep(5)
        else:
            logging.info("All falco pods are running, waitig a bit longer to re-check")
            time.sleep(20)
            pods = cv1.list_namespaced_pod(namespace="kube-system", label_selector=ls)
            for pod in pods.items:
                logging.info(f"Pod {pod.metadata.name}:  {pod.status.phase}")
            return
    raise Exception(f"Falco pods are not running or deployed after {max_iteratins} iterations")


def get_falco_profile(garden_api_client, profile_name):
    resource_path = f"/apis/falco.gardener.cloud/v1alpha1/falcoprofiles/falco"
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
    for version in falco_profile["spec"]["versions"]["falco"]:       
        if "expirationDate" in version and version["classification"] == "deprecated":
            expiration_date = datetime.fromisoformat(version["expirationDate"])
            if expiration_date > datetime.now(timezone.utc):
                return version["version"]
        elif version["classification"] == "deprecated":
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
    resource_path = f"/apis/falco.gardener.cloud/v1alpha1/falcoprofiles/falco"
    header_params = {
        "Accept": "application/json, */*"
    }
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="GET",
        header_params=header_params,
        response_type=object)
    return json.loads(data)


def run_falco_event_generator(shoot_api_client):
    cv1 = client.CoreV1Api(shoot_api_client)
    pod = {
        "kind": "Pod",
        "apiVersion":"v1",
        "metadata": {
            "name":"sample-events",
            "labels":{
                "test_falco":"sample-events"
            }
        },
        "spec": {
            "containers": [{
                "name": "sample-events",
                "image": "falcosecurity/event-generator",
                "args": ["run","syscall","--all"],
                "resources": {},
            }],
            "restartPolicy":"Always",
            "dnsPolicy":"ClusterFirst"
        },
    }
    # Create a pod
    pod = cv1.create_namespaced_pod("default", pod)
    logger.info(f"Pod 'sample-events' created. Pod status: {pod.status.phase}")
    time.sleep(10)
    logs = ""
    start = datetime.now()
    while logs.count("\n") < 50 and (datetime.now() - start).seconds < 60:
        logs = pod_logs(shoot_api_client, "default", "sample-events")
        time.sleep(5)

    logger.info(f"Logs: {logs}")
    cv1.delete_namespaced_pod(namespace="default", name="sample-events")
    logger.info("Pod 'sample-events' deleted")
    return logs
