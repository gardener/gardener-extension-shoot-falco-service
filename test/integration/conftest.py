
import pytest
import base64
import yaml
import os
import logging

from kubernetes import config
from kubernetes.client.exceptions import ApiException


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def pytest_addoption(parser):
    parser.addoption(
        "--garden-kubeconfig",
        action="store",
        required=True,
        help="Location of garden kubeconfig file",
    )
    parser.addoption(
        "--project-namespace",
        action="store",
        required=True,
        help="Project namespace of shoot",
    )
    parser.addoption(
        "--shoot-name",
        action="store",
        required=True,
        help="Name of the shoot",
    )


@pytest.fixture(scope="session")
def garden_kubeconfig(pytestconfig):
    if pytestconfig.getoption('--garden-kubeconfig'):
        if not os.path.exists(pytestconfig.getoption('--garden-kubeconfig')):
            pytest.exit("garden-kubeconfig file does not exist.", 1)
        return pytestconfig.getoption('--garden-kubeconfig')
    pytest.exit("Need to specify garden-kubeconfig to test on.", 1)


@pytest.fixture(scope="session")
def project_namespace(pytestconfig):
    if pytestconfig.getoption('--project-namespace'):
        return pytestconfig.getoption('--project-namespace')
    pytest.exit("Need to specify project-namespace to test on.", 1)


@pytest.fixture(scope="session")
def shoot_name(pytestconfig):
    if pytestconfig.getoption('--shoot-name'):
        return pytestconfig.getoption('--shoot-name')
    pytest.exit("Need to specify shoot-name to test on.", 1)


@pytest.fixture(scope="session")
def garden_api_client(garden_kubeconfig):
    return config.new_client_from_config(config_file=garden_kubeconfig)


@pytest.fixture(scope="session")
def shoot_api_client(garden_api_client, project_namespace: str, shoot_name: str):
    request = {
        "spec": {
            "expirationSeconds": 900000
        }
    }
    header_params = {
         "Accept": "application/json, */*"
    }
    auth_settings = ['BearerToken']
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}/adminkubeconfig"
    logger.info(f"Requesting shoot kubeconfig for {project_namespace}/{shoot_name}: {resource_path}")
    data, status, headers = garden_api_client.call_api(
        resource_path=resource_path,
        method="POST",
        header_params=header_params,
        body=request,
        auth_settings=auth_settings,
        response_type=object)
    kubeconfig = base64.b64decode(data["status"]["kubeconfig"])
    kc = yaml.safe_load(kubeconfig)
    return config.new_client_from_config_dict(kc)


@pytest.fixture(scope="session")
def shoot(garden_api_client, project_namespace: str, shoot_name: str):
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
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


@pytest.fixture(scope="session")
def falco_profile(garden_api_client):
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


def pytest_assertrepr_compare(op, left, right):
    # print exception is assertion fails
    if left is not None and isinstance(left, ApiException) and right is None and op == "is":
        return [
            "ApiException is:",
            left.__str__(),
        ]