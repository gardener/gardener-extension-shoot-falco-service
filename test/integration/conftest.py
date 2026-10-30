
import pytest
import base64
import yaml
import os
import logging

from kubernetes import config
from kubernetes.client.exceptions import ApiException
from falcotest.falcolib import api_request


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

    # ---------------------------------------------------------------------------
    # AdaptiveResources test options
    # ---------------------------------------------------------------------------
    # Three worker pools with different memory tiers are added temporarily.
    # All pools use minimum=0/maximum=0 so no nodes are actually provisioned —
    # only the DaemonSet resource values are verified.
    #
    # Example AWS machine types:
    #   small:  m5.large   (2 vCPU,  8 GiB) → NodeMemoryGi=8
    #   medium: m5.xlarge  (4 vCPU, 16 GiB) → NodeMemoryGi=16
    #   large:  m5.2xlarge (8 vCPU, 32 GiB) → NodeMemoryGi=32
    #
    # The formula "NodeMemoryGi < 10 ? 200 : (NodeMemoryGi < 20 ? 400 : 800)"
    # produces 200m / 400m / 800m for those three tiers.
    parser.addoption(
        "--adaptive-cloud-profile",
        action="store",
        default=None,
        help="Cloud profile name to add adaptive machine types to (default: read from shoot spec)",
    )
    parser.addoption(
        "--adaptive-machine-small",
        action="store",
        default="m5.large",
        help="Machine type name for the small pool (~8 GiB RAM). Default: m5.large (AWS)",
    )
    parser.addoption(
        "--adaptive-machine-medium",
        action="store",
        default="m5.xlarge",
        help="Machine type name for the medium pool (~16 GiB RAM). Default: m5.xlarge (AWS)",
    )
    parser.addoption(
        "--adaptive-machine-large",
        action="store",
        default="m5.2xlarge",
        help="Machine type name for the large pool (~32 GiB RAM). Default: m5.2xlarge (AWS)",
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
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}/adminkubeconfig"
    logger.info(f"Requesting shoot kubeconfig for {project_namespace}/{shoot_name}: {resource_path}")
    data, status, headers = api_request(
        garden_api_client,
        method="POST",
        resource_path=resource_path,
        header_params=header_params,
        body=request)
    kubeconfig = base64.b64decode(data["status"]["kubeconfig"])
    kc = yaml.safe_load(kubeconfig)
    return config.new_client_from_config_dict(kc)


@pytest.fixture(scope="session")
def shoot(garden_api_client, project_namespace: str, shoot_name: str):
    resource_path = f"/apis/core.gardener.cloud/v1beta1/namespaces/{project_namespace}/shoots/{shoot_name}"
    header_params = {
         "Accept": "application/json, */*"
    }
    data, status, headers = api_request(
        garden_api_client,
        method="GET",
        resource_path=resource_path,
        header_params=header_params)
    return data


@pytest.fixture(scope="session")
def falco_profile(garden_api_client):
    resource_path = "/apis/falco.gardener.cloud/v1alpha1/falcoprofiles/falco"
    header_params = {
        "Accept": "application/json, */*"
    }
    data, status, headers = api_request(
        garden_api_client,
        method="GET",
        resource_path=resource_path,
        header_params=header_params)
    return data


def pytest_assertrepr_compare(op, left, right):
    # print exception is assertion fails
    if left is not None and isinstance(left, ApiException) and right is None and op == "is":
        return [
            "ApiException is:",
            left.__str__(),
        ]


@pytest.fixture(scope="session")
def adaptive_cloud_profile(pytestconfig):
    return pytestconfig.getoption("--adaptive-cloud-profile")


@pytest.fixture(scope="session")
def adaptive_machine_small(pytestconfig):
    return pytestconfig.getoption("--adaptive-machine-small")


@pytest.fixture(scope="session")
def adaptive_machine_medium(pytestconfig):
    return pytestconfig.getoption("--adaptive-machine-medium")


@pytest.fixture(scope="session")
def adaptive_machine_large(pytestconfig):
    return pytestconfig.getoption("--adaptive-machine-large")