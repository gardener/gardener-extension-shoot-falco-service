import logging
import json
import sys
import os
import time
import base64
import yaml
import jwt
from datetime import datetime, timezone

import pytest

from falcotest.falcolib import ensure_extension_not_deployed, get_falco_extension, \
            annotate_shoot, get_latest_supported_falco_version, \
            get_deprecated_falco_version, run_falco_event_generator, \
            falcosidekick_pod_label_selector, pod_logs_from_label_selector, \
            add_falco_to_shoot, wait_for_extension_deployed, \
            falco_pod_label_selector, get_secret, label_node, \
            get_token_lifetime, get_token_public_key, delete_configmaps, \
            delete_event_generator_pod, get_nodes, get_falco_pods, \
            get_falco_sidekick_pods, \
            add_machine_type_to_cloudprofile, remove_machine_type_from_cloudprofile, \
            add_worker_pool_to_shoot, remove_worker_pool_from_shoot, \
            wait_for_daemonsets, wait_for_daemonsets_absent, get_daemonset_resources, \
            wait_for_shoot_reconciled_and_healthy, \
            get_shoot_cloud_profile_name, get_shoot, \
            assert_shoot_system_components_healthy, \
            wait_for_shoot_system_components_healthy, \
            get_daemonset_node_selector, get_daemonset_affinity


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@pytest.fixture(autouse=True)
def run_around_tests(garden_api_client, shoot_api_client, project_namespace, shoot_name):
    logger.info(f"Making sure Falco extension is not deployed in shoot {shoot_name}")
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
    delete_configmaps(garden_api_client, project_namespace)
    delete_event_generator_pod(shoot_api_client)
    yield
    logger.info("Undepoying falco extension")
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name)
    delete_configmaps(garden_api_client, project_namespace)
    delete_event_generator_pod(shoot_api_client)


def test_falco_deployment(
                garden_api_client,
                shoot_api_client,
                project_namespace,
                shoot_name):
    logger.info("Deploying Falco extension")
    custom_rules = {
        "rules-map-1": {
            "file1.yaml":
                """
                # rules file1.yaml
                """,
            "file2.yaml":
                """
                # rules file2.yaml
                """
        },
        "rules-map-2": {
            "file3.yaml":
                """
                # rules file3.yaml
                """,
            "file4.yaml":
                """
                # rules file4.yaml
                """
        }
    }
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "rules": {
                "standard": [
                    "falco-rules"
                ]
            },
            "destinations": [
                {"name": "stdout"},
                {"name": "logging"}
            ]
        }
    }
    error = add_falco_to_shoot(
                garden_api_client,
                project_namespace,
                shoot_name,
                custom_rules=custom_rules,
                extension_config=extension_config)
    assert error is None
    if error is not None:
        body = json.loads(error.body)
        if body["message"] == \
                "admission webhook \"validator.admission-shoot-falco-service.extensions.gardener.cloud\" " \
                "denied the request: chosen version is marked as deprecated":
            print("bingo")
        else:
            print("ooohhch")
            sys.exit(1)

    wait_for_extension_deployed(shoot_api_client)
    logger.info("Reading logs from falco pods")
    logs = pod_logs_from_label_selector(
                                shoot_api_client,
                                "kube-system",
                                falco_pod_label_selector)
    for k, v in logs.items():
        logger.info(f"Logs from {k}\n{v}")
        assert "/etc/falco/rules.d/file1.yaml" in v
        assert "/etc/falco/rules.d/file2.yaml" in v
        assert "/etc/falco/rules.d/file3.yaml" in v
        assert "/etc/falco/rules.d/file4.yaml" in v
    logger.info("checking access token")
    secret = get_secret(
                shoot_api_client,
                "kube-system",
                "gardener-falcosidekick")
    token = secret.data["token"]
    token_decoded = str(base64.b64decode(token), "utf-8")
    assert token_decoded.count(".") == 2

    logger.info("Running event generator")
    logs = run_falco_event_generator(shoot_api_client)
    # something that appears at the start
    assert "action executed" in logs

    # make sure it is correctly persisted
    logs = pod_logs_from_label_selector(
        shoot_api_client,
        "kube-system",
        falcosidekick_pod_label_selector)
    postedOK = False
    assert len(logs) > 0

    dev_env = os.getenv("FALCO_DEV_ENVIRONMENT")
    if dev_env is not None:
        # cental logging does not work in dev environment
        for k, v in logs.items():
            logger.debug(v)
            postedOK = postedOK or "Webhook - POST OK (200)" in v
        time.sleep(5000)
        assert postedOK

    if dev_env is not None:
        # this test works only in the dev environment due to lack of 
        # access in the test environment
        logger.info("checking access token")
        secret = get_secret(shoot_api_client, "kube-system", "falcosidekick")
        configyaml = secret.data["config.yaml"]
        logger.info(f"config.yaml: {configyaml}")
        falcosidekickcfg = yaml.safe_load(configyaml)
        headers64 = falcosidekickcfg["webhook"]["customHeaders"]["Authorization"]
        headers = str(base64.b64decode(headers64), "utf-8")
        encoded_token = headers.split(":")[1].split(" ")[1].strip()

        key = get_token_public_key(garden_api_client)
        tok = jwt.decode(encoded_token, key=key, verify_signature=True,
                         algorithms=["RS256"], audience="falco-db")
        logger.info("access token is valid")
        expiration = int(tok["exp"])
        now = int(time.time())
        token_lifetime = get_token_lifetime(garden_api_client)  
        assert expiration <= token_lifetime + now
        logger.info("access token has expected lifetime")
        assert expiration >= now + token_lifetime - (30*60)
        logger.info("access token has almost full lifetime")


def test_falco_deployment_with_all_rules(garden_api_client, shoot_api_client, project_namespace, shoot_name):    
    logger.info("Deploying Falco extension")
    extension_config = { 
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "rules": {
                "standard": [
                "falco-rules",
                "falco-incubating-rules",
                "falco-sandbox-rules"
                ]
            },
        }
    }
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)
    assert error is None
    # if error is not None:
        
    #     #self, status=None, reason=None, http_resp=None
    #     print("------------------------------------___")
    #     # print(f"Error: {e.body}")
    #     body = json.loads(error.body)
    #     print(type(body))
    #     print(body)
    #     print(body["status"])
    #     if body["message"] == "admission webhook \"validator.admission-shoot-falco-service.extensions.gardener.cloud\" denied the request: chosen version is marked as deprecated":
    #         print("bingo")
    #     else:
    #         print("ooohhch")
    #         sys.exit(1)

    wait_for_extension_deployed(shoot_api_client)
    
    logger.info("Reading logs from falco pods")
    logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falco_pod_label_selector)
    for l in logs.values():
        assert "/etc/falco/rules.d/falco_rules.yaml" in l
        assert "/etc/falco/rules.d/falco-incubating_rules.yaml" in l
        assert "/etc/falco/rules.d/falco-sandbox_rules.yaml" in l


def test_all_falco_versions(garden_api_client, shoot_api_client, project_namespace, shoot_name, falco_profile):
    num_versions = len(falco_profile["spec"]["versions"]["falco"])
    logger.info(f"Testing all {num_versions} falco versions for profile")

    for version in falco_profile["spec"]["versions"]["falco"]:
        fv = version["version"]
        logger.info(f"Testing falco version {fv}")
        ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
        delete_configmaps(garden_api_client, project_namespace)

        logger.info("Falco extension is not deployed, deploying")
        error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, fv)

        if error is not None:
            body = json.loads(error.body)
            # ensure it is the correct error
            assert body["message"] == \
                    "admission webhook \"validator.admission-shoot-falco-service.extensions.gardener.cloud\" " \
                    "denied the request: chosen version is marked as deprecated"
            # and the version is really expired
            if "expirationDate" in version:
                expiration_date = datetime.fromisoformat(version["expirationDate"])
                assert expiration_date < datetime.now(timezone.utc)
            else:
                pytest.fail(f"Falco version {fv} deployment failed with expiration error but version is not expired.")
            logger.info(f"Falco version {fv} is expired, skipping")
            continue

        wait_for_extension_deployed(shoot_api_client)

        logger.info("Reading and checking logs from falco/falcosidekick pods")
        logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falco_pod_label_selector)
        for k, v in logs.items():
            logger.info(f"Logs from {k}: {v}")
            assert f"Falco version: {fv}" in v
            assert "Opening 'syscall' source with modern BPF probe" in v
        logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falcosidekick_pod_label_selector)
        for k, v in logs.items():
            logger.info(f"Logs from {k}: {v}")
            assert "running HTTP server for endpoints defined in tlsserver.notlspaths"


def test_event_generator(
            garden_api_client,
            shoot_api_client,
            project_namespace,
            shoot_name):
    logger.info("Deploying Falco extension")
    extension_config = { 
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "rules": {
                "standard": [
                    "falco-rules",
                    "falco-incubating-rules",
                    "falco-sandbox-rules"
                ]
            },
            "destinations": [{
                "name": "logging",
            }, {
                "name": "stdout"
            }],
        }
    }
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)
    assert error is None
    wait_for_extension_deployed(shoot_api_client)

    logs = run_falco_event_generator(shoot_api_client)
    # something that appears at the start
    assert "action executed" in logs

    # make sure it is correctly persisted
    logs = pod_logs_from_label_selector(
        shoot_api_client,
        "kube-system", 
        falcosidekick_pod_label_selector)
    postedOK = False
    for k, v in logs.items():
        postedOK = postedOK or " Loki - POST OK" in v
    assert postedOK


@pytest.mark.skip(reason="this is done with the previous test")
def test_event_generator_to_loki(
    garden_api_client, shoot_api_client, project_namespace, shoot_name
):
    logger.info("Deploying Falco extension")
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "rules": {
                "standard": [
                    "falco-rules",
                    "falco-incubating-rules",
                    "falco-sandbox-rules"
                ]
            },
            "destinations": [
                {
                    "name": "loki",
                },
                {
                    "name": "stdout",
                }
            ],
        },
    }
    error = add_falco_to_shoot(
        garden_api_client,
        project_namespace,
        shoot_name,
        extension_config=extension_config,
    )
    assert error is None
    wait_for_extension_deployed(shoot_api_client)

    logs = run_falco_event_generator(shoot_api_client)
    # something that appears at the start
    assert (
        "syscall.Ptrace" in logs
    )

    # make sure it is correctly persisted
    logs = pod_logs_from_label_selector(
        shoot_api_client, "kube-system", falcosidekick_pod_label_selector
    )
    postedOK = False
    for _, v in logs.items():
        postedOK = postedOK or "Loki - POST OK (204)" in v
    assert postedOK


@pytest.mark.skip(reason="this is hard as we rarely have deprecated versions")
def test_falco_update_scenario(garden_api_client, falco_profile, shoot_api_client, project_namespace, shoot_name):
    logger.info("Deploying Falco extension")
    fw = get_deprecated_falco_version(falco_profile)
    if fw is None:
        pytest.skip("No deprecated falco version found")
    logger.info(f"Using deprecated Falco version {fw}")
    update_candiate = get_latest_supported_falco_version(falco_profile)
    if update_candiate is None:
        pytest.skip("No supported falco version found")

    logger.info(f"Deploying Falco version {fw} to shoot and expecting update to {update_candiate}")
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "falcoVersion": fw,
            "autoUpdate": True,
        },
    }
    err = add_falco_to_shoot(
        garden_api_client,
        project_namespace,
        shoot_name,
        extension_config=extension_config,
    )
    assert err is None
    wait_for_extension_deployed(shoot_api_client)
    annotate_shoot(
        garden_api_client,
        project_namespace,
        shoot_name,
        "gardener.cloud/operation=maintain",
    )

    max_tries = 10
    wait_seconds = 10
    for i in range(max_tries):
        (ext, rule_resources) = get_falco_extension(garden_api_client, project_namespace, shoot_name)
        assert ext is not None
        if ext["providerConfig"]["falcoVersion"] != update_candiate:
            logger.info(
                f"Falco version is {ext['providerConfig']['falcoVersion']}, "
                f"waiting {(max_tries-i-1)*wait_seconds} more seconds"
            )
            time.sleep(wait_seconds)
            annotate_shoot(
                garden_api_client,
                project_namespace,
                shoot_name,
                "gardener.cloud/operation=maintain",
            )
            continue
        else:
            break

    (ext, rule_resources) = get_falco_extension(garden_api_client, project_namespace, shoot_name)
    assert ext is not None
    assert ext["providerConfig"]["falcoVersion"] == update_candiate
    logger.info(f"Falco version updated as expected from {fw} to {update_candiate}")


def test_no_output(garden_api_client, shoot_api_client, project_namespace: str, shoot_name: str):
    logger.info("Deploying Falco extension")
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "autoUpdate": True,
            "destinations": [
                {
                    "name": "stdout",
                }
            ],
        },
    }
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)
    assert error is None

    wait_for_extension_deployed(shoot_api_client, expect_sidekick=False)
    pods = get_falco_sidekick_pods(shoot_api_client)
    assert len(pods) == 0, "Falcosidekick pods should not be running if stdout is configured"

    logger.info("Running event generator")
    logs = run_falco_event_generator(shoot_api_client)
    assert "action executed" in logs, "Event generator did not run as expected"

    logger.info("Waiting for Falco log to be flushed to log file")
    time.sleep(10)

    logger.info("Making sure expected events are in Falco log")
    logs = pod_logs_from_label_selector(
                    shoot_api_client,
                    "kube-system",
                    falco_pod_label_selector,
                    container_name="falco")
    allLogs = ""
    for _, lines in logs.items():
        allLogs += lines
    print(allLogs)
    assert "Warning Detected ptrace" in allLogs, "Falco log does not contain expected event"


def test_cluster_purpose(garden_api_client, shoot_api_client, shoot, project_namespace: str, shoot_name: str):
    logger.info("Deploying Falco extension to verify cluster_purpose customfield")
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "destinations": [
                {"name": "stdout"},
                {"name": "logging"},
            ],
        },
    }
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)
    assert error is None

    wait_for_extension_deployed(shoot_api_client)

    expected_purpose = shoot.get("spec", {}).get("purpose")
    assert expected_purpose is not None, "Shoot has no spec.purpose set"

    secret = get_secret(shoot_api_client, "kube-system", "falcosidekick")
    config_yaml_b64 = secret.data["config.yaml"]
    config_yaml = str(base64.b64decode(config_yaml_b64), "utf-8")
    sidekick_cfg = yaml.safe_load(config_yaml)

    actual_purpose = sidekick_cfg.get("customfields", {}).get("cluster_purpose")
    assert actual_purpose == expected_purpose, \
        f"cluster_purpose mismatch: expected '{expected_purpose}', got '{actual_purpose}'"
    logger.info(f"cluster_purpose correctly set to '{expected_purpose}'")


def test_node_selector(garden_api_client, shoot_api_client, project_namespace: str, shoot_name: str):
    logger.info("Check at least two nodes are available")
    nodes = get_nodes(shoot_api_client)
    if len(nodes) < 2:
        pytest.skip("At least two nodes are required for this test")

    node_to_deploy = nodes[0].metadata.name
    label_name = "deploy-falco-here"
    label = {label_name: "true"}

    logger.info(f"Labeling node {node_to_deploy} with {label}")
    label_node(
        shoot_api_client,
        node_to_deploy,
        label,
    )
    logger.info(f"Node {node_to_deploy} labeled with {label}")

    logger.info("Deploying Falco extension")
    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "nodeSelector": {
                label_name: "true",
            },
            "destinations": [
                {
                    "name": "stdout",
                }
            ],
        },
    }

    error = add_falco_to_shoot(
        garden_api_client,
        project_namespace,
        shoot_name,
        extension_config=extension_config,
    )
    assert error is None

    wait_for_extension_deployed(shoot_api_client, expect_sidekick=False, number_falco_pods=1)

    pods = get_falco_pods(shoot_api_client)
    assert len(pods) > 0, "No Falco pods found"

    for pod in pods:
        if pod.spec.node_name == node_to_deploy:
            logger.info(f"Found Falco pod {pod.metadata.name} on labeled node {node_to_deploy}")
        else:
            logger.info(f"Found Falco pod {pod.metadata.name} on node {pod.spec.node_name}")
            assert False, f"Falco pod {pod.metadata.name} is fond on unlabeled node {node_to_deploy}"

    logger.info("Removing label from node")
    label_node(
        shoot_api_client,
        node_to_deploy,
        None,
    )

    logger.info("Undeploying falco extension")
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name)


# ---------------------------------------------------------------------------
# AdaptiveResources integration tests
# ---------------------------------------------------------------------------
#
# These tests add three temporary worker pools (min=max=0) with different
# memory tiers.  No real VMs are provisioned; the tests verify the DaemonSet
# specs rendered by the extension — resource values, nodeSelectors, affinity.
#
# The machine types must exist in the cloud profile (or be auto-added via
# placeholder capacity).  Only the machine type capacity metadata is used;
# no nodes are actually scheduled.
#
# Required pytest options (skip tests if absent):
#   --adaptive-machine-small   machine type name with ~4-8 GiB RAM
#   --adaptive-machine-medium  machine type name with ~8-16 GiB RAM
#   --adaptive-machine-large   machine type name with >16 GiB RAM
#
# Formula used across both tests:
#   cpuRequest:    NodeMemoryGi < 10 ? 200 : (NodeMemoryGi < 20 ? 400 : 800)
#   memoryRequest: NodeMemoryGi * 8
#
# Expected results for the default placeholder capacities (8/16/32 GiB):
#   small  (8 GiB)  → cpu=200m, memory=64Mi
#   medium (16 GiB) → cpu=400m, memory=128Mi
#   large  (32 GiB) → cpu=800m, memory=256Mi

# Threshold and formula constants, expressed in terms of NodeMemoryGi so that
# the same logic works for any three tiers satisfying the tier boundaries below.
_CPU_FORMULA = "NodeMemoryGi < 10 ? 200 : (NodeMemoryGi < 20 ? 400 : 800)"
_MEM_FORMULA = "NodeMemoryGi * 8"

# Worker-pool names added temporarily by the adaptive tests (max 15 bytes each).
_POOL_SMALL  = "falco-sm"
_POOL_MEDIUM = "falco-md"
_POOL_LARGE  = "falco-lg"


# Per-test-run set of machine type names that were added by _setup_adaptive_pools
# and therefore must be removed by _teardown_adaptive_pools.  Populated at
# setup time so teardown does not need to inspect the cloud profile.
_added_machine_types: set[str] = set()


def _make_worker_pool(pool_name, machine_type, template: dict = None):
    """Build a worker pool spec, optionally inheriting provider fields from a template pool."""
    pool = {
        "name": pool_name,
        "machine": {"type": machine_type},
        "cri": {"name": "containerd"},
        "minimum": 0,
        "maximum": 0,
        "maxSurge": 1,
        "maxUnavailable": 0,
    }
    if template:
        # Inherit provider-required fields that vary by cloud provider.
        for key in ("volume", "zones", "providerConfig"):
            if key in template:
                pool[key] = template[key]
        # Inherit machine image from template if not overriding machine type image.
        if "machine" in template and "image" in template["machine"]:
            pool["machine"]["image"] = template["machine"]["image"]
    return pool


# Placeholder capacity for machine types that do not yet exist in the cloud
# profile (e.g. on a local/fake provider).  Keyed by the three tier names
# passed via --adaptive-machine-small/medium/large at setup time.
_PLACEHOLDER_CAPACITY = {
    "small":  {"cpu": "2",  "memory": "8Gi"},
    "medium": {"cpu": "4",  "memory": "16Gi"},
    "large":  {"cpu": "8",  "memory": "32Gi"},
}


def _setup_adaptive_pools(garden_api_client, project_namespace, shoot_name,
                          cloud_profile_name, small_type, medium_type, large_type):
    """Add machine types (if missing) and worker pools (min=max=0, no VMs provisioned).

    add_machine_type_to_cloudprofile is idempotent: it returns False (and skips
    the patch) when the type is already present.  We track which types were
    actually added so teardown can remove them without inspecting the cloud profile.
    """
    global _added_machine_types
    _added_machine_types = set()

    for tier, mt_name in [("small", small_type), ("medium", medium_type), ("large", large_type)]:
        cap = _PLACEHOLDER_CAPACITY[tier]
        entry = {
            "name":         mt_name,
            "cpu":          cap["cpu"],
            "gpu":          "0",
            "memory":       cap["memory"],
            "architecture": "amd64",
            "usable":       True,
        }
        added = add_machine_type_to_cloudprofile(garden_api_client, cloud_profile_name, entry)
        if added:
            _added_machine_types.add(mt_name)
            logger.info(f"Added machine type {mt_name} to cloud profile {cloud_profile_name}")
        else:
            logger.info(f"Machine type {mt_name} already in cloud profile {cloud_profile_name}, will not remove on teardown")

    for pool_name, machine_type in [
        (_POOL_SMALL,  small_type),
        (_POOL_MEDIUM, medium_type),
        (_POOL_LARGE,  large_type),
    ]:
        # Read a fresh copy of the shoot each time in case workers list changed.
        shoot = get_shoot(garden_api_client, project_namespace, shoot_name)
        existing_workers = shoot["spec"]["provider"].get("workers", [])
        template = existing_workers[0] if existing_workers else None
        add_worker_pool_to_shoot(
            garden_api_client, project_namespace, shoot_name,
            _make_worker_pool(pool_name, machine_type, template))


def _teardown_adaptive_pools(garden_api_client, project_namespace, shoot_name,
                             cloud_profile_name, small_type, medium_type, large_type):
    """Remove worker pools, wait for reconcile, then remove machine types we added."""
    ensure_extension_not_deployed(garden_api_client, None, project_namespace, shoot_name)
    for pool_name in [_POOL_SMALL, _POOL_MEDIUM, _POOL_LARGE]:
        remove_worker_pool_from_shoot(
            garden_api_client, project_namespace, shoot_name, pool_name)
    wait_for_shoot_reconciled_and_healthy(garden_api_client, project_namespace, shoot_name)

    # Only remove machine types that this test run added (not pre-existing types).
    for mt_name in _added_machine_types:
        remove_machine_type_from_cloudprofile(garden_api_client, cloud_profile_name, mt_name)


def test_adaptive_resources(
    garden_api_client,
    shoot_api_client,
    project_namespace,
    shoot_name,
    adaptive_cloud_profile,
    adaptive_machine_small,
    adaptive_machine_medium,
    adaptive_machine_large,
):
    """Deploy Falco with per-pool DaemonSets sized by formula expressions.

    Scenario
    --------
    Three temporary worker pools (min=max=0) are added to the shoot — no VMs
    are provisioned.  The FalcoServiceConfig sets a global cpuRequest formula
    that produces distinct values for each memory tier based on the machine
    type capacity recorded in the cloud profile:

        NodeMemoryGi < 10  → 200m   (small,  8 GiB placeholder)
        NodeMemoryGi < 20  → 400m   (medium, 16 GiB placeholder)
        else               → 800m   (large,  32 GiB placeholder)

    Verifications
    -------------
    1. Per-pool DaemonSets falco-<pool> are created; the monolithic 'falco'
       DaemonSet is absent.
    2. The falco-default DaemonSet (DoesNotExist affinity) exists.
    3. Each per-pool DaemonSet carries the correct nodeSelector.
    4. cpuRequest and memoryRequest on each DaemonSet match the formula output
       for that pool's machine-type capacity (read from cloud profile metadata,
       no actual nodes needed).
    5. After reconcile the shoot's SystemComponentsHealthy condition is True.
    6. Full teardown removes all per-pool DaemonSets.
    """
    if not all([adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large]):
        pytest.skip(
            "Adaptive resources test requires --adaptive-machine-small, "
            "--adaptive-machine-medium, and --adaptive-machine-large"
        )

    cloud_profile = adaptive_cloud_profile or get_shoot_cloud_profile_name(
        garden_api_client, project_namespace, shoot_name)
    assert cloud_profile, "Could not determine cloud profile name"

    logger.info(
        f"test_adaptive_resources: cloud_profile={cloud_profile} "
        f"small={adaptive_machine_small} medium={adaptive_machine_medium} "
        f"large={adaptive_machine_large}"
    )

    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name)

    _setup_adaptive_pools(
        garden_api_client, project_namespace, shoot_name,
        cloud_profile,
        adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large,
    )

    try:
        # ------------------------------------------------------------------
        # Deploy Falco with formula-based resources
        # ------------------------------------------------------------------
        extension_config = {
            "type": "shoot-falco-service",
            "providerConfig": {
                "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
                "kind": "FalcoServiceConfig",
                "rules": {"standard": ["falco-rules"]},
                "destinations": [{"name": "stdout"}],
                "falcoConfig": {
                    "resources": {
                        "requests": {
                            "cpu":    _CPU_FORMULA,
                            "memory": _MEM_FORMULA,
                        }
                    }
                },
            },
        }
        error = add_falco_to_shoot(
            garden_api_client, project_namespace, shoot_name,
            extension_config=extension_config)
        assert error is None, f"add_falco_to_shoot failed: {error}"

        wait_for_shoot_reconciled_and_healthy(garden_api_client, project_namespace, shoot_name)

        # ------------------------------------------------------------------
        # 1. Per-pool DaemonSets exist; monolithic 'falco' is absent
        # ------------------------------------------------------------------
        expected_ds = [
            f"falco-{_POOL_SMALL}",
            f"falco-{_POOL_MEDIUM}",
            f"falco-{_POOL_LARGE}",
            "falco-default",
        ]
        wait_for_daemonsets(shoot_api_client, expected_ds, timeout_seconds=300)
        wait_for_daemonsets_absent(shoot_api_client, ["falco"], timeout_seconds=120)
        logger.info("Per-pool DaemonSets present; monolithic DaemonSet absent")

        # ------------------------------------------------------------------
        # 2. falco-default has DoesNotExist affinity on worker-pool label
        # ------------------------------------------------------------------
        affinity = get_daemonset_affinity(shoot_api_client, "falco-default")
        assert affinity is not None, "falco-default has no affinity"
        terms = (
            affinity.node_affinity
            .required_during_scheduling_ignored_during_execution
            .node_selector_terms
        )
        expressions = terms[0].match_expressions
        does_not_exist = any(
            e.key == "worker.gardener.cloud/pool" and e.operator == "DoesNotExist"
            for e in expressions
        )
        assert does_not_exist, (
            "falco-default does not have DoesNotExist affinity on worker.gardener.cloud/pool"
        )
        logger.info("falco-default affinity correct")

        # ------------------------------------------------------------------
        # 3. Per-pool DaemonSets carry the correct nodeSelector
        # ------------------------------------------------------------------
        for pool_name in [_POOL_SMALL, _POOL_MEDIUM, _POOL_LARGE]:
            ds_name = f"falco-{pool_name}"
            ns = get_daemonset_node_selector(shoot_api_client, ds_name)
            assert ns.get("worker.gardener.cloud/pool") == pool_name, (
                f"{ds_name}: expected nodeSelector worker.gardener.cloud/pool={pool_name}, got {ns}"
            )
        logger.info("Per-pool DaemonSet nodeSelectors correct")

        # ------------------------------------------------------------------
        # 4. Resource values match formula output for each machine-type tier
        #
        # Formula: NodeMemoryGi < 10 → 200m; < 20 → 400m; else → 800m
        # Memory:  NodeMemoryGi * 8  → 64Mi / 128Mi / 256Mi
        # ------------------------------------------------------------------
        expected_resources = {
            _POOL_SMALL:  {"cpu": "200m", "memory": "64Mi"},   # 8 GiB tier
            _POOL_MEDIUM: {"cpu": "400m", "memory": "128Mi"},  # 16 GiB tier
            _POOL_LARGE:  {"cpu": "800m", "memory": "256Mi"},  # 32 GiB tier
        }
        for pool_name, want in expected_resources.items():
            ds_name = f"falco-{pool_name}"
            resources = get_daemonset_resources(shoot_api_client, ds_name)
            logger.info(f"{ds_name} resources: {resources}")
            requests = resources.get("requests", {})
            assert requests.get("cpu") == want["cpu"], (
                f"{ds_name}: expected cpuRequest={want['cpu']}, got {requests.get('cpu')}"
            )
            assert requests.get("memory") == want["memory"], (
                f"{ds_name}: expected memoryRequest={want['memory']}, got {requests.get('memory')}"
            )
        logger.info("Per-pool DaemonSet resource values correct")

        # ------------------------------------------------------------------
        # 5. Shoot SystemComponentsHealthy=True (extension health check)
        # ------------------------------------------------------------------
        wait_for_shoot_system_components_healthy(
            garden_api_client, project_namespace, shoot_name, timeout_seconds=180)
        assert_shoot_system_components_healthy(
            garden_api_client, project_namespace, shoot_name)
        logger.info("SystemComponentsHealthy=True confirmed")

        # ------------------------------------------------------------------
        # 6. Teardown: all adaptive DaemonSets disappear
        # ------------------------------------------------------------------
        ensure_extension_not_deployed(
            garden_api_client, shoot_api_client, project_namespace, shoot_name)
        wait_for_daemonsets_absent(
            shoot_api_client,
            expected_ds + ["falco"],
            timeout_seconds=180,
        )
        logger.info("All adaptive DaemonSets removed after teardown")

    finally:
        _teardown_adaptive_pools(
            garden_api_client, project_namespace, shoot_name,
            cloud_profile,
            adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large,
        )


def test_adaptive_resources_per_pool_override(
    garden_api_client,
    shoot_api_client,
    project_namespace,
    shoot_name,
    adaptive_cloud_profile,
    adaptive_machine_small,
    adaptive_machine_medium,
    adaptive_machine_large,
):
    """Deploy Falco with a global literal resource default and a per-pool override.

    Scenario
    --------
    The FalcoServiceConfig sets:
      - falcoConfig.resources: literal default cpuRequest=150m, memoryRequest=128Mi
      - falcoConfig.workerPoolResources[falco-test-large]: cpuRequest=900m

    Verifications
    -------------
    1. falco-<small> and falco-<medium> DaemonSets use the global default: 150m / 128Mi.
    2. falco-<large> DaemonSet uses the per-pool override: 900m / 128Mi (memory
       falls back to the global default because it is not overridden).
    3. falco-default DaemonSet uses chart defaults (no resources injected, since
       falco-default has no machine type context and inherits nothing).
    4. SystemComponentsHealthy=True after reconcile.
    """
    if not all([adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large]):
        pytest.skip(
            "Adaptive resources test requires --adaptive-machine-small, "
            "--adaptive-machine-medium, and --adaptive-machine-large"
        )

    cloud_profile = adaptive_cloud_profile or get_shoot_cloud_profile_name(
        garden_api_client, project_namespace, shoot_name)
    assert cloud_profile, "Could not determine cloud profile name"

    logger.info(
        f"test_adaptive_resources_per_pool_override: cloud_profile={cloud_profile} "
        f"small={adaptive_machine_small} medium={adaptive_machine_medium} "
        f"large={adaptive_machine_large}"
    )

    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name)

    _setup_adaptive_pools(
        garden_api_client, project_namespace, shoot_name,
        cloud_profile,
        adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large,
    )

    try:
        # ------------------------------------------------------------------
        # Deploy Falco: global literal default + per-pool override for large
        # ------------------------------------------------------------------
        extension_config = {
            "type": "shoot-falco-service",
            "providerConfig": {
                "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
                "kind": "FalcoServiceConfig",
                "rules": {"standard": ["falco-rules"]},
                "destinations": [{"name": "stdout"}],
                "falcoConfig": {
                    "resources": {
                        "requests": {
                            "cpu":    "150m",
                            "memory": "128Mi",
                        }
                    },
                    "workerPoolResources": {
                        _POOL_LARGE: {
                            "requests": {
                                "cpu": "900m",
                                # memory intentionally omitted — should fall back
                                # to the global default of 128Mi
                            }
                        }
                    },
                },
            },
        }
        error = add_falco_to_shoot(
            garden_api_client, project_namespace, shoot_name,
            extension_config=extension_config)
        assert error is None, f"add_falco_to_shoot failed: {error}"

        wait_for_shoot_reconciled_and_healthy(garden_api_client, project_namespace, shoot_name)

        expected_ds = [
            f"falco-{_POOL_SMALL}",
            f"falco-{_POOL_MEDIUM}",
            f"falco-{_POOL_LARGE}",
            "falco-default",
        ]
        wait_for_daemonsets(shoot_api_client, expected_ds, timeout_seconds=300)

        # ------------------------------------------------------------------
        # 1. small and medium use the global default
        # ------------------------------------------------------------------
        for pool_name in [_POOL_SMALL, _POOL_MEDIUM]:
            ds_name = f"falco-{pool_name}"
            resources = get_daemonset_resources(shoot_api_client, ds_name)
            logger.info(f"{ds_name} resources: {resources}")
            requests = resources.get("requests", {})
            assert requests.get("cpu") == "150m", (
                f"{ds_name}: expected global default cpuRequest=150m, got {requests.get('cpu')}"
            )
            assert requests.get("memory") == "128Mi", (
                f"{ds_name}: expected global default memoryRequest=128Mi, got {requests.get('memory')}"
            )
        logger.info("Small and medium pools use global default resources")

        # ------------------------------------------------------------------
        # 2. large uses the per-pool override for cpu; memory falls back to global
        # ------------------------------------------------------------------
        large_ds = f"falco-{_POOL_LARGE}"
        resources = get_daemonset_resources(shoot_api_client, large_ds)
        logger.info(f"{large_ds} resources: {resources}")
        requests = resources.get("requests", {})
        assert requests.get("cpu") == "900m", (
            f"{large_ds}: expected per-pool override cpuRequest=900m, got {requests.get('cpu')}"
        )
        assert requests.get("memory") == "128Mi", (
            f"{large_ds}: expected global default memoryRequest=128Mi (not overridden), "
            f"got {requests.get('memory')}"
        )
        logger.info("Large pool uses per-pool cpu override with global memory fallback")

        # ------------------------------------------------------------------
        # 3. falco-default does not carry injected resource values
        #    (uses chart defaults; no machine type context for evaluation)
        # ------------------------------------------------------------------
        default_resources = get_daemonset_resources(shoot_api_client, "falco-default")
        logger.info(f"falco-default resources: {default_resources}")
        if default_resources.get("requests"):
            for key in ("cpu", "memory"):
                val = default_resources["requests"].get(key, "")
                assert val not in ("150m", "128Mi", "900m"), (
                    f"falco-default should not inherit injected resource values, "
                    f"but found requests.{key}={val}"
                )
        logger.info("falco-default uses chart defaults (no injected resource values)")

        # ------------------------------------------------------------------
        # 4. SystemComponentsHealthy=True
        # ------------------------------------------------------------------
        wait_for_shoot_system_components_healthy(
            garden_api_client, project_namespace, shoot_name, timeout_seconds=180)
        assert_shoot_system_components_healthy(
            garden_api_client, project_namespace, shoot_name)
        logger.info("SystemComponentsHealthy=True confirmed")

    finally:
        _teardown_adaptive_pools(
            garden_api_client, project_namespace, shoot_name,
            cloud_profile,
            adaptive_machine_small, adaptive_machine_medium, adaptive_machine_large,
        )
