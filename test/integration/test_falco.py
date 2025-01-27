import logging
import json
import sys
import time
from datetime import datetime, timezone

import pytest
from kubernetes import client, config

from falcotest.falcolib import ensure_extension_not_deployed, get_falco_extension, annotate_shoot, get_latest_supported_falco_version, get_deprecated_falco_version, run_falco_event_generator, falcosidekick_pod_label_selector, falco_extension_deployed, add_falco_to_shoot, remove_falco_from_shoot, wait_for_extension_deployed, wait_for_extension_undeployed, pod_logs_from_label_selector, falco_pod_label_selector, get_falco_sidekick_pods


# from _pytest.config.argparsing import Parser

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def test_falco_deployment(garden_api_client, shoot_api_client, project_namespace, shoot_name):
    
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 

    logger.info("Falco extension is not deployed, deploying")
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name)
    assert error is None
    if error is not None:
        
        #self, status=None, reason=None, http_resp=None
        print("------------------------------------___")
        # print(f"Error: {e.body}")
        body = json.loads(error.body)
        print(type(body))
        print(body)
        print(body["status"])
        if body["message"] == "admission webhook \"validator.admission-shoot-falco-service.extensions.gardener.cloud\" denied the request: chosen version is marked as deprecated":
            print("bingo")
        else:
            print("ooohhch")
            sys.exit(1)

    wait_for_extension_deployed(shoot_api_client)
    
    logger.info("Reading logs from falco pods")
    pod_logs_from_label_selector(shoot_api_client, "kube-system", falco_pod_label_selector)
    
    logger.info("Undepoying falco extension")
    remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
    wait_for_extension_undeployed(shoot_api_client)


def test_falco_deployment_with_all_rules(garden_api_client, shoot_api_client, project_namespace, shoot_name):
    
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
    
    logger.info("Falco extension is not deployed, deploying")
    extension_config = { 
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "resources": "gardener",
            "gardener": {
                "useFalcoRules": True,
                "useFalcoIncubatingRules": True,
                "useFalcoSandboxesRules": True,
            }
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
    
    logger.info("Undepoying falco extension")
    remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
    wait_for_extension_undeployed(shoot_api_client)



def test_all_falco_versions(garden_api_client, shoot_api_client, project_namespace, shoot_name, falco_profile):
    num_versions = len(falco_profile["spec"]["versions"]["falco"])
    logger.info(f"Testing all {num_versions} falco versions for profile")

    for version in falco_profile["spec"]["versions"]["falco"]:
        fv = version["version"]
        logger.info(f"Testing falco version {fv}")
        ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
        
        logger.info("Falco extension is not deployed, deploying")
        error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, fv)
       
        if error is not None:
            body = json.loads(error.body)
            # ensure it is the correct error
            assert body["message"] == "admission webhook \"validator.admission-shoot-falco-service.extensions.gardener.cloud\" denied the request: chosen version is marked as deprecated"
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
        for k,v in logs.items():
            logger.info(f"Logs from {k}: {v}")
            assert f"Falco version: {fv}" in v
            assert "Opening 'syscall' source with modern BPF probe" in v
        logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falcosidekick_pod_label_selector)
        for k,v in logs.items():
            logger.info(f"Logs from {k}: {v}")
            assert "running HTTP server for endpoints defined in tlsserver.notlspaths"

        logger.info("Undepoying falco extension")
        remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
        wait_for_extension_undeployed(shoot_api_client)


def test_event_generator(shoot_api_client):
    logs = run_falco_event_generator(shoot_api_client)
    # something that appears at the start
    assert "syscall.UnprivilegedDelegationOfPageFaultsHandlingToAUserspaceProcess" in logs

    # make sure it is correctly persisted
    logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falcosidekick_pod_label_selector)
    postedOK = False
    for k,v in logs.items():
        postedOK = postedOK or "Webhook - POST OK (200)" in v
    assert postedOK


def test_falco_update_scenario(garden_api_client, falco_profile, shoot_api_client, project_namespace, shoot_name):
    
    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
    
    logger.info("Falco extension is not deployed, deploying")
    fw = get_deprecated_falco_version(falco_profile)
    if fw is None:
        pytest.skip("No deprecated falco version found")
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
        }
    }
    add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)

    wait_for_extension_deployed(shoot_api_client)
    annotate_shoot(garden_api_client, project_namespace, shoot_name, "gardener.cloud/operation=maintain")
    time.sleep(10)
    ext = get_falco_extension(garden_api_client, project_namespace, shoot_name)
    
    assert ext["providerConfig"]["falcoVersion"] == update_candiate

    logger.info("Undepoying falco extension")
    remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
    wait_for_extension_undeployed(shoot_api_client)


def test_no_output(garden_api_client, falco_profile, shoot_api_client, project_namespace, shoot_name):

    ensure_extension_not_deployed(garden_api_client, shoot_api_client, project_namespace, shoot_name) 
    logger.info("Falco extension is not deployed, deploying")

    extension_config = {
        "type": "shoot-falco-service",
        "providerConfig": {
            "apiVersion": "falco.extensions.gardener.cloud/v1alpha1",
            "kind": "FalcoServiceConfig",
            "autoUpdate": True,
            "output": {
                "eventCollector": "none",
                "logFalcoEvents": True
            }
        },
    }
    error = add_falco_to_shoot(garden_api_client, project_namespace, shoot_name, extension_config=extension_config)
    assert error is None

    wait_for_extension_deployed(shoot_api_client)
    pods = get_falco_sidekick_pods(shoot_api_client)
    assert len(pods) == 0
    logger.info("no falcosidekick pods running")
    
    logger.info("Running event generator")
    logs = run_falco_event_generator(shoot_api_client)
    assert "syscall.UnprivilegedDelegationOfPageFaultsHandlingToAUserspaceProcess" in logs
    
    logger.info("Waiting for Falco log to be flushed to log file")
    time.sleep(20)
    logger.info("Making sure expected events are in Falco log")
    logs = pod_logs_from_label_selector(shoot_api_client, "kube-system", falco_pod_label_selector)
    assert "Warning Detected ptrace" in logs
    
    logger.info("Undepoying falco extension")
#    remove_falco_from_shoot(garden_api_client, project_namespace, shoot_name)
#    wait_for_extension_undeployed(shoot_api_client)
