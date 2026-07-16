#!/usr/bin/env python3

import json
import sys
import urllib.request
import urllib.error
import yaml


def get_docker_hub_token(repository: str) -> str:
    url = (
        f"https://auth.docker.io/token"
        f"?service=registry.docker.io&scope=repository:{repository}:pull"
    )
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read())["token"]


def check_image_docker_hub(repository: str, tag: str) -> bool:
    token = get_docker_hub_token(repository)
    url = f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header(
        "Accept",
        "application/vnd.docker.distribution.manifest.v2+json, "
        "application/vnd.oci.image.index.v1+json",
    )
    try:
        urllib.request.urlopen(req)
        return True
    except urllib.error.HTTPError:
        return False


def check_image_oci(registry: str, repository: str, tag: str) -> bool:
    token_url = f"https://{registry}/v2/token?scope=repository:{repository}:pull"
    headers = {}
    try:
        with urllib.request.urlopen(token_url) as resp:
            token = json.loads(resp.read()).get("token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
    except urllib.error.HTTPError:
        pass

    url = f"https://{registry}/v2/{repository}/manifests/{tag}"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header(
        "Accept",
        "application/vnd.docker.distribution.manifest.v2+json, "
        "application/vnd.oci.image.index.v1+json",
    )
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        urllib.request.urlopen(req)
        return True
    except urllib.error.HTTPError:
        return False


def check_image(repository: str, tag: str) -> bool:
    if "/" in repository and "." in repository.split("/")[0]:
        parts = repository.split("/", 1)
        registry = parts[0]
        repo_path = parts[1]
        return check_image_oci(registry, repo_path, tag)
    else:
        return check_image_docker_hub(repository, tag)


def check_images(images: list) -> bool:
    has_error = False
    for image in images:
        if "tag" not in image:
            continue
        image_ref = f"{image['repository']}:{image['tag']}"
        if not check_image(image["repository"], image["tag"]):
            print(f"Image {image_ref} not found")
            has_error = True
        else:
            print(f"Image {image_ref} found")
    return has_error


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: validate-imagevector.py <imagevector>\n")
        sys.exit(1)
    with open(sys.argv[1], "r") as f:
        iv = yaml.safe_load(f)
    has_error = check_images(iv["images"])
    if has_error:
        sys.stderr.write("Not all images found\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
