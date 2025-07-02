#!/usr/bin/env python3

import sys
import yaml
import urllib.request

"""
Verify whehter images are available on docker hub
"""


def check_image(repository: str, tag: str, name: str) -> bool:
    url = f"https://hub.docker.com/v2/repositories/{repository}/tags/{tag}/"
    try:
        response = urllib.request.urlopen(url)
        return response.status == 200
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"Error checking image {repository}:{tag}: {e}\n")
        return False


def check_images(images: dict):
    has_error = False
    for image in images:
        if not check_image(image["repository"], image["tag"], image["name"]):
            print(f"Image {image['repository']}:{image['tag']} not found")
            has_error = True
        else:
            print(f"Image {image['repository']}:{image['tag']} found")
    return has_error


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: verify-falco-images.py <imagevector>")
        sys.exit(1)
    with open(sys.argv[1], "r") as f:
        iv = yaml.safe_load(f)
    has_error = check_images(iv["images"])
    if has_error:
        sys.stderr.write("Not all images found\n")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
