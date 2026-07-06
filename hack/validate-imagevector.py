#!/usr/bin/env python3

import subprocess
import sys
import yaml


def check_image(repository: str, tag: str) -> bool:
    image_ref = f"{repository}:{tag}"
    result = subprocess.run(
        ["crane", "manifest", image_ref],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(f"Error checking image {image_ref}: {result.stderr.decode().strip()}\n")
        return False
    return True


def check_images(images: dict):
    has_error = False
    for image in images:
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
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
