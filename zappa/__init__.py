import os
import sys
from pathlib import Path


def running_in_docker() -> bool:
    """
    Determine if zappa is running in docker.
    - When docker is used allow usage of any python version
    """
    # https://stackoverflow.com/questions/63116419
    running_in_docker_flag = os.getenv("ZAPPA_RUNNING_IN_DOCKER", "False").lower() in ("true", "1", "t")
    return running_in_docker_flag


SUPPORTED_VERSIONS = [(3, 7), (3, 8), (3, 9)]

if not running_in_docker() and sys.version_info[:2] not in SUPPORTED_VERSIONS:
    print(running_in_docker())
    formatted_supported_versions = ["{}.{}".format(*version) for version in SUPPORTED_VERSIONS]
    err_msg = "This version of Python ({}.{}) is not supported!\n".format(
        *sys.version_info
    ) + "Zappa (and AWS Lambda) support the following versions of Python: {}".format(formatted_supported_versions)
    raise RuntimeError(err_msg)


__version__ = "0.56.0"
