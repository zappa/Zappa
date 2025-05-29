import os
import sys


def running_in_docker() -> bool:
    """
    Determine if zappa is running in docker.
    - When docker is used allow usage of any python version
    """
    # https://stackoverflow.com/questions/63116419
    running_in_docker_flag = os.getenv("ZAPPA_RUNNING_IN_DOCKER", "False").lower() in {"y", "yes", "t", "true", "1"}
    return running_in_docker_flag


SUPPORTED_VERSIONS = [(3, 9), (3, 10), (3, 11), (3, 12), (3, 13)]
MINIMUM_SUPPORTED_MINOR_VERSION = 9


if not running_in_docker() and sys.version_info[:2] not in SUPPORTED_VERSIONS:
    print(running_in_docker())
    formatted_supported_versions = ["{}.{}".format(*version) for version in SUPPORTED_VERSIONS]
    err_msg = "This version of Python ({}.{}) is not supported!\n".format(
        *sys.version_info
    ) + "Zappa (and AWS Lambda) support the following versions of Python: {}".format(formatted_supported_versions)
    raise RuntimeError(err_msg)
elif running_in_docker() and sys.version_info.minor < MINIMUM_SUPPORTED_MINOR_VERSION:
    # when running in docker enforce minimum version only
    err_msg = (
        f"This version of Python ({sys.version_info.major}.{sys.version_info.minor}) is not supported!\n"
        f"Zappa requires a minimum version of 3.{MINIMUM_SUPPORTED_MINOR_VERSION}"
    )
    raise RuntimeError(err_msg)

__version__ = "0.60.2"
