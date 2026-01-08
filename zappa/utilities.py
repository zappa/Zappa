import calendar
import datetime
import json
import logging
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import boto3
import botocore
import durationpy

LOG = logging.getLogger(__name__)


class UnserializableJsonError(TypeError):
    """Exception class for JSON encoding errors"""

    pass


##
# Settings / Packaging
##

# mimetypes starting with entries defined here are considered as TEXT when BINARTY_SUPPORT is True.
# - Additional TEXT mimetypes may be defined with the 'ADDITIONAL_TEXT_MIMETYPES' setting.
DEFAULT_TEXT_MIMETYPES = (
    "text/",
    "application/json",  # RFC 4627
    "application/javascript",  # RFC 4329
    "application/ecmascript",  # RFC 4329
    "application/xml",  # RFC 3023
    "application/xml-external-parsed-entity",  # RFC 3023
    "application/xml-dtd",  # RFC 3023
    "image/svg+xml",  # RFC 3023
)

# Default EFS mount point for Lambda (no trailing slash - AWS requires /mnt/[a-zA-Z0-9-_.]+)
DEFAULT_EFS_MOUNT_POINT = "/mnt/efs"


def copytree(
    src: Path,
    dst: Path,
    metadata: bool = True,
    symlinks: bool = False,
    ignore: Optional[Callable[[Any, list[str]], set[str]]] = None,
) -> None:
    """
    This is a contributed re-implementation of 'copytree' that
    should work with the exact same behavior on multiple platforms.

    When `metadata` is False, file metadata such as permissions and modification
    times are not copied.
    """

    def copy_file(src_path: Path, dst_path: Path, item: str) -> None:
        s = src_path / item
        d = dst_path / item

        if symlinks and s.is_symlink():  # pragma: no cover
            if d.exists():
                d.unlink()
            d.symlink_to(s.readlink())
            if metadata:
                st = s.lstat()
                mode = stat.S_IMODE(st.st_mode)
                try:
                    os.chmod(str(d), mode)
                except Exception:
                    LOG.warning(f"Unable to perform chmod on: {d}")
        elif s.is_dir():
            copytree(s, d, metadata, symlinks, ignore)
        else:
            shutil.copy2(s, d) if metadata else shutil.copy(s, d)

    src_path = src
    dst_path = dst

    try:
        lst = [p.name for p in src_path.iterdir()]
        if not dst_path.exists():
            dst_path.mkdir(parents=True, exist_ok=True)
            if metadata:
                shutil.copystat(src_path, dst_path)
    except NotADirectoryError:  # egg-link files
        copy_file(src_path.parent, dst_path.parent, src_path.name)
        return

    if ignore:
        excl = ignore(src_path, lst)
        lst = [x for x in lst if x not in excl]

    for item in lst:
        copy_file(src_path, dst_path, item)


def parse_s3_url(url: Optional[str]) -> Tuple[str, str]:
    """
    Parses S3 URL.

    Returns bucket (domain) and file (full path).
    """
    bucket = ""
    path = ""
    if url:
        result = urlparse(url)
        bucket = result.netloc
        path = result.path.strip("/")
    return bucket, path


def human_size(num: float, suffix: str = "B") -> str:
    """
    Convert bytes length to a human-readable version
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return "{0:3.1f}{1!s}{2!s}".format(num, unit, suffix)
        num /= 1024.0
    return "{0:.1f}{1!s}{2!s}".format(num, "Yi", suffix)


def string_to_timestamp(timestring: str) -> int:
    """
    Accepts a str, returns an int timestamp.
    """

    ts = None

    # Uses an extended version of Go's duration string.
    try:
        delta = durationpy.from_str(timestring)
        past = datetime.datetime.now(datetime.timezone.utc) - delta
        ts = calendar.timegm(past.timetuple())
        return ts
    except Exception:
        pass

    if ts:
        return ts
    return 0


##
# `init` related
##


def detect_django_settings() -> List[str]:
    """
    Automatically try to discover Django settings files,
    return them as relative module paths.
    """

    matches = []
    cwd = Path.cwd()
    for settings_file in cwd.rglob("*settings.py"):
        if "site-packages" in str(settings_file):
            continue
        package_path = settings_file.relative_to(cwd)
        package_module = ".".join(package_path.parts).replace(".py", "")
        LOG.info(f"Detected Django settings file: {package_module}")
        matches.append(package_module)
    return matches


def detect_flask_apps() -> list[str]:
    """
    Automatically try to discover Flask apps files,
    return them as relative module paths.
    """

    matches = []
    cwd = Path.cwd()
    for py_file in cwd.rglob("*.py"):
        if "site-packages" in str(py_file):
            continue

        with py_file.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines:
                app = None

                # Kind of janky..
                if "= Flask(" in line:
                    app = line.split("= Flask(")[0].strip()
                if "=Flask(" in line:
                    app = line.split("=Flask(")[0].strip()

                if not app:
                    continue

                package_path = py_file.relative_to(cwd)
                package_module = ".".join(package_path.parts).replace(".py", "")
                app_module = f"{package_module}.{app}"
                matches.append(app_module)

    return matches


def get_venv_from_python_version() -> str:
    return "python{}.{}".format(*sys.version_info)


def get_runtime_from_python_version() -> str:
    """ """
    if sys.version_info[0] < 3:
        raise ValueError("Python 2.x is no longer supported.")
    else:
        if sys.version_info[1] <= 7:
            raise ValueError("Python 3.7 and below are no longer supported.")
        elif sys.version_info[1] == 8:
            raise ValueError("Python 3.8 and below are no longer supported.")
        elif sys.version_info[1] == 9:
            return "python3.9"
        elif sys.version_info[1] == 10:
            return "python3.10"
        elif sys.version_info[1] == 11:
            return "python3.11"
        elif sys.version_info[1] == 12:
            return "python3.12"
        elif sys.version_info[1] == 13:
            return "python3.13"
        elif sys.version_info[1] == 14:
            return "python3.14"
        else:
            raise ValueError(f"Python f{'.'.join(str(v) for v in sys.version_info[:2])} is not yet supported.")


##
# Async Tasks
##


def get_topic_name(lambda_name: str) -> str:
    """Topic name generation"""
    return "%s-zappa-async" % lambda_name


##
# Event sources
##


class BaseEventSource:
    """Base class for event sources"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        self.session = session
        self._config = config
        self.arn: str = config.get("arn", "")
        self.enabled: bool = config.get("enabled", True)
        self.batch_size: int = config.get("batch_size", 10)

    def add(self, function_arn: str) -> None:
        raise NotImplementedError

    def remove(self, function_arn: str) -> Union[bool, Dict[str, Any], None]:
        raise NotImplementedError

    def status(self, function_arn: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def update(self, function_arn: str) -> None:
        raise NotImplementedError


class EventSourceMappingMixin(BaseEventSource):
    """Mixin for event sources that use Lambda event source mappings (SQS, DynamoDB, Kinesis)"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        super().__init__(session, config)
        self._lambda = session.client("lambda")

    @property
    def batch_window(self) -> int:
        return self._config.get("batch_window", 1 if self.batch_size > 10 else 0)

    def _get_uuid(self, function_arn: str) -> Optional[str]:
        uuid = None
        response = self._lambda.list_event_source_mappings(
            FunctionName=function_arn,
            EventSourceArn=self.arn,
        )
        LOG.debug(response)
        if len(response["EventSourceMappings"]) > 0:
            uuid = response["EventSourceMappings"][0]["UUID"]
        return uuid

    def add(self, function_arn: str) -> None:
        try:
            kwargs = {
                "FunctionName": function_arn,
                "EventSourceArn": self.arn,
                "BatchSize": self.batch_size,
                "Enabled": self.enabled,
            }
            # Add batch window for SQS
            if hasattr(self, "_supports_batch_window") and self._supports_batch_window:
                kwargs["MaximumBatchingWindowInSeconds"] = self.batch_window

            response = self._lambda.create_event_source_mapping(**kwargs)
            LOG.debug(response)
        except Exception:
            LOG.exception("Unable to add event source")

    def enable(self, function_arn: str) -> None:
        self._config["enabled"] = True
        try:
            response = self._lambda.update_event_source_mapping(
                UUID=self._get_uuid(function_arn),
                Enabled=self.enabled,
            )
            LOG.debug(response)
        except Exception:
            LOG.exception("Unable to enable event source")

    def disable(self, function_arn: str) -> None:
        self._config["enabled"] = False
        try:
            response = self._lambda.update_event_source_mapping(
                UUID=self._get_uuid(function_arn),
                Enabled=self.enabled,
            )
            LOG.debug(response)
        except Exception:
            LOG.exception("Unable to disable event source")

    def update(self, function_arn: str) -> None:
        response = None
        uuid = self._get_uuid(function_arn)
        if uuid:
            try:
                kwargs = {
                    "UUID": uuid,
                    "BatchSize": self.batch_size,
                    "Enabled": self.enabled,
                    "FunctionName": function_arn,
                }
                # Add batch window for SQS
                if hasattr(self, "_supports_batch_window") and self._supports_batch_window:
                    kwargs["MaximumBatchingWindowInSeconds"] = self.batch_window

                response = self._lambda.update_event_source_mapping(**kwargs)
                LOG.debug(response)
            except Exception:
                LOG.exception("Unable to update event source")

    def remove(self, function_arn: str) -> Optional[Dict[str, Any]]:
        response = None
        uuid = self._get_uuid(function_arn)
        if uuid:
            response = self._lambda.delete_event_source_mapping(UUID=uuid)
            LOG.debug(response)
        return response

    def status(self, function_arn: str) -> Optional[Dict[str, Any]]:
        response = None
        LOG.debug("getting status for event source %s", self.arn)
        uuid = self._get_uuid(function_arn)
        if uuid:
            try:
                response = self._lambda.get_event_source_mapping(UUID=uuid)
                LOG.debug(response)
            except botocore.exceptions.ClientError:
                LOG.debug("event source %s does not exist", self.arn)
                response = None
        else:
            LOG.debug("No UUID for event source %s", self.arn)
        return response


class SqsEventSource(EventSourceMappingMixin, BaseEventSource):
    """SQS event source implementation"""

    _supports_batch_window = True


class DynamoDBStreamEventSource(EventSourceMappingMixin, BaseEventSource):
    """DynamoDB Stream event source implementation"""

    _supports_batch_window = False


class KinesisEventSource(EventSourceMappingMixin, BaseEventSource):
    """Kinesis event source implementation"""

    _supports_batch_window = False


class S3EventSource(BaseEventSource):
    """S3 event source implementation"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        super().__init__(session, config)
        self._lambda = session.client("lambda")
        self._s3 = session.client("s3")
        bucket_name = self.arn.split(":::")[-1]
        self.bucket_name: str = bucket_name
        self.events: List[str] = config.get("events", ["s3:ObjectCreated:*"])
        self.prefix: str = config.get("prefix", "")
        self.suffix: str = config.get("suffix", "")

    def _make_notification_id(self, function_arn: str) -> str:
        return function_arn.split(":")[-1]

    def add(self, function_arn: str) -> None:
        # Add Lambda permission
        try:
            self._lambda.add_permission(
                FunctionName=function_arn,
                StatementId=f"s3-{self.bucket_name}",
                Action="lambda:InvokeFunction",
                Principal="s3.amazonaws.com",
                SourceArn=self.arn,
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                LOG.exception("Unable to add Lambda permission for S3")

        # Configure bucket notification
        try:
            # Get existing configuration
            try:
                response = self._s3.get_bucket_notification_configuration(Bucket=self.bucket_name)
                config = response
            except botocore.exceptions.ClientError:
                config = {}

            # Add new configuration
            lambda_configs = config.get("LambdaFunctionConfigurations", [])
            new_config: Dict[str, Any] = {
                "Id": self._make_notification_id(function_arn),
                "LambdaFunctionArn": function_arn,
                "Events": self.events,
            }
            if self.prefix:
                new_config["Filter"] = {"Key": {"FilterRules": [{"Name": "prefix", "Value": self.prefix}]}}
            if self.suffix:
                if "Filter" not in new_config:
                    new_config["Filter"] = {"Key": {"FilterRules": []}}
                new_config["Filter"]["Key"]["FilterRules"].append({"Name": "suffix", "Value": self.suffix})

            lambda_configs.append(new_config)
            config["LambdaFunctionConfigurations"] = lambda_configs

            # Remove ResponseMetadata if present
            config.pop("ResponseMetadata", None)

            self._s3.put_bucket_notification_configuration(Bucket=self.bucket_name, NotificationConfiguration=config)
            LOG.debug("Added S3 event source")
        except Exception:
            LOG.exception("Unable to add S3 event source")

    def remove(self, function_arn: str) -> bool:
        try:
            # Remove Lambda permission
            try:
                self._lambda.remove_permission(FunctionName=function_arn, StatementId=f"s3-{self.bucket_name}")
            except botocore.exceptions.ClientError:
                pass

            # Remove bucket notification
            response = self._s3.get_bucket_notification_configuration(Bucket=self.bucket_name)
            config = response
            lambda_configs = config.get("LambdaFunctionConfigurations", [])
            notification_id = self._make_notification_id(function_arn)
            lambda_configs = [c for c in lambda_configs if c.get("Id") != notification_id]
            config["LambdaFunctionConfigurations"] = lambda_configs
            config.pop("ResponseMetadata", None)
            self._s3.put_bucket_notification_configuration(Bucket=self.bucket_name, NotificationConfiguration=config)
            LOG.debug("Removed S3 event source")
            return True
        except Exception:
            LOG.exception("Unable to remove S3 event source")
            return False

    def status(self, function_arn: str) -> Optional[Dict[str, Any]]:
        try:
            response = self._s3.get_bucket_notification_configuration(Bucket=self.bucket_name)
            lambda_configs = response.get("LambdaFunctionConfigurations", [])
            notification_id = self._make_notification_id(function_arn)
            for config in lambda_configs:
                if config.get("Id") == notification_id:
                    return config
            return None
        except Exception:
            LOG.exception("Unable to get S3 event source status")
            return None

    def update(self, function_arn: str) -> None:
        # For S3, update is remove + add
        self.remove(function_arn)
        self.add(function_arn)


class SNSEventSource(BaseEventSource):
    """SNS event source implementation"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        super().__init__(session, config)
        self._lambda = session.client("lambda")
        self._sns = session.client("sns")
        self.filters: Optional[Dict[str, Any]] = config.get("filters")

    def add(self, function_arn: str) -> None:
        # Add Lambda permission
        try:
            self._lambda.add_permission(
                FunctionName=function_arn,
                StatementId=f"sns-{self.arn.split(':')[-1]}",
                Action="lambda:InvokeFunction",
                Principal="sns.amazonaws.com",
                SourceArn=self.arn,
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                LOG.exception("Unable to add Lambda permission for SNS")

        # Subscribe to topic
        try:
            response = self._sns.subscribe(TopicArn=self.arn, Protocol="lambda", Endpoint=function_arn)
            subscription_arn = response["SubscriptionArn"]
            LOG.debug(response)

            # Add filters if specified
            if self.filters and subscription_arn != "PendingConfirmation":
                self._sns.set_subscription_attributes(
                    SubscriptionArn=subscription_arn,
                    AttributeName="FilterPolicy",
                    AttributeValue=json.dumps(self.filters),
                )
        except Exception:
            LOG.exception("Unable to add SNS event source")

    def remove(self, function_arn: str) -> bool:
        # Check if subscription exists and unsubscribe
        subscription_removed = False
        try:
            response = self._sns.list_subscriptions_by_topic(TopicArn=self.arn)
            for subscription in response["Subscriptions"]:
                if subscription["Endpoint"] == function_arn:
                    self._sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
                    LOG.debug("Removed SNS subscription")
                    subscription_removed = True
                    break
        except Exception:
            LOG.exception("Unable to remove SNS event source")

        # Only remove Lambda permission if we actually had a subscription
        if subscription_removed:
            try:
                self._lambda.remove_permission(FunctionName=function_arn, StatementId=f"sns-{self.arn.split(':')[-1]}")
            except Exception as e:
                LOG.warning(f"Failed to remove Lambda permission for SNS event source {self.arn}: {e.args}")

        return subscription_removed

    def status(self, function_arn: str) -> Optional[Dict[str, Any]]:
        try:
            response = self._sns.list_subscriptions_by_topic(TopicArn=self.arn)
            for subscription in response["Subscriptions"]:
                if subscription["Endpoint"] == function_arn:
                    return subscription
            return None
        except Exception:
            LOG.exception("Unable to get SNS event source status")
            return None

    def update(self, function_arn: str) -> None:
        # For SNS, update means updating filters if they exist
        if self.filters:
            subscription = self.status(function_arn)
            if subscription:
                try:
                    self._sns.set_subscription_attributes(
                        SubscriptionArn=subscription["SubscriptionArn"],
                        AttributeName="FilterPolicy",
                        AttributeValue=json.dumps(self.filters),
                    )
                except Exception:
                    LOG.exception("Unable to update SNS filters")


class CloudWatchEventSource(BaseEventSource):
    """CloudWatch Events (EventBridge) event source implementation"""

    def __init__(self, session: boto3.Session, config: Dict[str, Any]) -> None:
        super().__init__(session, config)
        self._lambda = session.client("lambda")
        self._events = session.client("events")
        self.rule_name: str = config.get("rule_name", config.get("name", ""))
        self.rule_description: str = config.get("rule_description", config.get("description", ""))
        self.pattern: Optional[Union[str, Dict[str, Any]]] = config.get("event_pattern", config.get("pattern"))
        self.schedule: Optional[str] = config.get("schedule_expression", config.get("schedule"))

    def add(self, function_arn: str) -> None:
        # Create or update rule
        try:
            rule_kwargs: Dict[str, Any] = {
                "Name": self.rule_name,
                "State": "ENABLED" if self.enabled else "DISABLED",
            }
            if self.rule_description:
                rule_kwargs["Description"] = self.rule_description
            if self.pattern:
                rule_kwargs["EventPattern"] = json.dumps(self.pattern) if isinstance(self.pattern, dict) else self.pattern
            if self.schedule:
                rule_kwargs["ScheduleExpression"] = self.schedule

            response = self._events.put_rule(**rule_kwargs)
            rule_arn = response["RuleArn"]
            LOG.debug(response)
        except Exception:
            LOG.exception("Unable to create CloudWatch Events rule")
            return

        # Add Lambda permission
        try:
            self._lambda.add_permission(
                FunctionName=function_arn,
                StatementId=f"events-{self.rule_name}",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                LOG.exception("Unable to add Lambda permission for CloudWatch Events")

        # Add target
        try:
            self._events.put_targets(Rule=self.rule_name, Targets=[{"Id": "1", "Arn": function_arn}])
            LOG.debug("Added CloudWatch Events target")
        except Exception:
            LOG.exception("Unable to add CloudWatch Events target")

    def remove(self, function_arn: str) -> bool:
        # Remove target
        try:
            self._events.remove_targets(Rule=self.rule_name, Ids=["1"])
        except botocore.exceptions.ClientError:
            pass

        # Remove Lambda permission
        try:
            self._lambda.remove_permission(FunctionName=function_arn, StatementId=f"events-{self.rule_name}")
        except botocore.exceptions.ClientError:
            pass

        # Delete rule
        try:
            self._events.delete_rule(Name=self.rule_name)
            LOG.debug("Removed CloudWatch Events rule")
            return True
        except botocore.exceptions.ClientError:
            pass
        return False

    def status(self, function_arn: str) -> Optional[Dict[str, Any]]:
        try:
            response = self._events.describe_rule(Name=self.rule_name)
            # Check if Lambda is a target
            targets = self._events.list_targets_by_rule(Rule=self.rule_name)
            for target in targets["Targets"]:
                if target["Arn"] == function_arn:
                    return response
            return None
        except botocore.exceptions.ClientError:
            return None

    def update(self, function_arn: str) -> None:
        # Update rule if it exists
        if self.status(function_arn):
            self.add(function_arn)


def get_event_source(
    event_source: Dict[str, Any], lambda_arn: str, target_function: str, boto_session: boto3.Session, dry: bool = False
) -> Tuple[BaseEventSource, str]:
    """
    Given an event_source dictionary item, a session and a lambda_arn,
    create and return the appropriate event source object.
    """
    event_source_map: Dict[str, type[BaseEventSource]] = {
        "dynamodb": DynamoDBStreamEventSource,
        "kinesis": KinesisEventSource,
        "s3": S3EventSource,
        "sns": SNSEventSource,
        "sqs": SqsEventSource,
        "events": CloudWatchEventSource,
    }

    arn = event_source["arn"]
    _, _, svc, _ = arn.split(":", 3)

    event_source_class = event_source_map.get(svc, None)
    if not event_source_class:
        raise ValueError("Unknown event source: {0}".format(arn))

    # Handle S3 special case for function ARN
    if svc == "s3":
        split_arn = lambda_arn.split(":")
        arn_front = ":".join(split_arn[:-1])
        arn_back = split_arn[-1]
        function_arn = ":".join([arn_back, target_function])
        lambda_arn = arn_front
    else:
        function_arn = lambda_arn

    event_source_obj = event_source_class(boto_session, event_source)

    return event_source_obj, function_arn


def add_event_source(
    event_source: Dict[str, Any], lambda_arn: str, target_function: str, boto_session: boto3.Session, dry: bool = False
) -> str:
    """
    Given an event_source dictionary, create the object and add the event source.
    """
    event_source_obj, function_arn = get_event_source(event_source, lambda_arn, target_function, boto_session, dry=False)
    # TODO: Detect changes in config and refine exists algorithm
    if not dry:
        if not event_source_obj.status(function_arn):
            event_source_obj.add(function_arn)
            return "successful" if event_source_obj.status(function_arn) else "failed"
        else:
            return "exists"

    return "dryrun"


def remove_event_source(
    event_source: Dict[str, Any], lambda_arn: str, target_function: str, boto_session: boto3.Session, dry: bool = False
) -> Union[BaseEventSource, bool, Dict[str, Any], None]:
    """
    Given an event_source dictionary, create the object and remove the event source.
    """
    event_source_obj, function_arn = get_event_source(event_source, lambda_arn, target_function, boto_session, dry=False)

    if not dry:
        rule_response = event_source_obj.remove(function_arn)
        return rule_response
    else:
        return event_source_obj


def get_event_source_status(
    event_source: Dict[str, Any], lambda_arn: str, target_function: str, boto_session: boto3.Session, dry: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Given an event_source dictionary, create the object and get the event source status.
    """
    event_source_obj, function_arn = get_event_source(event_source, lambda_arn, target_function, boto_session, dry=False)
    return event_source_obj.status(function_arn)


##
# Analytics / Surveillance / Nagging
##


def check_new_version_available(this_version: str) -> bool:
    """
    Checks if a newer version of Zappa is available.

    Returns True is updateable, else False.

    """
    import requests

    pypi_url = "https://pypi.org/pypi/Zappa/json"
    resp = requests.get(pypi_url, timeout=1.5)
    top_version = resp.json()["info"]["version"]

    return this_version != top_version


class InvalidAwsLambdaName(Exception):
    """Exception: proposed AWS Lambda name is invalid"""

    pass


def validate_name(name: str, maxlen: int = 80) -> str:
    """Validate name for AWS Lambda function.
    name: actual name (without `arn:aws:lambda:...:` prefix and without
        `:$LATEST`, alias or version suffix.
    maxlen: max allowed length for name without prefix and suffix.

    The value 80 was calculated from prefix with longest known region name
    and assuming that no alias or version would be longer than `$LATEST`.

    Based on AWS Lambda spec
    http://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html

    Return: the name
    Raise: InvalidAwsLambdaName, if the name is invalid.
    """
    if not isinstance(name, str):
        msg = "Name must be of type string"
        raise InvalidAwsLambdaName(msg)
    if len(name) > maxlen:
        msg = "Name is longer than {maxlen} characters."
        raise InvalidAwsLambdaName(msg.format(maxlen=maxlen))
    if len(name) == 0:
        msg = "Name must not be empty string."
        raise InvalidAwsLambdaName(msg)
    if not re.match("^[a-zA-Z0-9-_]+$", name):
        msg = "Name can only contain characters from a-z, A-Z, 0-9, _ and -"
        raise InvalidAwsLambdaName(msg)
    return name


def contains_python_files_or_subdirs(folder: str) -> bool:
    """
    Checks (recursively) if the directory contains .py or .pyc files
    """
    folder_path = Path(folder)
    # Check for .py files
    if any(folder_path.rglob("*.py")):
        return True
    # Check for .pyc files
    if any(folder_path.rglob("*.pyc")):
        return True
    return False


def conflicts_with_a_neighbouring_module(directory_path: str) -> bool:
    """
    Checks if a directory lies in the same directory as a .py file with the same name.
    """
    dir_path = Path(directory_path).resolve()
    parent_dir = dir_path.parent
    current_dir_name = dir_path.name
    conflicting_neighbour_filename = current_dir_name + ".py"
    conflicting_file = parent_dir / conflicting_neighbour_filename
    return conflicting_file.exists()


# https://github.com/Miserlou/Zappa/issues/1188
def titlecase_keys(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a dict with keys of type str and returns a new dict with all keys titlecased.
    """
    return {k.title(): v for k, v in d.items()}


# https://github.com/Miserlou/Zappa/issues/1688
def is_valid_bucket_name(name: str) -> bool:
    """
    Checks if an S3 bucket name is valid according to:
     https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules
    """
    # Bucket names must be at least 3 and no more than 63 characters long.
    if len(name) < 3 or len(name) > 63:
        return False
    # Bucket names must not contain uppercase characters or underscores.
    if any(x.isupper() for x in name):
        return False
    if "_" in name:
        return False
    # Bucket names must start with a lowercase letter or number.
    if not (name[0].islower() or name[0].isdigit()):
        return False
    # Bucket names must be a series of one or more labels. Adjacent labels are separated by a single period (.).
    for label in name.split("."):
        # Each label must start and end with a lowercase letter or a number.
        if len(label) < 1:
            return False
        if not (label[0].islower() or label[0].isdigit()):
            return False
        if not (label[-1].islower() or label[-1].isdigit()):
            return False
    # Bucket names must not be formatted as an IP address (for example, 192.168.5.4).
    looks_like_IP = True
    for label in name.split("."):
        if not label.isdigit():
            looks_like_IP = False
            break
    if looks_like_IP:
        return False

    return True


def merge_headers(event: Dict[str, Any]) -> Dict[str, str]:
    """
    Merge the values of headers and multiValueHeaders into a single dict.
    Opens up support for multivalue headers via API Gateway and ALB.
    See: https://github.com/Miserlou/Zappa/pull/1756
    """
    headers = event.get("headers") or {}
    multi_headers = (event.get("multiValueHeaders") or {}).copy()
    for h in set(headers.keys()):
        if h not in multi_headers:
            multi_headers[h] = [headers[h]]
    for h in multi_headers.keys():
        multi_headers[h] = ", ".join(multi_headers[h])
    return multi_headers


class ApacheNCSAFormatters:
    """
    NCSA extended/combined Log Format:
    "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
    %h: Remote hostname.
    %l: Remote logname
    %u: Remote user if the request was authenticated. May be bogus if return status (%s) is 401 (unauthorized).
    %t: Time the request was received, in the format [18/Sep/2011:19:18:28 -0400].
        The last number indicates the timezone offset from GMT
    %r: First line of request.
    %>s: Final Status
    %b: Size of response in bytes, excluding HTTP headers.
        In CLF format, i.e. a '-' rather than a 0 when no bytes are sent.
    %{Referer}i:The contents of Referer: header line(s) in the request sent to the server.
    %{User-agent}i: The contents of User-agent: header line(s) in the request sent to the server.

    Refer to:
    https://httpd.apache.org/docs/current/en/mod/mod_log_config.html
    """

    @staticmethod
    def format_log(status_code: int, environ: dict, content_length: int, **kwargs) -> str:
        ip_header = kwargs.get("ip_header", None)
        if ip_header:
            host = environ.get(ip_header, "")
        else:
            host = environ.get("REMOTE_ADDR", "")

        logname = "-"
        user = "-"
        now = datetime.datetime.now(datetime.timezone.utc)
        display_datetime = now.strftime("%d/%b/%Y:%H:%M:%S %z")
        method = environ.get("REQUEST_METHOD", "")
        path_info = environ.get("PATH_INFO", "")
        query_string = ""
        raw_query_string = environ.get("QUERY_STRING", "")
        if raw_query_string:
            query_string = f"?{raw_query_string}"
        server_protocol = environ.get("SERVER_PROTOCOL", "")
        request = f"{method} {path_info}{query_string} {server_protocol}"
        referer = environ.get("HTTP_REFERER", "")
        agent = environ.get("HTTP_USER_AGENT", "")
        log_entry = (
            f'{host} {logname} {user} [{display_datetime}] "{request}" {status_code} {content_length} "{referer}" "{agent}"'
        )
        return log_entry

    @staticmethod
    def format_log_with_response_time(*args, **kwargs) -> str:
        """
        Expect that kwargs includes response time in microseconds, 'rt_us'.
        Mimics Apache-like access HTTP log where the response time data is enabled

        NCSA extended/combined Log Format:
            "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %T/%D"

        %T: The time taken to serve the request, in seconds.
        %D: The time taken to serve the request, in microseconds.
        """
        response_time_microseconds = kwargs.get("rt_us", None)
        log_entry = ApacheNCSAFormatters.format_log(*args, **kwargs)
        if response_time_microseconds:
            response_time_seconds = int(response_time_microseconds / 1_000_000)
            log_entry = f"{log_entry} {response_time_seconds}/{response_time_microseconds}"
        return log_entry


def ApacheNCSAFormatter(with_response_time: bool = True) -> Callable:
    """A factory that returns the wanted formatter"""
    if with_response_time:
        return ApacheNCSAFormatters.format_log_with_response_time
    else:
        return ApacheNCSAFormatters.format_log


def validate_json_serializable(*args: Any, **kwargs: Any) -> None:
    try:
        json.dumps((args, kwargs))
    except (TypeError, OverflowError):
        raise UnserializableJsonError("Arguments to asynchronous.task must be JSON serializable!")
