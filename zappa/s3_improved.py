import logging

import kappa.awsclient
import kappa.event_source.base

LOG = logging.getLogger(__name__)


# This class allows for correct addition, updates, and deletes of S3 trigger events when there are multiple events
# on a bucket that may be tied to different stages with different filters by limiting changes only to events tied
# to the targeted method and stage unlike the handler in Kappa.
# Related: https://github.com/Miserlou/Zappa/issues/2111
# This entire class is reimplemented rather than extending the Kappa version because only the constructor is reused
# and I didn't want any future usages or extentions to accidentally fall through to Kappa's object via one of the
# 'aliases' it sets up.
class S3EventSource(kappa.event_source.base.EventSource):
    def __init__(self, context, config):
        super(S3EventSource, self).__init__(context, config)
        self._s3 = kappa.awsclient.create_client("s3", context.session)

    def _get_bucket_name(self):
        return self.arn.split(":")[-1]

    def _make_notification_id(self, function_name):
        return "Kappa-%s-notification" % function_name

    def add(self, function):
        event_config = {
            "Id": self._make_notification_id(function.name),
            "Events": [e for e in self._config["events"]],
            "LambdaFunctionArn": "%s:%s" % (function.arn, function._context.environment),
        }

        # Add S3 key filters
        if "key_filters" in self._config:
            filters_spec = {"Key": {"FilterRules": []}}
            for key_filter in self._config["key_filters"]:
                if "type" in key_filter and "value" in key_filter and key_filter["type"] in ("prefix", "suffix"):
                    rule = {
                        "Name": key_filter["type"],
                        "Value": key_filter["value"],
                    }
                    filters_spec["Key"]["FilterRules"].append(rule)
            event_config["Filter"] = filters_spec

        try:
            bucket_config = self._s3.call(
                "get_bucket_notification_configuration",
                Bucket=self._get_bucket_name(),
            )
            del bucket_config["ResponseMetadata"]
            if "LambdaFunctionConfigurations" in bucket_config:
                bucket_config["LambdaFunctionConfigurations"].append(event_config)
            else:
                bucket_config["LambdaFunctionConfigurations"] = [event_config]
            response = self._s3.call(
                "put_bucket_notification_configuration",
                Bucket=self._get_bucket_name(),
                NotificationConfiguration=bucket_config,
            )
            LOG.debug(response)
        except Exception as exc:
            LOG.debug(exc.response)
            LOG.exception("Unable to add S3 event source")

    enable = add

    def update(self, function):
        self.add(function)

    def remove(self, function):
        LOG.debug("removing s3 notification")
        bucket_config = self._s3.call("get_bucket_notification_configuration", Bucket=self._get_bucket_name())
        LOG.debug(bucket_config)

        new_config = []
        for configuration in bucket_config.get("LambdaFunctionConfigurations", []):
            if configuration["Id"] != self._make_notification_id(function.name):
                new_config.append(configuration)
        response = self._s3.call(
            "put_bucket_notification_configuration",
            Bucket=self._get_bucket_name(),
            NotificationConfiguration={"LambdaFunctionConfigurations": new_config},
        )
        LOG.debug(response)

    disable = remove

    def status(self, function):
        LOG.debug("status for s3 notification for %s", function.name)
        bucket_config = self._s3.call("get_bucket_notification_configuration", Bucket=self._get_bucket_name())
        LOG.debug(bucket_config)
        for configuration in bucket_config.get("LambdaFunctionConfigurations", []):
            if configuration["Id"] == self._make_notification_id(function.name):
                return {
                    "LambdaFunctionConfiguration": configuration,
                    "State": "Enabled",
                }
        return None
