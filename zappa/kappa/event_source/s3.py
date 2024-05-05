# -*- coding: utf-8 -*-
# Copyright (c) 2014, 2015 Mitch Garnaat
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import kappa.event_source.base
import logging

LOG = logging.getLogger(__name__)


class S3EventSource(kappa.event_source.base.EventSource):

    def __init__(self, context, config):
        super(S3EventSource, self).__init__(context, config)
        self._s3 = kappa.awsclient.create_client('s3', context.session)

    def _make_notification_id(self, function_name):
        return 'Kappa-%s-notification' % function_name

    def _get_bucket_name(self):
        return self.arn.split(':')[-1]

    def add(self, function):
        notification_spec = {
            'LambdaFunctionConfigurations': [
                {
                    'Id': self._make_notification_id(function.name),
                    'Events': [e for e in self._config['events']],
                    'LambdaFunctionArn': '%s:%s' % (function.arn, function._context.environment),
                }
            ]
        }

        # Add S3 key filters
        if 'key_filters' in self._config:
            filters_spec = { 'Key' : { 'FilterRules' : [] } }
            for filter in self._config['key_filters']:
                if 'type' in filter and 'value' in filter and filter['type'] in ('prefix', 'suffix'):
                    rule = { 'Name' : filter['type'], 'Value' : filter['value'] }
                    filters_spec['Key']['FilterRules'].append(rule)
            notification_spec['LambdaFunctionConfigurations'][0]['Filter'] = filters_spec

        try:
            response = self._s3.call(
                'put_bucket_notification_configuration',
                Bucket=self._get_bucket_name(),
                NotificationConfiguration=notification_spec)
            LOG.debug(response)
        except Exception as exc:
            LOG.debug(exc.response)
            LOG.exception('Unable to add S3 event source')

    enable = add

    def update(self, function):
        self.add(function)

    def remove(self, function):
        LOG.debug('removing s3 notification')
        response = self._s3.call(
            'get_bucket_notification',
            Bucket=self._get_bucket_name())
        LOG.debug(response)
        if 'CloudFunctionConfiguration' in response:
            fn_arn = response['CloudFunctionConfiguration']['CloudFunction']
            if fn_arn == function.arn:
                del response['CloudFunctionConfiguration']
                del response['ResponseMetadata']
                response = self._s3.call(
                    'put_bucket_notification',
                    Bucket=self._get_bucket_name(),
                    NotificationConfiguration=response)
                LOG.debug(response)

    disable = remove

    def status(self, function):
        LOG.debug('status for s3 notification for %s', function.name)
        response = self._s3.call(
            'get_bucket_notification',
            Bucket=self._get_bucket_name())
        LOG.debug(response)
        if 'CloudFunctionConfiguration' not in response:
            return None
        return {
            'EventSourceArn': response['CloudFunctionConfiguration']['CloudFunction'],
            'State': 'Enabled'
        }
