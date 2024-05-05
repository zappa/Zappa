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

import kappa.awsclient
import kappa.event_source.base
import logging

LOG = logging.getLogger(__name__)


class SNSEventSource(kappa.event_source.base.EventSource):

    def __init__(self, context, config):
        super(SNSEventSource, self).__init__(context, config)
        self._sns = kappa.awsclient.create_client('sns', context.session)

    def _make_notification_id(self, function_name):
        return 'Kappa-%s-notification' % function_name

    def exists(self, function):
        try:
            response = self._sns.call(
                'list_subscriptions_by_topic',
                TopicArn=self.arn)
            LOG.debug(response)
            for subscription in response['Subscriptions']:
                if subscription['Endpoint'] == function.arn:
                    return subscription
            return None
        except Exception:
            LOG.exception('Unable to find event source %s', self.arn)

    def add(self, function):
        try:
            response = self._sns.call(
                'subscribe',
                TopicArn=self.arn, Protocol='lambda',
                Endpoint=function.arn)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to add SNS event source')

    enable = add

    def update(self, function):
        self.add(function)

    def remove(self, function):
        LOG.debug('removing SNS event source')
        try:
            subscription = self.exists(function)
            if subscription:
                response = self._sns.call(
                    'unsubscribe',
                    SubscriptionArn=subscription['SubscriptionArn'])
                LOG.debug(response)
        except Exception:
            LOG.exception('Unable to remove event source %s', self.arn)

    disable = remove

    def status(self, function):
        LOG.debug('status for SNS notification for %s', function.name)
        status = self.exists(function)
        if status:
            status['EventSourceArn'] = status['TopicArn']
        return status
