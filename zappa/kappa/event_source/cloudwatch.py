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
import uuid

LOG = logging.getLogger(__name__)


class CloudWatchEventSource(kappa.event_source.base.EventSource):

    def __init__(self, context, config):
        super(CloudWatchEventSource, self).__init__(context, config)
        self._events = kappa.awsclient.create_client('events', context.session)
        self._lambda = kappa.awsclient.create_client('lambda', context.session)
        self._name = config['arn'].split('/')[-1]
        self._context = context
        self._config = config

    def get_rule(self):
        response = self._events.call('list_rules', NamePrefix=self._name)
        LOG.debug(response)
        if 'Rules' in response:
            for r in response['Rules']:
                if r['Name'] == self._name:
                    return r
        return None

    def add(self, function):
        kwargs = {
            'Name': self._name,
            'State': 'ENABLED' if self.enabled else 'DISABLED'
        }
        if 'schedule' in self._config:
            kwargs['ScheduleExpression'] = self._config['schedule']
        if 'pattern' in self._config:
            kwargs['EventPattern'] = self._config['pattern']
        if 'description' in self._config:
            kwargs['Description'] = self._config['description']
        if 'role_arn' in self._config:
            kwargs['RoleArn'] = self._config['role_arn']
        try:
            response = self._events.call('put_rule', **kwargs)
            LOG.debug(response)
            self._config['arn'] = response['RuleArn']
            response = self._lambda.call('add_permission',
                                         FunctionName=function.name,
                                         StatementId=str(uuid.uuid4()),
                                         Action='lambda:InvokeFunction',
                                         Principal='events.amazonaws.com',
                                         SourceArn=response['RuleArn'])
            LOG.debug(response)
            response = self._events.call('put_targets',
                                         Rule=self._name,
                                         Targets=[{
                                             'Id': function.name,
                                             'Arn': function.arn
                                         }])
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to put CloudWatch event source')

    def update(self, function):
        self.add(function)

    def remove(self, function):
        LOG.debug('removing CloudWatch event source')
        try:
            rule = self.get_rule()
            if rule:
                response = self._events.call('remove_targets',
                                             Rule=self._name,
                                             Ids=[function.name])
                LOG.debug(response)
                response = self._events.call('delete_rule',
                                             Name=self._name)
                LOG.debug(response)
        except Exception:
            LOG.exception('Unable to remove CloudWatch event source %s', self._name)

    def status(self, function):
        LOG.debug('status for CloudWatch event for %s', function.name)
        return self._to_status(self.get_rule())

    def enable(self, function):
        if self.get_rule():
            self._events.call('enable_rule', Name=self._name)

    def disable(self, function):
        if self.get_rule():
            self._events.call('disable_rule', Name=self._name)

    def _to_status(self, rule):
        if rule:
            return {
                'EventSourceArn': rule['Arn'],
                'State': rule['State']
            }
        return None
