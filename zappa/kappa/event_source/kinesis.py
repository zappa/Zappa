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

import botocore.exceptions
import kappa.event_source.base
import logging

LOG = logging.getLogger(__name__)


class KinesisEventSource(kappa.event_source.base.EventSource):

    def __init__(self, context, config):
        super(KinesisEventSource, self).__init__(context, config)
        self._lambda = kappa.awsclient.create_client(
            'lambda', context.session)

    def _get_uuid(self, function):
        uuid = None
        response = self._lambda.call(
            'list_event_source_mappings',
            FunctionName=function.name,
            EventSourceArn=self.arn)
        LOG.debug(response)
        if len(response['EventSourceMappings']) > 0:
            uuid = response['EventSourceMappings'][0]['UUID']
        return uuid

    def add(self, function):
        try:
            response = self._lambda.call(
                'create_event_source_mapping',
                FunctionName=function.name,
                EventSourceArn=self.arn,
                BatchSize=self.batch_size,
                StartingPosition=self.starting_position,
                Enabled=self.enabled
            )
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to add event source')

    def enable(self, function):
        self._config['enabled'] = True
        try:
            response = self._lambda.call(
                'update_event_source_mapping',
                UUID=self._get_uuid(function),
                Enabled=self.enabled
            )
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to enable event source')

    def disable(self, function):
        self._config['enabled'] = False
        try:
            response = self._lambda.call(
                'update_event_source_mapping',
                FunctionName=function.name,
                Enabled=self.enabled
            )
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to disable event source')

    def update(self, function):
        response = None
        uuid = self._get_uuid(function)
        if uuid:
            try:
                response = self._lambda.call(
                    'update_event_source_mapping',
                    BatchSize=self.batch_size,
                    Enabled=self.enabled,
                    FunctionName=function.arn)
                LOG.debug(response)
            except Exception:
                LOG.exception('Unable to update event source')

    def remove(self, function):
        response = None
        uuid = self._get_uuid(function)
        if uuid:
            response = self._lambda.call(
                'delete_event_source_mapping',
                UUID=uuid)
            LOG.debug(response)
        return response

    def status(self, function):
        response = None
        LOG.debug('getting status for event source %s', self.arn)
        uuid = self._get_uuid(function)
        if uuid:
            try:
                response = self._lambda.call(
                    'get_event_source_mapping',
                    UUID=self._get_uuid(function))
                LOG.debug(response)
            except botocore.exceptions.ClientError:
                LOG.debug('event source %s does not exist', self.arn)
                response = None
        else:
            LOG.debug('No UUID for event source %s', self.arn)
        return response
