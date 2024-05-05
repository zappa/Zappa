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

import logging

from botocore.exceptions import ClientError

import kappa.awsclient

LOG = logging.getLogger(__name__)


class Log(object):

    def __init__(self, context, log_group_name):
        self._context = context
        self.log_group_name = log_group_name
        self._log_client = kappa.awsclient.create_client(
            'logs', context.session)

    def _check_for_log_group(self):
        LOG.debug('checking for log group')
        response = self._log_client.call('describe_log_groups')
        log_group_names = [lg['logGroupName'] for lg in response['logGroups']]
        return self.log_group_name in log_group_names

    def streams(self):
        LOG.debug('getting streams for log group: %s', self.log_group_name)
        if not self._check_for_log_group():
            LOG.info(
                'log group %s has not been created yet', self.log_group_name)
            return []
        response = self._log_client.call(
            'describe_log_streams',
            logGroupName=self.log_group_name)
        LOG.debug(response)
        return response['logStreams']

    def tail(self):
        LOG.debug('tailing log group: %s', self.log_group_name)
        if not self._check_for_log_group():
            LOG.info(
                'log group %s has not been created yet', self.log_group_name)
            return []
        latest = None
        streams = self.streams()
        for stream in streams:
            if not latest:
                latest = stream
            elif stream['lastEventTimestamp'] > latest['lastEventTimestamp']:
                latest = stream
        response = self._log_client.call(
            'get_log_events',
            logGroupName=self.log_group_name,
            logStreamName=latest['logStreamName'])
        LOG.debug(response)
        return response['events']

    def delete(self):
        try:
            response = self._log_client.call(
                'delete_log_group',
                logGroupName=self.log_group_name)
            LOG.debug(response)
        except ClientError:
            LOG.debug('unable to delete log group')
