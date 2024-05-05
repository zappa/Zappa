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


AssumeRolePolicyDocument = """{
    "Version" : "2012-10-17",
    "Statement": [ {
        "Effect": "Allow",
        "Principal": {
            "Service": [ "lambda.amazonaws.com" ]
        },
        "Action": [ "sts:AssumeRole" ]
    } ]
}"""


class Role(object):

    Path = '/kappa/'

    def __init__(self, context, config, iam_client=None):
        self._context = context
        self._config = config
        self._iam_client = iam_client
        if not iam_client:
            self._iam_client = kappa.awsclient.create_client(
                'iam', context.session)
        self._arn = None

    @property
    def name(self):
        return '{}_{}'.format(self._context.name, self._context.environment)

    @property
    def arn(self):
        if self._arn is None:
            role = self._get_role()
            if role:
                self._arn = role['Arn']
            else:
                LOG.debug('Unable to find ARN for role: %s', self.name)
        return self._arn

    def _get_role(self):
        try:
            response = self._iam_client.call('get_role', RoleName=self.name)
            if response and 'Role' in response:
                response = response['Role']
            return response
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                LOG.exception('Error getting role')
        except Exception:
            LOG.exception('Error getting role')
        return None

    def exists(self):
        return self._get_role() is not None

    def create(self):
        LOG.info('creating role %s', self.name)
        role = self.exists()
        if not role:
            try:
                response = self._iam_client.call(
                    'create_role',
                    Path=self.Path, RoleName=self.name,
                    AssumeRolePolicyDocument=AssumeRolePolicyDocument)
                LOG.debug(response)
                if self._context.policy:
                    LOG.debug('attaching policy %s', self._context.policy.arn)
                    response = self._iam_client.call(
                        'attach_role_policy',
                        RoleName=self.name,
                        PolicyArn=self._context.policy.arn)
                    LOG.debug(response)
            except ClientError:
                LOG.exception('Error creating Role')
        else:
            LOG.info('role already exists')

    def delete(self):
        response = None
        if not self.exists():
            LOG.debug('role %s does not exist - skipping delete', self.name)
            return response

        LOG.debug('deleting role %s', self.name)
        try:
            LOG.debug('First detach the policy from the role')
            policy_arn = self._context.policy.arn
            if policy_arn:
                response = self._iam_client.call(
                    'detach_role_policy',
                    RoleName=self.name, PolicyArn=policy_arn)
                LOG.debug(response)
            response = self._iam_client.call(
                'delete_role', RoleName=self.name)
            LOG.debug(response)
        except ClientError:
            LOG.exception('role %s not found', self.name)
        return response

    def status(self):
        LOG.debug('getting status for role %s', self.name)
        role = self._get_role()
        if not role:
            LOG.debug('role %s not found', self.name)
        return role
