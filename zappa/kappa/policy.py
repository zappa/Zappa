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
import json
import hashlib

import kappa.awsclient

LOG = logging.getLogger(__name__)


class Policy(object):

    _path_prefix = '/kappa/'

    def __init__(self, context, config):
        self.context = context
        self.config = config
        self._iam_client = kappa.awsclient.create_client(
            'iam', self.context.session)
        self._arn = self.config['policy'].get('arn', None)

    @property
    def name(self):
        return '{}_{}'.format(self.context.name, self.context.environment)

    @property
    def description(self):
        return 'A kappa policy to control access to {} resources'.format(
            self.context.environment)

    def document(self):
        if ('resources' not in self.config['policy'] and
                'statements' not in self.config['policy']):
            return None
        document = {'Version': '2012-10-17'}
        statements = []
        document['Statement'] = statements
        for resource in self.config['policy'].get('resources', []):
            arn = resource['arn']
            _, _, service, _ = arn.split(':', 3)
            statement = {"Effect": "Allow",
                         "Resource": resource['arn']}
            actions = []
            for action in resource['actions']:
                actions.append("{}:{}".format(service, action))
            statement['Action'] = actions
            statements.append(statement)
        for statement in self.config['policy'].get('statements', []):
            statements.append(statement)
        return json.dumps(document, indent=2, sort_keys=True)

    @property
    def arn(self):
        if self._arn is None:
            policy = self.exists()
            if policy:
                self._arn = policy.get('Arn', None)
        return self._arn

    def _find_all_policies(self):
        try:
            response = self._iam_client.call(
                'list_policies', PathPrefix=self._path_prefix)
        except Exception:
            LOG.exception('Error listing policies')
            response = {}
        return response.get('Policies', list())

    def _list_versions(self):
        try:
            response = self._iam_client.call(
                'list_policy_versions',
                PolicyArn=self.arn)
        except Exception:
            LOG.exception('Error listing policy versions')
            response = {}
        return response.get('Versions', list())

    def exists(self):
        for policy in self._find_all_policies():
            if policy['PolicyName'] == self.name:
                return policy
        return None

    def _add_policy_version(self):
        document = self.document()
        if not document:
            LOG.debug('not a custom policy, no need to version it')
            return
        versions = self._list_versions()
        if len(versions) == 5:
            try:
                response = self._iam_client.call(
                    'delete_policy_version',
                    PolicyArn=self.arn,
                    VersionId=versions[-1]['VersionId'])
            except Exception:
                LOG.exception('Unable to delete policy version')
        # update policy with a new version here
        try:
            response = self._iam_client.call(
                'create_policy_version',
                PolicyArn=self.arn,
                PolicyDocument=document,
                SetAsDefault=True)
            LOG.debug(response)
        except Exception:
            LOG.exception('Error creating new Policy version')

    def _check_md5(self, document):
        m = hashlib.md5()
        m.update(document.encode('utf-8'))
        policy_md5 = m.hexdigest()
        cached_md5 = self.context.get_cache_value('policy_md5')
        LOG.debug('policy_md5: %s', policy_md5)
        LOG.debug('cached md5: %s', cached_md5)
        if policy_md5 != cached_md5:
            self.context.set_cache_value('policy_md5', policy_md5)
            return True
        return False

    def deploy(self):
        LOG.info('deploying policy %s', self.name)
        document = self.document()
        if not document:
            LOG.info('not a custom policy, no need to create it')
            return
        policy = self.exists()
        if policy:
            if self._check_md5(document):
                self._add_policy_version()
            else:
                LOG.info('policy unchanged')
        else:
            # create a new policy
            self._check_md5(document)
            try:
                response = self._iam_client.call(
                    'create_policy',
                    Path=self._path_prefix, PolicyName=self.name,
                    PolicyDocument=document,
                    Description=self.description)
                LOG.debug(response)
            except Exception:
                LOG.exception('Error creating Policy')

    def delete(self):
        response = None
        # Only delete the policy if it has a document associated with it.
        # This indicates that it was a custom policy created by kappa.
        document = self.document()
        if self.arn and document:
            LOG.info('deleting policy %s', self.name)
            LOG.info('deleting all policy versions for %s', self.name)
            versions = self._list_versions()
            for version in versions:
                LOG.debug('deleting version %s', version['VersionId'])
                if not version['IsDefaultVersion']:
                    try:
                        response = self._iam_client.call(
                            'delete_policy_version',
                            PolicyArn=self.arn,
                            VersionId=version['VersionId'])
                    except Exception:
                        LOG.exception('Unable to delete policy version %s',
                                      version['VersionId'])
            LOG.debug('now delete policy')
            response = self._iam_client.call(
                'delete_policy', PolicyArn=self.arn)
            LOG.debug(response)
        return response

    def status(self):
        LOG.debug('getting status for policy %s', self.name)
        return self.exists()
