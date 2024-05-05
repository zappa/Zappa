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
import kappa.log

LOG = logging.getLogger(__name__)


class RestApi(object):

    def __init__(self, context, config):
        self._context = context
        self._config = config
        self._apigateway_client = kappa.awsclient.create_client(
            'apigateway', context.session)
        self._api = None
        self._resources = None
        self._resource = None

    @property
    def arn(self):
        _, _, _, region, account, _ = self._context.function.arn.split(':', 5)
        arn = 'arn:aws:execute-api:{}:{}:{}/*/*/{}'.format(
            region, account, self.api_id, self.resource_name)
        return arn

    @property
    def api_name(self):
        return self._config['name']

    @property
    def description(self):
        return self._config['description']

    @property
    def resource_name(self):
        return self._config['resource']['name']

    @property
    def parent_resource(self):
        return self._config['resource']['parent']

    @property
    def full_path(self):
        parts = self.parent_resource.split('/')
        parts.append(self.resource_name)
        return '/'.join(parts)

    @property
    def api_id(self):
        api = self._get_api()
        return api.get('id')

    @property
    def resource_id(self):
        resources = self._get_resources()
        return resources.get(self.full_path).get('id')

    def _get_api(self):
        if self._api is None:
            try:
                response = self._apigateway_client.call(
                    'get_rest_apis')
                LOG.debug(response)
                for item in response['items']:
                    if item['name'] == self.api_name:
                        self._api = item
            except Exception:
                LOG.exception('Error finding restapi')
        return self._api

    def _get_resources(self):
        if self._resources is None:
            try:
                response = self._apigateway_client.call(
                    'get_resources',
                    restApiId=self.api_id)
                LOG.debug(response)
                self._resources = {}
                for item in response['items']:
                    self._resources[item['path']] = item
            except Exception:
                LOG.exception('Unable to find resources for: %s',
                              self.api_name)
        return self._resources

    def create_restapi(self):
        if not self.api_exists():
            LOG.info('creating restapi %s', self.api_name)
            try:
                response = self._apigateway_client.call(
                    'create_rest_api',
                    name=self.api_name,
                    description=self.description)
                LOG.debug(response)
            except Exception:
                LOG.exception('Unable to create new restapi')

    def create_resource_path(self):
        path = self.full_path
        parts = path.split('/')
        resources = self._get_resources()
        parent = None
        build_path = []
        for part in parts:
            LOG.debug('part=%s', part)
            build_path.append(part)
            LOG.debug('build_path=%s', build_path)
            full_path = '/'.join(build_path)
            LOG.debug('full_path=%s', full_path)
            if full_path is '':
                parent = resources['/']
            else:
                if full_path not in resources and parent:
                    try:
                        response = self._apigateway_client.call(
                            'create_resource',
                            restApiId=self.api_id,
                            parentId=parent['id'],
                            pathPart=part)
                        LOG.debug(response)
                        resources[full_path] = response
                    except Exception:
                        LOG.exception('Unable to create new resource')
                parent = resources[full_path]
        self._item = resources[path]

    def create_method(self, method, config):
        LOG.info('creating method: %s', method)
        try:
            response = self._apigateway_client.call(
                'put_method',
                restApiId=self.api_id,
                resourceId=self.resource_id,
                httpMethod=method,
                authorizationType=config.get('authorization_type'),
                apiKeyRequired=config.get('apikey_required', False)
            )
            LOG.debug(response)
            LOG.debug('now create integration')
            uri = 'arn:aws:apigateway:{}:'.format(
                self._apigateway_client.region_name)
            uri += 'lambda:path/2015-03-31/functions/'
            uri += self._context.function.arn
            uri += ':${stageVariables.environment}/invocations'
            LOG.debug(uri)
            response = self._apigateway_client.call(
                'put_integration',
                restApiId=self.api_id,
                resourceId=self.resource_id,
                httpMethod=method,
                integrationHttpMethod=method,
                type='AWS',
                uri=uri
            )
        except Exception:
            LOG.exception('Unable to create integration: %s', method)

    def create_deployment(self):
        LOG.info('creating a deployment for %s to stage: %s',
                 self.api_name, self._context.environment)
        try:
            response = self._apigateway_client.call(
                'create_deployment',
                restApiId=self.api_id,
                stageName=self._context.environment
            )
            LOG.debug(response)
            LOG.info('Now deployed to: %s', self.deployment_uri)
        except Exception:
            LOG.exception('Unable to create a deployment')

    def create_methods(self):
        resource_config = self._config['resource']
        for method in resource_config.get('methods', dict()):
            if not self.method_exists(method):
                method_config = resource_config['methods'][method]
                self.create_method(method, method_config)

    def api_exists(self):
        return self._get_api()

    def resource_exists(self):
        resources = self._get_resources()
        return resources.get(self.full_path)

    def method_exists(self, method):
        exists = False
        resource = self.resource_exists()
        if resource:
            methods = resource.get('resourceMethods')
            if methods:
                for method_name in methods:
                    if method_name == method:
                        exists = True
        return exists

    def find_parent_resource_id(self):
        parent_id = None
        resources = self._get_resources()
        for item in resources:
            if item['path'] == self.parent:
                parent_id = item['id']
        return parent_id

    def api_update(self):
        LOG.info('updating restapi %s', self.api_name)

    def resource_update(self):
        LOG.info('updating resource %s', self.full_path)

    def add_permission(self):
        LOG.info('Adding permission for APIGateway to call function')
        self._context.function.add_permission(
            action='lambda:InvokeFunction',
            principal='apigateway.amazonaws.com',
            source_arn=self.arn)

    def deploy(self):
        if self.api_exists():
            self.api_update()
        else:
            self.create_restapi()
        if self.resource_exists():
            self.resource_update()
        else:
            self.create_resource_path()
            self.create_methods()
            self.add_permission()

    def delete(self):
        LOG.info('deleting resource %s', self.resource_name)
        try:
            response = self._apigateway_client.call(
                'delete_resource',
                restApiId=self.api_id,
                resourceId=self.resource_id)
            LOG.debug(response)
        except ClientError:
            LOG.exception('Unable to delete resource %s', self.resource_name)
        return response

    def status(self):
        try:
            response = self._apigateway_client.call(
                'delete_',
                FunctionName=self.name)
            LOG.debug(response)
        except ClientError:
            LOG.exception('function %s not found', self.name)
            response = None
        return response
