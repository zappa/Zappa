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

import hashlib
import logging
import os
import shutil
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

import kappa.awsclient
import kappa.log

LOG = logging.getLogger(__name__)


class Function(object):

    excluded_dirs = ['boto3', 'botocore', 'concurrent', 'dateutil',
                     'docutils', 'futures', 'jmespath', 'python_dateutil']
    excluded_files = ['.gitignore']

    def __init__(self, context, config):
        self._context = context
        self._config = config
        self._lambda_client = kappa.awsclient.create_client(
            'lambda', context.session)
        self._response = None
        self._log = None

    @property
    def name(self):
        return self._context.name

    @property
    def runtime(self):
        return self._config['runtime']

    @property
    def handler(self):
        return self._config['handler']

    @property
    def dependencies(self):
        return self._config.get('dependencies', list())

    @property
    def description(self):
        return self._config['description']

    @property
    def timeout(self):
        return self._config['timeout']

    @property
    def memory_size(self):
        return self._config['memory_size']

    @property
    def vpc_config(self):
        vpc_config = {}
        if 'vpc_config' in self._config:
            if 'security_group_ids' in self._config['vpc_config']:
                sgids = self._config['vpc_config']['security_group_ids']
                vpc_config['SecurityGroupIds'] = sgids
            if 'subnet_ids' in self._config['vpc_config']:
                snids = self._config['vpc_config']['subnet_ids']
                vpc_config['SubnetIds'] = snids
        return vpc_config

    @property
    def zipfile_name(self):
        return '{}.zip'.format(self._context.name)

    @property
    def tests(self):
        return self._config.get('tests', '_tests')

    @property
    def permissions(self):
        return self._config.get('permissions', list())

    @property
    def log(self):
        if self._log is None:
            log_group_name = '/aws/lambda/%s' % self.name
            self._log = kappa.log.Log(self._context, log_group_name)
        return self._log

    @property
    def code_sha_256(self):
        return self._get_response_configuration('CodeSha256')

    @property
    def arn(self):
        return self._get_response_configuration('FunctionArn')

    @property
    def alias_arn(self):
        return self.arn + ':{}'.format(self._context.environment)

    @property
    def repository_type(self):
        return self._get_response_code('RepositoryType')

    @property
    def location(self):
        return self._get_response_code('Location')

    @property
    def version(self):
        return self._get_response_configuration('Version')

    @property
    def deployment_uri(self):
        return 'https://{}.execute-api.{}.amazonaws.com/{}'.format(
            self.api_id, self._apigateway_client.region_name,
            self._context.environment)

    def _get_response(self):
        if self._response is None:
            try:
                self._response = self._lambda_client.call(
                    'get_function',
                    FunctionName=self.name)
                LOG.debug(self._response)
            except Exception:
                LOG.debug('Unable to find ARN for function: %s', self.name)
        return self._response

    def _get_response_configuration(self, key, default=None):
        value = None
        response = self._get_response()
        if response:
            if 'Configuration' in response:
                value = response['Configuration'].get(key, default)
        return value

    def _get_response_code(self, key, default=None):
        value = None
        response = self._get_response
        if response:
            if 'Configuration' in response:
                value = response['Configuration'].get(key, default)
        return value

    def _check_function_md5(self):
        # Zip up the source code and then compute the MD5 of that.
        # If the MD5 does not match the cached MD5, the function has
        # changed and needs to be updated so return True.
        changed = True
        self._copy_config_file()
        files = [] + self.dependencies + [self._context.source_dir]
        self.zip_lambda_function(self.zipfile_name, files)
        m = hashlib.md5()
        with open(self.zipfile_name, 'rb') as fp:
            m.update(fp.read())
        zip_md5 = m.hexdigest()
        cached_md5 = self._context.get_cache_value('zip_md5')
        LOG.debug('zip_md5: %s', zip_md5)
        LOG.debug('cached md5: %s', cached_md5)
        if zip_md5 != cached_md5:
            self._context.set_cache_value('zip_md5', zip_md5)
        else:
            changed = False
            LOG.info('function unchanged')
        return changed

    def _check_config_md5(self):
        # Compute the MD5 of all of the components of the configuration.
        # If the MD5 does not match the cached MD5, the configuration has
        # changed and needs to be updated so return True.
        m = hashlib.md5()
        m.update(self.description.encode('utf-8'))
        m.update(self.handler.encode('utf-8'))
        m.update(str(self.memory_size).encode('utf-8'))
        m.update(self._context.exec_role_arn.encode('utf-8'))
        m.update(str(self.timeout).encode('utf-8'))
        m.update(str(self.vpc_config).encode('utf-8'))
        config_md5 = m.hexdigest()
        cached_md5 = self._context.get_cache_value('config_md5')
        LOG.debug('config_md5: %s', config_md5)
        LOG.debug('cached_md5: %s', cached_md5)
        if config_md5 != cached_md5:
            self._context.set_cache_value('config_md5', config_md5)
            changed = True
        else:
            changed = False
        return changed

    def _copy_config_file(self):
        config_name = '{}_config.json'.format(self._context.environment)
        config_path = os.path.join(self._context.source_dir, config_name)
        if os.path.exists(config_path):
            dest_path = os.path.join(self._context.source_dir, 'config.json')
            LOG.debug('copy %s to %s', config_path, dest_path)
            shutil.copy2(config_path, dest_path)

    def _zip_lambda_dir(self, zipfile_name, lambda_dir):
        LOG.debug('_zip_lambda_dir: lambda_dir=%s', lambda_dir)
        LOG.debug('zipfile_name=%s', zipfile_name)
        relroot = os.path.abspath(lambda_dir)
        with zipfile.ZipFile(zipfile_name, 'a',
                             compression=zipfile.ZIP_DEFLATED) as zf:
            for root, subdirs, files in os.walk(lambda_dir):
                excluded_dirs = []
                for subdir in subdirs:
                    for excluded in self.excluded_dirs:
                        if subdir.startswith(excluded):
                            excluded_dirs.append(subdir)
                for excluded in excluded_dirs:
                    subdirs.remove(excluded)

                try:
                    dir_path = os.path.relpath(root, relroot)
                    dir_path = os.path.normpath(
                        os.path.splitdrive(dir_path)[1]
                    )
                    while dir_path[0] in (os.sep, os.altsep):
                        dir_path = dir_path[1:]
                    dir_path += '/'
                    zf.getinfo(dir_path)
                except KeyError:
                    zf.write(root, dir_path)

                for filename in files:
                    if filename not in self.excluded_files:
                        filepath = os.path.join(root, filename)
                        if os.path.isfile(filepath):
                            arcname = os.path.join(
                                os.path.relpath(root, relroot), filename)
                            try:
                                zf.getinfo(arcname)
                            except KeyError:
                                zf.write(filepath, arcname)

    def _zip_lambda_file(self, zipfile_name, lambda_file):
        LOG.debug('_zip_lambda_file: lambda_file=%s', lambda_file)
        LOG.debug('zipfile_name=%s', zipfile_name)
        with zipfile.ZipFile(zipfile_name, 'a',
                             compression=zipfile.ZIP_DEFLATED) as zf:
            try:
                zf.getinfo(lambda_file)
            except KeyError:
                zf.write(lambda_file)

    def zip_lambda_function(self, zipfile_name, files):
        try:
            os.remove(zipfile_name)
        except OSError:
            pass
        for f in files:
            LOG.debug('adding file %s', f)
            if os.path.isdir(f):
                self._zip_lambda_dir(zipfile_name, f)
            else:
                self._zip_lambda_file(zipfile_name, f)

    def exists(self):
        return self._get_response()

    def tail(self, attempt=0):
        try:
            LOG.debug('tailing function: %s', self.name)
            return self.log.tail()
        except Exception as e:
            if attempt > 10:
                return e

            time.sleep(attempt)
            return self.tail(attempt + 1)

    def list_aliases(self):
        LOG.info('listing aliases of %s', self.name)
        try:
            response = self._lambda_client.call(
                'list_aliases',
                FunctionName=self.name)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to list aliases')
        return response.get('Versions', list())

    def find_latest_version(self):
        # Find the current (latest) version by version number
        # First find the SHA256 of $LATEST
        versions = self.list_versions()
        for v in versions:
            if v['Version'] == '$LATEST':
                latest_sha256 = v['CodeSha256']
                break
        for v in versions:
            if v['Version'] != '$LATEST':
                if v['CodeSha256'] == latest_sha256:
                    version = v['Version']
                    break
        return version

    def create_alias(self, name, description, version=None):
        if not version:
            version = self.find_latest_version()
        try:
            LOG.debug('creating alias %s=%s', name, version)
            response = self._lambda_client.call(
                'create_alias',
                FunctionName=self.name,
                Description=description,
                FunctionVersion=version,
                Name=name)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to create alias')

    def update_alias(self, name, description, version=None):
        # Find the current (latest) version by version number
        # First find the SHA256 of $LATEST
        if not version:
            version = self.find_latest_version()
        try:
            LOG.debug('updating alias %s=%s', name, version)
            response = self._lambda_client.call(
                'update_alias',
                FunctionName=self.name,
                Description=description,
                FunctionVersion=version,
                Name=name)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to update alias')

    def add_permission(self, action, principal,
                       source_arn=None, source_account=None):
        try:
            kwargs = {
                'FunctionName': self.name,
                'Qualifier': self._context.environment,
                'StatementId': str(uuid.uuid4()),
                'Action': action,
                'Principal': principal}
            if source_arn:
                kwargs['SourceArn'] = source_arn
            if source_account:
                kwargs['SourceAccount'] = source_account
            response = self._lambda_client.call(
                'add_permission', **kwargs)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to add permission')

    def add_permissions(self):
        if self.permissions:
            time.sleep(5)
        for permission in self.permissions:
            self.add_permission(
                permission['action'],
                permission['principal'],
                permission.get('source_arn'),
                permission.get('source_account'))

    def create(self):
        LOG.info('creating function %s', self.name)
        self._check_function_md5()
        self._check_config_md5()
        # There is a consistency problem here.
        # Sometimes the role is not ready to be used by the function.
        ready = False
        while not ready:
            with open(self.zipfile_name, 'rb') as fp:
                exec_role = self._context.exec_role_arn
                LOG.debug('exec_role=%s', exec_role)
                try:
                    zipdata = fp.read()
                    response = self._lambda_client.call(
                        'create_function',
                        FunctionName=self.name,
                        Code={'ZipFile': zipdata},
                        Runtime=self.runtime,
                        Role=exec_role,
                        Handler=self.handler,
                        Description=self.description,
                        Timeout=self.timeout,
                        MemorySize=self.memory_size,
                        VpcConfig=self.vpc_config,
                        Publish=True)
                    LOG.debug(response)
                    description = 'For stage {}'.format(
                        self._context.environment)
                    self.create_alias(self._context.environment, description)
                    ready = True
                except ClientError as e:
                    if 'InvalidParameterValueException' in str(e):
                        LOG.debug('Role is not ready, waiting')
                        time.sleep(2)
                    else:
                        LOG.debug(str(e))
                        ready = True
                except Exception:
                    LOG.exception('Unable to upload zip file')
                    ready = True
        self.add_permissions()

    def update(self):
        LOG.info('updating function %s', self.name)
        if self._check_function_md5():
            self._response = None
            with open(self.zipfile_name, 'rb') as fp:
                try:
                    LOG.info('uploading new function zipfile %s',
                             self.zipfile_name)
                    zipdata = fp.read()
                    response = self._lambda_client.call(
                        'update_function_code',
                        FunctionName=self.name,
                        ZipFile=zipdata,
                        Publish=True)
                    LOG.debug(response)
                    self.update_alias(
                        self._context.environment,
                        'For the {} stage'.format(self._context.environment))
                except Exception:
                    LOG.exception('unable to update zip file')

    def update_configuration(self):
        if self._check_config_md5():
            self._response = None
            LOG.info('updating configuration for %s', self.name)
            exec_role = self._context.exec_role_arn
            LOG.debug('exec_role=%s', exec_role)
            try:
                response = self._lambda_client.call(
                    'update_function_configuration',
                    FunctionName=self.name,
                    VpcConfig=self.vpc_config,
                    Role=exec_role,
                    Handler=self.handler,
                    Description=self.description,
                    Timeout=self.timeout,
                    MemorySize=self.memory_size)
                LOG.debug(response)
            except Exception:
                LOG.exception('unable to update function configuration')
        else:
            LOG.info('function configuration has not changed')

    def deploy(self):
        if self.exists():
            self.update_configuration()
            return self.update()
        return self.create()

    def list_versions(self):
        try:
            response = self._lambda_client.call(
                'list_versions_by_function',
                FunctionName=self.name)
            LOG.debug(response)
        except Exception:
            LOG.exception('Unable to list versions')
        return response['Versions']

    def tag(self, name, description):
        self.create_alias(name, description)

    def delete(self):
        LOG.info('deleting function %s', self.name)
        response = None
        try:
            response = self._lambda_client.call(
                'delete_function',
                FunctionName=self.name)
            LOG.debug(response)
        except ClientError:
            LOG.debug('function %s: not found', self.name)
        return response

    def status(self):
        try:
            response = self._lambda_client.call(
                'get_function',
                FunctionName=self.name)
            LOG.debug(response)
        except ClientError:
            LOG.debug('function %s not found', self.name)
            response = None
        return response

    def _invoke(self, data, invocation_type):
        LOG.debug('invoke %s as %s', self.name, invocation_type)
        response = self._lambda_client.call(
            'invoke',
            FunctionName=self.name,
            InvocationType=invocation_type,
            LogType='Tail',
            Payload=data)
        LOG.debug(response)
        return response

    def invoke(self, test_data=None):
        return self._invoke(test_data, 'RequestResponse')

    def invoke_async(self, test_data=None):
        return self._invoke(test_data, 'Event')

    def dryrun(self, test_data=None):
        return self._invoke(test_data, 'DryRun')
