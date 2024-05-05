# -*- coding: utf-8 -*-
# Copyright (c) 2015 Mitch Garnaat
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

import jmespath
import boto3


LOG = logging.getLogger(__name__)

_session_cache = {}


class AWSClient(object):

    def __init__(self, service_name, session):
        self._service_name = service_name
        self._session = session
        self.client = self._create_client()

    @property
    def service_name(self):
        return self._service_name

    @property
    def session(self):
        return self._session

    @property
    def region_name(self):
        return self.client.meta.region_name

    def _create_client(self):
        client = self._session.client(self._service_name)
        return client

    def call(self, op_name, query=None, **kwargs):
        """
        Make a request to a method in this client.  The response data is
        returned from this call as native Python data structures.

        This method differs from just calling the client method directly
        in the following ways:

          * It automatically handles the pagination rather than
            relying on a separate pagination method call.
          * You can pass an optional jmespath query and this query
            will be applied to the data returned from the low-level
            call.  This allows you to tailor the returned data to be
            exactly what you want.

        :type op_name: str
        :param op_name: The name of the request you wish to make.

        :type query: str
        :param query: A jmespath query that will be applied to the
            data returned by the operation prior to returning
            it to the user.

        :type kwargs: keyword arguments
        :param kwargs: Additional keyword arguments you want to pass
            to the method when making the request.
        """
        LOG.debug(kwargs)
        if query:
            query = jmespath.compile(query)
        if self.client.can_paginate(op_name):
            paginator = self.client.get_paginator(op_name)
            results = paginator.paginate(**kwargs)
            data = results.build_full_result()
        else:
            op = getattr(self.client, op_name)
            data = op(**kwargs)
        if query:
            data = query.search(data)
        return data


def create_session(profile_name, region_name):
    global _session_cache
    session_key = '{}:{}'.format(profile_name, region_name)
    if session_key not in _session_cache:
        session = boto3.session.Session(
            region_name=region_name, profile_name=profile_name)
        _session_cache[session_key] = session
    return _session_cache[session_key]


def create_client(service_name, session):
    return AWSClient(service_name, session)
