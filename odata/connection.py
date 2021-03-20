# -*- coding: utf-8 -*-

import json
import functools
import logging

from aiohttp import ClientError

from odata import version
from .exceptions import ODataError, ODataConnectionError


def catch_requests_errors(fn):
    @functools.wraps(fn)
    def inner(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            raise ODataConnectionError(str(e))
    return inner


class ODataConnection(object):

    base_headers = {
        'Accept': 'application/json',
        'OData-Version': '4.0',
        'User-Agent': 'python-odata {0}'.format(version),
    }
    timeout = 90

    def __init__(self, session=None, auth=None):
        self.session = session
        self.auth = auth
        self.log = logging.getLogger('odata.connection')

    def _apply_options(self, kwargs):
        kwargs['timeout'] = self.timeout

        if self.auth is not None:
            kwargs['auth'] = self.auth

    @catch_requests_errors
    async def _do_get(self, *args, **kwargs):
        self._apply_options(kwargs)
        return await self.session.get(*args, **kwargs)

    @catch_requests_errors
    async def _do_post(self, *args, **kwargs):
        self._apply_options(kwargs)
        return await self.session.post(*args, **kwargs)

    @catch_requests_errors
    async def _do_patch(self, *args, **kwargs):
        self._apply_options(kwargs)
        return await self.session.patch(*args, **kwargs)

    @catch_requests_errors
    async def _do_delete(self, *args, **kwargs):
        self._apply_options(kwargs)
        return await self.session.delete(*args, **kwargs)

    async def _handle_odata_error(self, response):
        try:
            response.raise_for_status()
        except:
            status_code = 'HTTP {0}'.format(response.status)
            code = 'None'
            message = 'Server did not supply any error messages'
            detailed_message = 'None'
            response_ct = response.headers.get('content-type', '')

            if 'application/json' in response_ct:
                errordata = await response.json()

                if 'error' in errordata:
                    odata_error = errordata.get('error')

                    if 'code' in odata_error:
                        code = odata_error.get('code') or code
                    if 'message' in odata_error:
                        message = odata_error.get('message') or message
                    if 'innererror' in odata_error:
                        ie = odata_error['innererror']
                        detailed_message = ie.get('message') or detailed_message

            msg = ' | '.join([status_code, code, message, detailed_message])
            err = ODataError(msg)
            err.status_code = status_code
            err.code = code
            err.message = message
            err.detailed_message = detailed_message
            raise err

    async def execute_get(self, url, params=None):
        headers = {}
        headers.update(self.base_headers)

        self.log.info(u'GET {0}'.format(url))
        if params:
            self.log.info(u'Query: {0}'.format(params))

        response = await self._do_get(url, params=params, headers=headers)
        await self._handle_odata_error(response)
        response_ct = response.headers.get('content-type', '')
        if response.status == 204:
            return
        if 'application/json' in response_ct:
            data = await response.json()
            return data
        else:
            msg = u'Unsupported response Content-Type: {0}'.format(response_ct)
            raise ODataError(msg)

    async def execute_post(self, url, data, params=None):
        headers = {
            'Content-Type': 'application/json',
        }
        headers.update(self.base_headers)

        data = json.dumps(data)

        self.log.info(u'POST {0}'.format(url))
        self.log.info(u'Payload: {0}'.format(data))

        response = await self._do_post(url, data=data, headers=headers, params=params)
        await self._handle_odata_error(response)
        response_ct = response.headers.get('content-type', '')
        if response.status == 204:
            return
        if 'application/json' in response_ct:
            return await response.json()
        # no exceptions here, POSTing to Actions may not return data

    async def execute_patch(self, url, data):
        headers = {
            'Content-Type': 'application/json',
        }
        headers.update(self.base_headers)

        data = json.dumps(data)

        self.log.info(u'PATCH {0}'.format(url))
        self.log.info(u'Payload: {0}'.format(data))

        response = await self._do_patch(url, data=data, headers=headers)
        await self._handle_odata_error(response)

    async def execute_delete(self, url):
        headers = {}
        headers.update(self.base_headers)

        self.log.info(u'DELETE {0}'.format(url))

        response = await self._do_delete(url, headers=headers)
        await self._handle_odata_error(response)
