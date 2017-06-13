from .json_import import simplejson
from six.moves.urllib.parse import urlencode
from httplib2 import Http
from hashlib import sha256
import mimetypes
import six
import hmac
import requests

class OAuth2AuthExchangeError(Exception):
    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description


class OAuth2API(object):
    host = None
    base_path = None
    authorize_url = None
    access_token_url = None
    redirect_uri = None
    # some providers use "oauth_token"
    access_token_field = "access_token"
    protocol = "https"
    # override with 'Instagram', etc
    api_name = "Generic API"

    def __init__(self, client_id=None, client_secret=None, client_ips=None, access_token=None, redirect_uri=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_ips = client_ips
        self.access_token = access_token
        self.redirect_uri = redirect_uri

    def get_authorize_login_url(self, scope=None):
        """ scope should be a tuple or list of requested scope access levels """
        req = OAuth2AuthExchangeRequest(self)
        return req.get_authorize_login_url(scope=scope)

    def exchange_code_for_access_token(self, code):
        req = OAuth2AuthExchangeRequest(self)
        return req.exchange_for_access_token(code=code)

    def exchange_user_id_for_access_token(self, user_id):
        req = OAuth2AuthExchangeRequest(self)
        return req.exchange_for_access_token(user_id=user_id)

    def exchange_xauth_login_for_access_token(self, username, password, scope=None):
        """ scope should be a tuple or list of requested scope access levels """
        req = OAuth2AuthExchangeRequest(self)
        return req.exchange_for_access_token(username=username, password=password,
                                             scope=scope)


class OAuth2AuthExchangeRequest(object):
    def __init__(self, api):
        self.api = api

    def _data_for_authorize(self, scope=None):
        scope = scope or ['basic']

        client_params = {
            "client_id": self.api.client_id,
            "response_type": "code",
            "redirect_uri": self.api.redirect_uri,
            "scope": scope
        }

        return client_params

    def _data_for_exchange(self, code=None, username=None, password=None, scope=None, user_id=None):
        client_params = {
            "client_id": self.api.client_id,
            "client_secret": self.api.client_secret,
            "redirect_uri": self.api.redirect_uri,
            "grant_type": "authorization_code"
        }
        if code:
            client_params.update(code=code)
        elif username and password:
            client_params.update(username=username,
                                 password=password,
                                 grant_type="password")
        elif user_id:
            client_params.update(user_id=user_id)
        if scope:
            client_params.update(scope='+'.join(scope))
        return client_params

    def get_authorize_login_url(self, scope=None):
        url = self.api.authorize_url
        params = self._data_for_authorize(scope)
        response = OAuth2Request(api=self.api, url=url, params=params).make_request()
        if not response.ok:
            raise OAuth2AuthExchangeError("The server returned a non-200 response for URL %s" % url)
        return response.url

    def exchange_for_access_token(self, code=None, username=None, password=None, scope=None, user_id=None, client_id=None):
        params = self._data_for_exchange(code, username, password, scope=scope, user_id=user_id)
        url = self.api.access_token_url
        response = OAuth2Request(self.api, method="POST", url=url, params=params).make_request()
        content = response.json()

        if not response.ok:
            raise OAuth2AuthExchangeError(content["error_message"])
        return content

class OAuth2Request(object):
    def __init__(self, api, path=None, method="GET", params=None, url=None, include_secret=None, headers=None, include_signed_request=None):
        self.api = api
        self.path = path
        self.method = method
        self.params = params
        self.include_secret = include_secret
        self.url = url
        self.include_signed_request = include_signed_request
        self.headers = headers

        if self.params.has_key('files'):
            self.files = params['files']
            del self.params['files']

        self._full_url()
        self._auth_params()
        self.status_code = None
        self.content = None
        self.content_json = None
        self.request = None


    def _generate_sig(self):
        sig = self.path
        for key in sorted(self.params.keys()):
            sig += '|%s=%s' % (key, self.params[key])
        return hmac.new(self.api.client_secret.encode(), sig.encode(), sha256).hexdigest()

    def _full_url(self):
        if self.url is None:
            self.url = "%s://%s%s%s" % (self.api.protocol,
                                  self.api.host,
                                  self.api.base_path,
                                  self.path)

    def _auth_params(self):
        auth_params = {}
        if self.api.access_token:
            auth_params[self.api.access_token_field] = self.api.access_token
        elif self.api.client_id:
            auth_params["client_id"] = self.api.client_id
            if self.include_secret:
                auth_params["client_secret"] = self.api.client_secret
        self.params.update(auth_params)

    def _signed_request(self):
        if self.include_signed_request and self.api.client_secret is not None:
            if self.api.access_token:
                self.params['access_token'] = self.api.access_token
            elif self.api.client_id:
                self.params['client_id'] = self.api.client_id
            if self.include_secret and self.api.client_secret:
                self.params['client_secret'] = self.api.client_secret
            return "&sig=%s" % self._generate_sig()
        else:
            return ''

    def make_request(self):

        if self.method == "POST":
            response = requests.post(self.url, data=self.params, files=self.files, headers=self.headers)
        else:
            response = requests.get(self.url, params=self.params, headers=self.headers)
        self.api.response = response
        return response
