import os

from pprint import pformat

from oic.oic import Client as OIDCClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

__author__ = 'regu0004'


class Client(object):
    # DONE specify the correct path
    ROOT_PATH = "/root/openid_course"
    # DONE specify the correct URL
    ISSUER = "https://example.com"

    def __init__(self, client_metadata):
        self.client = OIDCClient(client_authn_method=CLIENT_AUTHN_METHOD)

        # DONE get the provider configuration information
        provider_info = self.client.provider_config('https://op1.test.inacademia.org')

        # DONE register with the provider using the client_metadata
        args = {
            "redirect_uris": ['http://alex.inf.um.es:8090/code_flow_callback',
                              'http://alex.inf.um.es:8090/implicit_flow_callback'],
            "response_types": ["code", "id_token token"],
            "contacts": ["alex@um.es"]
        }

        registration_response = self.client.register(provider_info["registration_endpoint"], **args)

    def authenticate(self, session):
        # Use the session object to store state between requests

        # DONE make authentication request
        from oic import rndstr
        from oic.utils.http_util import Redirect

        session["state"] = rndstr()
        session["nonce"] = rndstr()
        args = {
            "client_id": self.client.client_id,
           # "response_type": "code",
            "response_type": ["id_token", "token"],
            "scope": ["email openid"],
            "nonce": session["nonce"],
            "redirect_uri": self.client.registration_response["redirect_uris"][1],
            "state": session["state"]
        }

        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        print(auth_req)

        # DONE insert the redirect URL
        login_url = auth_req.request(self.client.authorization_endpoint)

        return login_url

    def code_flow_callback(self, auth_response, session):
        # DONE parse the authentication response
        from oic.oic.message import AuthorizationResponse
        aresp = self.client.parse_response(AuthorizationResponse, info=auth_response, sformat="urlencoded")

        # DONE validate the 'state' parameter
        assert aresp['state'] == session['state']

        # DONE make token request
        args = {
            "code": aresp["code"]
        }

        resp = self.client.do_access_token_request(state=aresp["state"],
                                                   request_args=args,
                                                   authn_method="client_secret_basic")


        # DONE? validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        assert(session['nonce'] == resp['id_token']['nonce'])

        # DONE make userinfo request
        userinfo = self.client.do_user_info_request(state=aresp["state"])

        # DONE set the appropriate values
        access_code = aresp['code']
        access_token = resp['access_token']
        id_token_claims = resp['id_token']
        userinfo = userinfo

        return success_page(access_code, access_token, id_token_claims, userinfo)

    def implicit_flow_callback(self, auth_response, session):
        # DONE parse the authentication response
        from oic.oic.message import AuthorizationResponse
        aresp = self.client.parse_response(AuthorizationResponse, info=auth_response, sformat="urlencoded")

        # DONE validate the 'state' parameter
        assert aresp['state'] == session['state']

        # DONE? validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)
        assert(session['nonce'] == aresp['id_token']['nonce'])

        # DONE set the appropriate values
        userinfo = self.client.do_user_info_request(state=aresp["state"])
        print(userinfo)

        access_token = aresp['access_token']
        id_token_claims = aresp['id_token']
        userinfo = userinfo

        return success_page(None, access_token, id_token_claims, userinfo)


def success_page(auth_code, access_token, id_token_claims, userinfo):
    html_page = read_from_file("success_page.html")
    return html_page.format(auth_code, access_token,
                            pformat(id_token_claims.to_dict()),
                            pformat(userinfo.to_dict()))


def read_from_file(path):
    full_path = os.path.join(Client.ROOT_PATH, path)
    with open(full_path, "r") as f:
        return f.read()
