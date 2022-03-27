# # -*- coding: utf-8 -*- 
import json

import requests

from odoo import api, fields, models
from odoo.exceptions import AccessDenied, UserError
from odoo.addons.auth_signup.models.res_users import SignupError

from odoo.addons.auth_oauth.models import res_users

from odoo.addons import base
base.models.res_users.USER_PRIVATE_FIELDS.append('oauth_access_token')

class AuthOAuthProvider(models.Model):
    _inherit = 'auth.oauth.provider'

    client_secret_key = fields.Char(string="Client Secret Key")     
    application = fields.Selection([('other', 'Other'),('github', 'Github')])
    redirect_url = fields.Char(string="Redirect URL")

class ResUsers(models.Model):
    _inherit = 'res.users'

    @api.model
    def _auth_oauth_rpc(self, endpoint, access_token):

        return requests.get(endpoint, params={'access_token': access_token}).json()


    @api.model
    def _auth_oauth_validate(self, provider, access_token):
        """ return the validation data corresponding to the access token """
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        if oauth_provider.application == 'github':
            secrect_key = oauth_provider.client_secret_key
            redirect_url = oauth_provider.redirect_url + '/auth_oauth/signin'
            headers = {'content-type': 'application/json'}
            pay_load = {
                        'client_id':oauth_provider.client_id,   
                        'client_secret':secrect_key,
                        'code':access_token,
                        'redirect_uri':redirect_url
                        }
            r = requests.get('https://github.com/login/oauth/access_token', data=json.dumps(pay_load), headers=headers)
            b = r.text.split('=')
            c = b[1].split('&')
            access_token=c[0]  
            headers = {'Authorization': 'token '+access_token}
            response = requests.get('https://api.github.com/user', headers=headers)
            validation = response.json().copy()
            validation['access_token']=access_token   
        else:  
            validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token)
        if validation.get("error"):
            raise Exception(validation['error'])
        if oauth_provider.data_endpoint:
            data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
            validation.update(data)
        return validation 

    @api.model
    def _generate_signup_values(self, provider, validation, params):
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        
        if oauth_provider.application == 'github':
            oauth_uid = validation['user_id']
            email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
            name = validation.get('login', email)
            return {
                'name': name,
                'login': name,
                'email': email,
                'oauth_provider_id': provider,
                'oauth_uid': oauth_uid,
                'oauth_access_token': validation['access_token'],
                'active': True,
            }
        else:
            oauth_uid = validation['user_id']
            email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
            name = validation.get('name', email)
            return {
                'name': name,
                'login': email,
                'email': email,
                'oauth_provider_id': provider,
                'oauth_uid': oauth_uid,
                'oauth_access_token': params['access_token'],
                'active': True,
            }

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        # Advice by Google (to avoid Confused Deputy Problem)
        # if validation.audience != OUR_CLIENT_ID:
        #   abort()
        # else:
        #   continue with the process
        if oauth_provider.application == 'github':
            access_token = params.get('code')
        else:
            access_token = params.get('access_token')
        validation = self._auth_oauth_validate(provider, access_token)
        if oauth_provider.application == 'github':
            access_token = validation.get('access_token') 
        else:
            access_token = params.get('access_token')
        # required check
        if not validation.get('user_id'):
            # Workaround: facebook does not send 'user_id' in Open Graph Api
            if validation.get('id'):
                validation['user_id'] = validation['id']
            else:
                raise AccessDenied()

        # retrieve and sign in user
        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        # return user credentials
        return (self.env.cr.dbname, login, access_token)   

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        oauth_uid = validation['user_id']
        try:
            oauth_user = self.search([("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider)])
            oauth_provider = self.env['auth.oauth.provider'].browse(provider)
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1
            if oauth_provider.application == 'github':
                oauth_user.write({'oauth_access_token': validation['access_token']})
            else:
                oauth_user.write({'oauth_access_token': params['access_token']})
            return oauth_user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            state = json.loads(params['state'])
            token = state.get('t')
            values = self._generate_signup_values(provider, validation, params)
            try:
                _, login, _ = self.signup(values, token)
                return login
            except (SignupError, UserError):
                raise access_denied_exception
