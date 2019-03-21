import logging

from hashlib import md5

import ckan.plugins as plugins
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.plugins.toolkit import config

HEADER_USERNAME = "sec-username"
HEADER_ROLES = "sec-roles"
HEADER_ORG = "sec-org"
HEADER_EMAIL = "sec-email"
HEADER_FIRSTNAME = "sec-firstname"
HEADER_LASTNAME = "sec-lastname"
HEADER_TEL = "sec-tel"


def auth_function_disabled(context, data_dict=None):
    # TODO : consider to return true in some "sysadmin" context. For instance to create organization
    return {
        'success': True,
        'msg': 'Authentication is disabled on CKAN and is handled by geOrchestra.'
    }


log = logging.getLogger(__name__)


class GeorchestraPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    #TODO add IConfigurable implementation as in https://github.com/NaturalHistoryMuseum/ckanext-ldap/blob/master/ckanext/ldap/plugin.py

    prefix = config['ckanext.georchestra.role.prefix']
    ldap_roles_dict = {
        prefix + config['ckanext.georchestra.role.sysadmin']: 'sysadmin',
        prefix + config['ckanext.georchestra.role.orgadmin']: 'admin',
        prefix + config['ckanext.georchestra.role.editor']: 'editor'
    }

    # ignore basic auth actions
    def login(self):
        """Implementation of IAuthenticator.login"""
        pass

    def logout(self):
        """Implementation of IAuthenticator.logout"""
        #TODO: check if we don't need to somewhat clear the session
        pass

    def abort(self, status_code, detail, headers, comment):
        """Implementation of IAuthenticator.abort"""
        return status_code, detail, headers, comment

    def identify(self):
        """Implementation of IAuthenticator.identify
        Used to determine the currently logged in user
        Will first check if a username is available and act accordingly (get existing user, create new one)
        """
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        self.site_user_name = user['name']
        self.context = {'user': user['name']}

        headers = toolkit.request.headers
        username = headers.get(HEADER_USERNAME)
        if username:
            email = headers.get(HEADER_EMAIL) or 'empty@empty.org'
            emailhash = md5(email.strip().lower().encode('utf8')).hexdigest()
            firstname = headers.get(HEADER_FIRSTNAME) or 'john'
            lastname = headers.get(HEADER_LASTNAME) or 'doe'
            roles = headers.get(HEADER_ROLES)
            role = 'member' # default
            if roles:
                for r in roles.split(";"):
                    # roles in headers are comma-separated but somehow end up being semicolon-separated here...
                    if r in self.ldap_roles_dict:
                        role = self.ldap_roles_dict[r]
                        break
            log.debug('identified user {0} with role {1}'.format(username, role))
            userdict = {
                'id': username,
                'email': email,
                'name': username,
                'fullname': firstname + ' ' + lastname,
                'password': '12345678',
                'role': role,
                'sysadmin': (role=='sysadmin'),
                'state': 'active'
            }
            try:
                ckan_user = toolkit.get_action('user_show')(self.context, {'id': userdict['name']})

                # Check if the user needs to be updated
                check_fields = ['name', 'email', 'fullname', 'sysadmin', 'state']
                checks = [(ckan_user[f] != userdict[f]) for f in check_fields]
                needs_update = reduce(lambda x, y: x or y, checks)
                if needs_update:
                    ckan_user = toolkit.get_action('user_update')(self.context, userdict)
                    log.debug("updated user {0}".format(userdict['name']))
                else:
                    log.debug("user {0} is up-to-date".format(userdict['name']))

                toolkit.c.user = ckan_user['name']
                toolkit.c.user_obj = ckan_user

                #TODO check if user membership needs updating and if needs organization to be created
            except toolkit.ObjectNotFound:
                # Means it doesn't exist yet => we create it
                self.create_userdict(userdict)

            toolkit.c.user = username
            toolkit.c.user_obj = ckan_user
        else:
            toolkit.c.user = None

    def create_user(self, userdict):
        try:
            ckan_user = toolkit.get_action('user_create')(context.copy(), user)
            log.debug("created user {0}".format(user['id']))
            # TODO check organization existence
            # TODO add membership to org
        except ValidationError, e:
            log.error("User parameters are invalid. Could create the user. {0}".format(e))