import ckan.plugins as plugins
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from hashlib import md5
import logging

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
        'success': False,
        'msg': 'Authentication is disabled on CKAN and is handled by geOrchestra.'
    }


log = logging.getLogger(__name__)


class GeorchestraPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IConfigurer)

    # ignore basic auth actions
    def login(self):
        pass

    def logout(self):
        pass

    def abort(self, status_code, detail, headers, comment):
        pass

    def identify(self):
        """
        Used to determine the currently logged in user
        Will first check if a username is available and act accordingly (get existing user, create new one)
        """
        headers = toolkit.request.headers
        username = headers.get(HEADER_USERNAME)
        if username:
            email = headers.get(HEADER_EMAIL) or 'empty@empty.org'
            emailhash = md5(email.strip().lower().encode('utf8')).hexdigest()
            firstname = headers.get(HEADER_FIRSTNAME) or 'john'
            lastname = headers.get(HEADER_LASTNAME) or 'doe'
            userdict = {'email': email,
                        'name': username,
                        'fullname': firstname + ' ' + lastname,
                        'password': '12345678'}

            # create user if missing
            try:
                toolkit.get_converter('user_name_exists')(
                    username,
                    {'model': model, 'session': model.Session})
            except toolkit.Invalid:
                toolkit.get_action('user_create')(
                    {'model': model, 'session': model.Session, 'user': None, 'ignore_auth': True},
                    userdict)

            userdict['id'] = toolkit.get_converter('convert_user_name_or_id_to_id')(
                username,
                {'model': model, 'session': model.Session})
            user_obj = toolkit.get_action('user_show')(
                {'model': model, 'session': model.Session, 'user': None, 'ignore_auth': True},
                {'id': userdict['id']})

            # update user if necessary
            #if user_obj['email_hash'] != emailhash or user_obj['fullname'] != userdict['fullname']:
            #    toolkit.get_action('user_update')(
            #        {'model': model, 'session': model.Session, 'user': None, 'ignore_auth': True},
            #        userdict)

            toolkit.c.user = username
            psession=model.Session
            #self.update_orgs(userdict)
        else:
            toolkit.c.user = None

    # Update organizations associated to the user
    def update_orgs(self, userdict):
        # TODO
        # 1. get list of orgs for this user using get_action('organization_list_for_user')
        # 2. check if the current user's org is in the list. If not, create it
        # 3. for the list - the current user's org, remove the user from the orgs
        # 4. purge ophan orgs : this will be done by the sync_with_LDAP task

        # update Organization info
        orgs_list = toolkit.get_action('organization_list_for_user')(
            {'model': model, 'session': model.Session, 'user': '', 'ignore_auth': True},
            {'id': userdict['id']})
        log.debug('user {1} belongs to {0} organizations'.format(len(orgs_list), userdict['name']))
        for org in orgs_list:
            log.info('belongs to org {0}'.format(org['display_name']))

        headers = toolkit.request.headers
        user_org_name = headers.get(HEADER_ORG)
        # check if organization exists
        try:
            org_exists = toolkit.get_validator('group_id_or_name_exists')(
                user_org_name,
                {'model': model, 'session': model.Session, 'user': '', 'ignore_auth': True})

            log.debug('organization exists ? {0}'.format(org_exists))
        except toolkit.Invalid:
            log.debug('organization exists ? nope')
            #then create organization
            #self.create_org(user_org_name, userdict)


    #create a new organization
    def create_org(self,user_org_name, userdict):
        new_org = toolkit.get_action('organization_create')(
            {},
            {'name': user_org_name, 'ldap_allow':True })
        return new_org


    # override auth functions
    def get_auth_functions(self):
        return {
            'user_create': auth_function_disabled,
            'organization_create': auth_function_disabled,
            'group_create': auth_function_disabled
        }

    # IConfigurer
    def update_config(self, config_):
        pass
        #toolkit.add_template_directory(config_, 'templates')
        # toolkit.add_public_directory(config_, 'public')
        # toolkit.add_resource('fanstatic', 'georchestra')
