# encoding: utf-8

import logging
import six
import traceback
from routes.mapper import SubMapper
from os import environ

import ckan.plugins as plugins
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.plugins.toolkit import config
import ckan.lib.dictization.model_dictize as model_dictize
import ckanext.georchestra.utils.organizations as organizations_utils
import ckanext.georchestra.utils.users as user_utils
import ckanext.georchestra.utils.ldap_utils as ldap_utils

go_headers = {
    'HEADER_USERNAME': u'sec-username',
    'HEADER_ROLES': u'sec-roles',
    'HEADER_ORG': u'sec-org',
    'HEADER_EMAIL': u'sec-email',
    'HEADER_FIRSTNAME': u'sec-firstname',
    'HEADER_LASTNAME': u'sec-lastname',
    'HEADER_TEL': u'sec-tel',
}

CONFIG_FROM_ENV_VARS = {
    'ckanext.georchestra.ldap.uri': 'CKAN_LDAP_URL',
    'ckanext.georchestra.sync.force_update': 'CKAN_LDAP_SYNC_FORCE',
    'ckanext.georchestra.orphans.users.purge': 'CKAN_LDAP_SYNC_ORPHANS_PURGE',
}

log = logging.getLogger(__name__)


class GeorchestraPlugin(plugins.SingletonPlugin):
    """
    geOrchestra plugin

    This plugin plugin synchronizes the users, organizations and user membership with a georchestra LDAP instance.
    On user access, it performs a quick check and sync on this user only.
    For full sync, use the paster command (should be set as cron task)
    """
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)

    def update_config(self, config):

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        # 'templates' is the path to the templates dir, relative to this
        # plugin.py file.
        toolkit.add_template_directory(config, 'templates')


    # IRoutes
    def before_map(self, routes):
        controller = 'ckanext.georchestra.controller:GeorchestraController'
        routes.connect('/user/login',
                    controller='ckanext.georchestra.controller:GeorchestraController',
                    action='georchestra_login')
        routes.connect('/user/_logout',
                    controller='ckanext.georchestra.controller:GeorchestraController',
                    action='georchestra_logout')
        return routes

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

    def get_superuser_context(self):
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        context = {'user': user['name']}
        return context

    def identify(self):
        """Implementation of IAuthenticator.identify
        Used to determine the currently logged in user
        Will first check if a username is available and act accordingly (get existing user, create new one)
        """
        # Retrieve security-proxy headers, and specifically sec-username. Security-proxy headers are not case-sensitive,
        # meaning we can get uppercased of camel-cased headers => we lower-case them
        sec_headers = _get_lowercased_sec_headers(toolkit.request.headers)
        userdict = _user_dict_from_sec_headers(sec_headers)
        username = userdict['name']
        if not username:
            # be anonymous
            toolkit.c.user = None
            return

        # make sure username will be compatible with CKAN syntax
        username = ldap_utils.sanitize(username)

        # Check if username exists in the db
        userobj = model.User.by_name(username)
        if userobj:
            # User exists
            # check if it needs an update
            if _user_profile_needs_updating(userobj, userdict):
                user = toolkit.get_action('user_update')(self.get_superuser_context().copy(), userdict)
                userobj = model.User.by_name(username)

            # User identified
            toolkit.c.user = userobj.name
            toolkit.c.user_obj = userobj
            if (userobj.sysadmin):
                # User identified, we're done here
                return

            log.debug('Checking user {}, role {}, org {}'.format(userobj.id, userdict['role'], userdict['org_id']))
            # For non-sysadmins, we also want to check he is still member of the org declared in the headers
            if self.organization_check_for_user(userobj.id, userdict['org_id'], userdict['role']):
                # no change with org, we're done here
                return
            else:
                log.debug('Needs to update user {}: set as {} role on org {}'.format(userobj.id, userdict['role'], userdict['org_id']))
                organizations_utils.organization_set_member_or_create(self.get_superuser_context().copy(),
                                                                     userobj.id, userdict['org_id'], userdict['role'])

        # (else:)
        log.debug('User {0} does not have an account yet in ckan. Creating the user'.format(username))
        # userobj = None means:
        # User exists in LDAP, but not (yet) on CKAN. We need to create the user in the DB. It will be a temporary,
        # light user instance, that will be completed on next sync
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        context = {'user': user['name']}
        ckan_user = user_utils.create(context, userdict)
        if not ckan_user:
            # There was an error. Log the info, and be anonymous
            log.warning('There was an error creating the user. Logging you as anonymous.')
            toolkit.c.user = None
            return

        toolkit.c.user = ckan_user['id']
        return


    def configure(self, main_config):
        """Implementation of IConfigurable.configure"""
        # Our own config schema, defines required items, default values and transform functions
        # strongly inspired from from https://github.com/NaturalHistoryMuseum/ckanext-ldap/blob/master/ckanext/ldap/plugin.py
        schema = {
            'ckanext.georchestra.ldap.uri': {'required': True},
            'ckanext.georchestra.ldap.base_dn': {'required': True},
            'ckanext.georchestra.ldap.orgs.rdn': {'required': True},
            'ckanext.georchestra.ldap.roles.rdn': {'required': True},
            'ckanext.georchestra.ldap.users.rdn': {'required': True},
            'ckanext.georchestra.ldap.admin.dn': {'required': True},
            'ckanext.georchestra.ldap.users.nosync': {'default': 'geoserver_privileged_user'},
            'ckanext.georchestra.ldap.admin.password': {'required': True},
            'ckanext.georchestra.ldap.auth.method': {'default': 'SIMPLE', 'validate': _allowed_auth_methods},
            'ckanext.georchestra.ldap.auth.mechanism': {'default': 'DIGEST-MD5', 'validate': _allowed_auth_mechanisms},
            'ckanext.georchestra.ldap.trace_level': {'default': 0, 'parse': toolkit.asint},
            'ckanext.georchestra.role.prefix': {'default': 'ROLE_'},
            'ckanext.georchestra.role.sysadmin': {'default': 'CKAN_SYSADMIN'},
            'ckanext.georchestra.role.orgadmin': {'default': 'CKAN_ADMIN'},
            'ckanext.georchestra.role.editor': {'default': 'CKAN_EDITOR'},
            'ckanext.georchestra.external_users': {'default': 'ckan'},
            'ckanext.georchestra.orphans.users.purge': {'default': False, 'parse': toolkit.asbool},
            'ckanext.georchestra.orphans.users.orgname': {'default': 'orphan_users'},
            'ckanext.georchestra.organization.ghosts.prefix': {'default': '[GHOST] '},
            'ckanext.georchestra.sync.force_update': {'default': False, 'parse': toolkit.asbool},
        }
        errors = []
        for i in schema:
            v = _get_from_environment(i)
            # Environment variables take precedence over config file
            if v:
                log.debug("reading variable {} from environment".format(i))
            else:
                if i in main_config:
                    v = main_config[i]
                elif i.replace('ckanext.', '') in main_config:
                    log.warning('geOrchestra configuration options should be prefixed with \'ckanext.\'. ' +
                                'Please update {0} to {1}'.format(i.replace('ckanext.', ''), i))

            if v:
                if 'parse' in schema[i]:
                    v = (schema[i]['parse'])(v)
                try:
                    if 'validate' in schema[i]:
                        (schema[i]['validate'])(v)
                    if isinstance(v, str):
                        main_config[i] = six.text_type(v, encoding='utf-8')
                    else:
                        main_config[i] = v
                except ConfigError as e:
                    errors.append(str(e))
            elif schema[i].get('required', False):
                errors.append('Configuration parameter {} is required'.format(i))
            elif schema[i].get('required_if', False) and schema[i]['required_if'] in main_config:
                errors.append('Configuration parameter {} is required when {} is present'.format(i,
                                                                                            schema[i]['required_if']))
            elif 'default' in schema[i]:
                main_config[i] = schema[i]['default']
        if len(errors):
            raise ConfigError("\n".join(errors))


    def organization_check_for_user(self, user_id, org_name, user_role):
        """
            Check if the user belongs to that group in CKAN, with corresponding role
            :param user_id
            :param org_name  the name of the org, provided by sec-headers
            :param user_role
            :return: boolean
        """
        memberships = model.Session.query(model.Member, model.Group) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.state == 'active') \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.capacity == user_role) \
            .join(model.Group)
        for member, group in memberships.all():
            if group.type == 'organization' and group.name == org_name:
                return True
        return False

    def organization_sync_for_user(self, user_dict):
        """
        Synchronize on-the-fly organization membership. If organization does not exist, it creates an org with only
        the name (id). The empty title field will serve to know, at next full sync, that this org needs to be updated
        (otherwise, the update date being more recent, it wouldn't trigger an update)
        This function needs to go low-level using model, because it is called from identify function, and while in
        identify, the user is not properly identified and the organization_list_for_user action, for instance, fails.
        :param context:
        :param user_id:
        :param org_id:
        :param role:
        :return:
        """
        try:
            model = self.context['model']
            # Get all groups where user is a member
            q = model.Session.query(model.Member, model.Group) \
                .filter(model.Member.table_name == 'user') \
                .filter(model.Member.table_id == user_id) \
                .filter(model.Member.state == 'active') \
                .join(model.Group)
            his_org=None
            for member, group in q.all():
                log.debug('user {0} is member of {1} with role {2}'.format(user_id, group.id, member.capacity))
                if (group.id == org_id) or (group.name == org_id):
                    his_org = model_dictize.group_dictize(group, self.context)
                    if member.capacity != role:
                        log.debug("found {0}. Update membership".format(org_id))
                        organizations_utils.organization_set_member_or_create(self.context.copy(), user_id, org_id, role)
                    else:
                        log.debug("found {0}. Membership OK".format(org_id))
                else:
                    log.debug("remove user from {0}".format(group.id))
                    toolkit.get_action('organization_member_delete')(self.context.copy(), {'id': group.id,
                                                                                      'username': user_id})

            if his_org is None:
                organizations_utils.organization_set_member_or_create(self.context, user_id, org_id, role)
        except Exception as e:
            log.debug("Exception {}".format(e))
            log.debug(traceback.format_exc())

class ConfigError(Exception):
    pass


def _get_lowercased_sec_headers(headers):
    sec_headers = {k.lower(): v for k, v in headers.items() if k.lower() in go_headers.values()}
    return sec_headers


def _user_dict_from_sec_headers(sec_headers):
    # It seems we might sometimes get headers encoded in ISO. This should get them back to unicode
    for k,v in sec_headers.items():
        if isinstance(v, str):
            sec_headers[k] = six.text_type(v, encoding='latin1')

    username = ldap_utils.sanitize(sec_headers.get(go_headers['HEADER_USERNAME']))
    email = sec_headers.get(go_headers['HEADER_EMAIL']) or u'empty@empty.org'
    firstname = sec_headers.get(go_headers['HEADER_FIRSTNAME']) or u'john'
    lastname = sec_headers.get(go_headers['HEADER_LASTNAME']) or u'doe'
    roles = sec_headers.get(go_headers['HEADER_ROLES'])
    org = ldap_utils.sanitize(sec_headers.get(go_headers['HEADER_ORG']))

    # define role for user (default is unprivileged 'member'
    role = ldap_utils.get_ckan_role_from_security_proxy_roles(roles)
    log.debug('Giving user {0} role {1}'.format(username, role))

    userdict = {
        u'id': username,
        u'email': email,
        u'name': username,
        u'fullname': firstname + ' ' + lastname,
        u'password': u'12345678',
        u'org_id': org,
        u'role': role,
        u'sysadmin': (role == u'sysadmin'),
        u'state': u'active'
    }
    return userdict


def _allowed_auth_methods(v):
    """Raise an exception if the value is not an allowed authentication method"""
    if v.upper() not in ['SIMPLE', 'SASL']:
        raise ConfigError('Only SIMPLE and SASL authentication methods are supported')


def _allowed_auth_mechanisms(v):
    """Raise an exception if the value is not an allowed authentication mechanism"""
    if v.upper() not in ['DIGEST-MD5',]:  # Only DIGEST-MD5 is supported when the auth method is SASL
        raise ConfigError('Only DIGEST-MD5 is supported as an authentication mechanism')


def _get_from_environment(key):
    env_var_name = CONFIG_FROM_ENV_VARS.get(key, '')
    return environ.get(env_var_name, None)


def _user_profile_needs_updating(userobj, userdict):
    """
    Check if significant parts of the user object have changed, between the userobject stored in DB and the user profile
    retrieved from the headers
    :param userobj: user definition stored in DB
    :param userdict: user profile retrieved from the headers
    :return: (boolean) True if the user profile need to be updated (there *is* some change)
    """
    attributes = [ u'sysadmin', u'state', u'id', u'name']
    obj_dict = vars(userobj)
    for att in attributes:
        if obj_dict[att] != userdict[att]:
            return True

    # There is no significant change
    return False