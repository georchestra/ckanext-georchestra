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
}

log = logging.getLogger(__name__)

def organization_edit(context, data_dict=None):
    return {'success': False,
            'msg': 'Managed by geOrchestra LDAP console'}

def user_edit(context, data_dict=None):
    return {'success': False,
            'msg': 'Managed by geOrchestra LDAP console'}



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
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IRoutes, inherit=True)
    #TODO improve IConfigurer implementation ?


    def get_auth_functions(self):
        """Implementation of IAuthFunctions.get_auth_functions"""
        return {
            #'organization_update': organization_edit,
            #'user_update':user_edit
        }

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

    def identify(self):
        """Implementation of IAuthenticator.identify
        Used to determine the currently logged in user
        Will first check if a username is available and act accordingly (get existing user, create new one)
        """
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        self.site_user_name = user['name']
        self.context = {'user': user['name']}

        headers = toolkit.request.headers
        # Headers are not case-sensitive, meaning we can get uppercased of camel-cased headers => we lower-case them
        sec_headers = {k.lower():v for k,v in headers.items() if k.lower() in go_headers.values()}
        username = sec_headers.get(go_headers['HEADER_USERNAME'])
        if not username:
            toolkit.c.user = None
            return

        username = ldap_utils.sanitize(username)
        email = sec_headers.get(go_headers['HEADER_EMAIL']) or u'empty@empty.org'
        firstname = sec_headers.get(go_headers['HEADER_FIRSTNAME']) or u'john'
        lastname = sec_headers.get(go_headers['HEADER_LASTNAME']) or u'doe'
        roles = sec_headers.get(go_headers['HEADER_ROLES'])
        org = ldap_utils.sanitize(sec_headers.get(go_headers['HEADER_ORG']))

        # define role for user (default is unprivileged 'member'
        role = u'member' # default
        prefix = config['ckanext.georchestra.role.prefix']
        ldap_roles_dict = ldap_utils.get_ldap_roles_as_ordereddict(prefix)
        if roles:
            for k, v in ldap_roles_dict.iteritems():
                if k in roles.split(";"):
                    role = v
                    break
        log.debug('identified user {0} with role {1}'.format(username, role))

        userdict = {
            'id': username,
            'email': email,
            'name': username,
            'fullname': firstname + ' ' + lastname,
            'password': u'12345678',
            'org_id': org,
            'role': role,
            'sysadmin': (role==u'sysadmin'),
            'state': u'active'
        }
        try:
            # get the user info. If it does not exist, it will throw an exception. We then create the user in when
            # dealing with that exception (see below)
            ckan_user = toolkit.get_action('user_show')(self.context, {'id': userdict['name']})

            # TODO don't check at every call find a way to store the info it was already synced
            # Check if the user needs to be updated
            check_fields = ['name', 'email', 'sysadmin', 'state']
            if user_utils.needs_updating(check_fields, ckan_user, userdict):
                ckan_user = toolkit.get_action('user_update')(self.context, userdict)
                log.debug("updated user {0}".format(userdict['name']))
            else:
                log.debug("user {0} is up-to-date".format(userdict['name']))
            if userdict['org_id']:
                if role == 'sysadmin':
                    # if sysadmin, we only need to check if the org needs to be created
                    try:
                        toolkit.get_action('organization_create')(self.context.copy(), {'name': userdict['org_id']})
                    except Exception, e:
                        # organization most likely exists, which will fail the create action. We ignore this.
                        pass
                else:
                    # check if user membership needs updating and if needs organization to be created
                    self.organization_sync_for_user(userdict['id'], userdict['org_id'], userdict['role'])
        except toolkit.ObjectNotFound:
            # Means the user doesn't exist yet => we create it
            user_utils.create(self.context, userdict)

        toolkit.c.user = username
        #toolkit.c.user_obj = ckan_user # seems not necessary. Raises an error when the user is new


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

    def organization_sync_for_user(self, user_id, org_id, role):
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
