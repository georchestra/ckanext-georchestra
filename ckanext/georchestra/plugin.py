import logging

from hashlib import md5

import ckan.plugins as plugins
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.plugins.toolkit import config
import ckan.lib.dictization.model_dictize as model_dictize

HEADER_USERNAME = "sec-username"
HEADER_ROLES = "sec-roles"
HEADER_ORG = "sec-org"
HEADER_EMAIL = "sec-email"
HEADER_FIRSTNAME = "sec-firstname"
HEADER_LASTNAME = "sec-lastname"
HEADER_TEL = "sec-tel"

log = logging.getLogger(__name__)

def organization_edit(context, data_dict=None):
    return {'success': False,
            'msg': 'Managed by Georchestra LDAP console'}

def user_edit(context, data_dict=None):
    return {'success': False,
            'msg': 'Managed by Georchestra LDAP console'}



class GeorchestraPlugin(plugins.SingletonPlugin):
    """
    Georchestra plugin

    This plugin plugin synchronizes the users, organizations and user membership with a georchestra LDAP instance.
    On user access, it performs a quick check and sync on this user only.
    For full sync, use the paster command (should be set as cron task)
    """
    plugins.implements(plugins.IAuthenticator)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthFunctions)
    #TODO improve IConfigurer implementation ?

    prefix = config['ckanext.georchestra.role.prefix']
    ldap_roles_dict = {
        prefix + config['ckanext.georchestra.role.sysadmin']: 'sysadmin',
        prefix + config['ckanext.georchestra.role.orgadmin']: 'admin',
        prefix + config['ckanext.georchestra.role.editor']: 'editor'
    }
    sync_done = False

    def get_auth_functions(self):
        """Implementation of IAuthFunctions.get_auth_functions"""
        return {
            'organization_update': organization_edit,
            'user_update':user_edit
        }

    def update_config(self, config):

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        # 'templates' is the path to the templates dir, relative to this
        # plugin.py file.
        toolkit.add_template_directory(config, 'templates')

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
            org = headers.get(HEADER_ORG)
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
                'org': org,
                'role': role,
                'sysadmin': (role=='sysadmin'),
                'state': 'active'
            }
            try:
                ckan_user = toolkit.get_action('user_show')(self.context, {'id': userdict['name']})

                # TODO don't check at every call find a way to store the info it was already synced
                # Check if the user needs to be updated
                check_fields = ['name', 'email', 'fullname', 'sysadmin', 'state']
                checks = [(ckan_user[f] != userdict[f]) for f in check_fields]
                needs_update = reduce(lambda x, y: x or y, checks)
                if needs_update:
                    ckan_user = toolkit.get_action('user_update')(self.context, userdict)
                    log.debug("updated user {0}".format(userdict['name']))
                else:
                    log.debug("user {0} is up-to-date".format(userdict['name']))

                # check if user membership needs updating and if needs organization to be created
                # TODO: if sysadmin, we still need to check if the org needs to be created
                if role != 'sysadmin':
                    self.organization_sync_for_user(userdict['id'], userdict['org'], userdict['role'])
            except toolkit.ObjectNotFound:
                # Means it doesn't exist yet => we create it
                self.create_user(userdict)

            toolkit.c.user = username
            toolkit.c.user_obj = ckan_user
        else:
            toolkit.c.user = None

    def configure(self, main_config):
        """Implementation of IConfigurable.configure"""
        # Our own config schema, defines required items, default values and transform functions
        # strongly inspired from from https://github.com/NaturalHistoryMuseum/ckanext-ldap/blob/master/ckanext/ldap/plugin.py
        schema = {
            'ckanext.georchestra.ldap.uri': {'required': True},
            'ckanext.georchestra.ldap.base_dn': {'required': True},
            'ckanext.georchestra.ldap.base_dn.orgs': {'required': True},
            'ckanext.georchestra.ldap.base_dn.roles': {'required': True},
            'ckanext.georchestra.ldap.base_dn.users': {'required': True},
            'ckanext.georchestra.ldap.auth.dn': {'required': True},
            'ckanext.georchestra.ldap.users.nosync': {'default': 'geoserver_privileged_user'},
            'ckanext.georchestra.ldap.auth.password': {'required': True},
            'ckanext.georchestra.ldap.auth.method': {'default': 'SIMPLE', 'validate': _allowed_auth_methods},
            'ckanext.georchestra.ldap.auth.mechanism': {'default': 'DIGEST-MD5', 'validate': _allowed_auth_mechanisms},
            'ckanext.georchestra.ldap.trace_level': {'default': 0, 'parse': toolkit.asint},
            'ckanext.georchestra.role.prefix': {'default': 'ROLE_'},
            'ckanext.georchestra.role.sysadmin': {'default': 'CKAN_SYSADMIN'},
            'ckanext.georchestra.role.orgadmin': {'default': 'CKAN_ADMIN'},
            'ckanext.georchestra.role.editor': {'default': 'CKAN_EDITOR'},
            'ckanext.georchestra.external_users': {'default': 'ckan'},
            'ckanext.georchestra.orphans.users.purge': {'default': True, 'parse': toolkit.asbool},
            'ckanext.georchestra.orphans.users.orgname': {'default': 'orphan_users'},
        }
        errors = []
        for i in schema:
            v = None
            if i in main_config:
                v = main_config[i]
            elif i.replace('ckanext.', '') in main_config:
                log.warning('Georchestra configuration options should be prefixed with \'ckanext.\'. ' +
                            'Please update {0} to {1}'.format(i.replace('ckanext.', ''), i))

            if v:
                if 'parse' in schema[i]:
                    v = (schema[i]['parse'])(v)
                try:
                    if 'validate' in schema[i]:
                        (schema[i]['validate'])(v)
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
        # make sure all the strings in the config are unicode formatted
        for key, value in main_config.iteritems():
            if isinstance(value, str):
                main_config[key] = unicode(value, encoding='utf-8')

    def create_user(self, userdict):
        try:
            ckan_user = toolkit.get_action('user_create')(self.context.copy(), userdict)
            log.debug("created user {0}".format(userdict['id']))
            self.organization_set_member_or_create(userdict['id'], userdict['org'], userdict['role'])
        except toolkit.ValidationError as e:
            log.error("User parameters are invalid. Could not create the user. {0}".format(e))

    def organization_sync_for_user(self, user_id, org_id, role):
        """
        Synchronize on-the-fly organization membership. If organization does not exist, it creates an org with only
        the name (id). The empty title field will serve to know, as next full sync, that this org needs to be updated
        (otherwise, the update date being more recent, it wouldn't trigger an update)
        This function needs to go low-level using model, because it is called from identify function, and while in
        identify, the user is not properly identified and the organization_list_for_user action, for instance, fails.
        :param context:
        :param user_id:
        :param org_id:
        :param role:
        :return:
        """
        model = self.context['model']
        q = model.Session.query(model.Member, model.Group) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.state == 'active') \
            .join(model.Group)
        his_org=None
        for member, group in q.all():
            log.debug('user {0} is member of {1} with role {2}'.format(user_id, group.id, member.capacity))
            if group.id == org_id:
                his_org = model_dictize.group_dictize(group, self.context)
                if member.capacity != role:
                    log.debug("found {0}. Update membership".format(org_id))
                    toolkit.get_action('organization_member_create')(self.context.copy(),
                                                                     {'id': org_id, 'username': user_id,
                                                                      'role': role})
                else:
                    log.debug("found {0}. Membership OK".format(org_id))
            else:
                log.debug("TODO : remove user from {0}".format(group.id))
                toolkit.get_action('organization_member_delete')(self.context.copy(), {'id': group.id,
                                                                                  'username': user_id})

        if his_org is None:
            self.organization_set_member_or_create(user_id, org_id, role)


    def organization_set_member_or_create(self, user_id, org_id, role):
        """
        Set user as member of the organization, with the given role.
        If the organization doesn't exist, create the organization, setting only it's ID. The remaining information will
        be completed on next full sync (paster command)
        :param self:
        :param user_id:
        :param org_id:
        :param role:
        :return:
        """
        try:
            toolkit.get_action('organization_member_create')(self.context.copy(), {'id': org_id, 'username': user_id,
                                                                                   'role': role})
            log.debug("added user to {0}".format(org_id))

        except toolkit.ValidationError:
            # Means it doesn't exist yet => we create it
            log.debug("Creating organization {0}".format(org_id))
            #his_org = toolkit.get_action('organization_create')(self.context.copy(), {'name': org_id,
            #                                                                          'extras': [{
            #                                                                                'key': 'needs_sync',
            #                                                                                'value':True
            #                                                                            }]
            #                                                                          })
            his_org = toolkit.get_action('organization_create')(self.context.copy(), {'name': org_id})
            log.debug("adding user to {0}".format(org_id))
            toolkit.get_action('organization_member_create')(self.context.copy(), {'id': org_id, 'username': user_id,
                                                                                   'role': role})


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