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


class GeorchestraPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator)
    #TODO add IConfigurable implementation as in https://github.com/NaturalHistoryMuseum/ckanext-ldap/blob/master/ckanext/ldap/plugin.py

    prefix = config['ckanext.georchestra.role.prefix']
    ldap_roles_dict = {
        prefix + config['ckanext.georchestra.role.sysadmin']: 'sysadmin',
        prefix + config['ckanext.georchestra.role.orgadmin']: 'admin',
        prefix + config['ckanext.georchestra.role.editor']: 'editor'
    }

    sync_done = False

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

                # TODO don't check at evry call find a way to store the info it was already synced
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
                if role != 'sysadmin':
                    self.organization_sync_for_user(self.context, ckan_user['id'], headers.get(HEADER_ORG), role)
            except toolkit.ObjectNotFound:
                # Means it doesn't exist yet => we create it
                self.create_user(userdict)

            toolkit.c.user = username
            toolkit.c.user_obj = ckan_user
        else:
            toolkit.c.user = None

    def create_user(self, userdict):
        try:
            ckan_user = toolkit.get_action('user_create')(self.context.copy(), userdict)
            log.debug("created user {0}".format(userdict['id']))
            # TODO check organization existence
            # TODO add membership to org
        except toolkit.ValidationError as e:
            log.error("User parameters are invalid. Could not create the user. {0}".format(e))


    def organization_sync_for_user(self, context, user_id, org_id, role):
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
        model = context['model']
        q = model.Session.query(model.Member, model.Group) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.state == 'active') \
            .join(model.Group)
        his_org=None
        for member, group in q.all():
            log.debug('user {0} is member of {1} with role {2}'.format(user_id, group.id, member.capacity))
            if group.id == org_id:
                his_org = model_dictize.group_dictize(group, context)
                if member.capacity != role:
                    log.debug("found {0}. Update membership".format(org_id))
                    toolkit.get_action('organization_member_create')(context.copy(),
                                                                     {'id': org_id, 'username': user_id,
                                                                      'role': role})
                else:
                    log.debug("found {0}. Membership OK".format(org_id))
            else:
                log.debug("TODO : remove user from {0}".format(group.id))
                toolkit.get_action('organization_member_delete')(context.copy(), {'id': group.id,
                                                                                  'username': user_id})

        if his_org is None:
            try:
                toolkit.get_action('organization_member_create')(context.copy(), {'id':org_id, 'username':user_id, 'role':role})
                log.debug("TODO : add user to {0}".format(org_id))

            except toolkit.ValidationError:
                # Means it doesn't exist yet => we create it
                log.debug("Creating organization {0}".format(org_id))
                #TODO
                his_org = toolkit.get_action('organization_create')(context.copy(), {'name':org_id})
                toolkit.get_action('organization_member_create')(context.copy(), {'id':org_id, 'username':user_id, 'role':role})
