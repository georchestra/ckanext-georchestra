import logging
import dateutil

from ckan.lib.cli import CkanCommand
from ckan.plugins import toolkit
from ckan.plugins.toolkit import config

from ckanext.georchestra.commands.utils import ldap_utils
from ckanext.georchestra.commands.utils import organizations as org_utils
from ckanext.georchestra.commands.utils import users as user_utils


log = logging.getLogger()


class GeorchestraLDAPCommand(CkanCommand):
    """
    Paster function to synchronize the users/organizations with the LDAP directory
    Commands:
        paster georchestra ldap-sync-all -c /etc/ckan/default/development.ini
    """
    summary = __doc__.split('\n')[0]
    usage = __doc__

    cnx = None
    ldap_orgs_list = None

    #TODO: change those values to False for prod
    is_dev_mode=True
    is_debug_mode=True

    def command(self):

        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print self.__doc__
            return

        self._load_config()

        # Set up context
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        self.context = {'user': user['name']}

        cmd = self.args[0]

        if cmd == 'ldap_sync_all':
            self.ldap_sync_all()
        else:
            print 'Command %s not recognized' % cmd

    def ldap_sync_all(self):
        log.setLevel(logging.DEBUG)

        ldap_cnx= ldap_utils.get_ldap_connection()
        ldap_orgs_list = self.sync_organizations(ldap_cnx)
        self.sync_users(ldap_cnx, ldap_orgs_list)
        #self.sync_membership(ldap_cnx)


    def sync_organizations(self, ldap_cnx):
        org_utils.preseed(self.context)
        ldap_orgs_list = ldap_utils.get_ldap_orgs(ldap_cnx)
        ckan_orgs_names_list = self.get_ckan_orgs()

        ckan_orgs_set=set(ckan_orgs_names_list)

        orgs_exist = [ el for el in ldap_orgs_list if el['id'] in ckan_orgs_set ]
        orgs_missing = [ el for el in ldap_orgs_list if el['id'] not in ckan_orgs_set ]
        orgs_deprecated = list( ckan_orgs_set - set([el['id'] for el in ldap_orgs_list]))

        org_utils.update(self.context,orgs_exist, force_update=self.is_dev_mode)
        org_utils.add(self.context,orgs_missing)
        org_utils.remove(self.context,orgs_deprecated)

        log.debug("orgs sync ok !")
        return ldap_orgs_list

    def sync_users(self, ldap_cnx, ldap_orgs_list ):
        #TODO : there is certainly much room here for optimization...

        roles = ldap_utils.get_roles_memberships(ldap_cnx)

        # TODO: find a way to put apart sysadmin user used to run the command, at least
        processed_userids = ['ckandev', 'ckan']
        for org in ldap_orgs_list:
            ldap_users_list = ldap_utils.get_ldap_org_members(ldap_cnx, org, roles)
            for user in  ldap_users_list:
                try:
                    toolkit.get_action('user_show')(self.context, {'id':user['id']})
                    # no exception means the user already exists in the DB
                    user_utils.update(self.context, user, org)
                except toolkit.ObjectNotFound:
                    user_utils.create(self.context, user, org)
                processed_userids.append(user['id'])
        ckan_all_users = toolkit.get_action('user_list')(self.context, {'all_fields':False})
        orphan_users = set(ckan_all_users)-set(processed_userids)
        # TODO: remove orphan users but be careful not to remove, for instance, ckandev sysadmin user used to run this command
        log.debug("there are {0} orphan users to remove".format(len(orphan_users)))

    def get_ckan_orgs(self):
        orgs = toolkit.get_action('organization_list')(self.context, {'limit': 1000, 'all_fields':False})
        return orgs

    def get_ckan_members_of_org(self, org):
        users = toolkit.get_action('member_list')(self.context, {'id':org['id'], 'object_type': 'user'})
        return users

