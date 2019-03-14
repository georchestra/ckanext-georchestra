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

        all_users_by_groups = self.get_ckan_members_by_groups(ldap_orgs_list)
        for org in ldap_orgs_list:
            ldap_users_list = ldap_utils.get_ldap_org_members(ldap_cnx, org)
            ckan_org_members_list = self.get_ckan_members_of_org(org)
            for user in ldap_users_list:
                #list the orgs he belongs in ckan
                user_ckan_orgs = toolkit.get_action(
                    'organization_list_for_user')(self.context, {'id':user['uid'], 'include_dataset_count': True})
                if (len(user_ckan_orgs) > 1):
                    raise Exception("oops")
                elif (len(user_ckan_orgs) == 0):
                    user_utils.create(self.context, user, org)
                elif (user_ckan_orgs[0] == org['id']):
                    user_utils.update(self.context, user, org)
                else:
                    user_utils.change_org(self.context, user, org)

                log.debug("ok")
            #users_exist = [ el for el in ldap_users_list if el['cn'] in ckan_org_members_list]
            log.debug("ok")

    def get_ckan_orgs(self):
        orgs = toolkit.get_action('organization_list')(self.context, {'limit': 1000, 'all_fields':False})
        return orgs

    def get_ckan_members_of_org(self, org):
        users = toolkit.get_action('member_list')(self.context, {'id':org['id'], 'object_type': 'user'})
        return users

    def get_ckan_members_by_groups(self, orgs_list):
        # This toolkit action doesn't seem to work... I get an empty list
        groups_with_members = toolkit.get_action('organization_list')(self.context, {'limit':1000, 'all_fields':True,
                                                                                     'include_users':True})
        return groups_with_members
