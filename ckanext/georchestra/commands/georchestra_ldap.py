import logging
import dateutil

from ckan.lib.cli import CkanCommand
from ckan.plugins import toolkit
from ckan.plugins.toolkit import config

from ckanext.georchestra.commands.utils import ldap_utils
from ckanext.georchestra.commands.utils import organizations


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
        self.sync_organizations(ldap_cnx)


    def sync_organizations(self, ldap_cnx):
        organizations.preseed(self.context)
        ldap_orgs_list = ldap_utils.get_ldap_orgs(ldap_cnx)
        ckan_orgs_names_list = self.get_ckan_orgs()

        ckan_orgs_set=set(ckan_orgs_names_list)

        orgs_exist = [ el for el in ldap_orgs_list if el['id'] in ckan_orgs_set ]
        orgs_missing = [ el for el in ldap_orgs_list if el['id'] not in ckan_orgs_set ]
        orgs_deprecated = list( ckan_orgs_set - set([el['id'] for el in ldap_orgs_list]))

        organizations.update(self.context,orgs_exist)
        organizations.add(self.context,orgs_missing)
        organizations.remove(self.context,orgs_deprecated)

        log.debug("orgs sync ok !")

    def get_ckan_orgs(self):
        orgs = toolkit.get_action('organization_list')(self.context, {'limit': 1000, 'all_fields':False})
        return orgs