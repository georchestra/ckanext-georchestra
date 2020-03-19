# encoding: utf-8

import logging

from ckan.lib.cli import CkanCommand
from ckan.plugins import toolkit
from ckan.plugins.toolkit import config

from ckanext.georchestra.utils import ldap_utils
from ckanext.georchestra.utils import organizations as org_utils
from ckanext.georchestra.utils import users as user_utils


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
    georchestra_ldap = None

    def command(self):

        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print self.__doc__
            return

        self._load_config()

        # Set up context
        user = toolkit.get_action('get_site_user')({'ignore_auth': True}, {})
        self.site_user_name=user['name']
        self.context = {'user': user['name']}

        cmd = self.args[0]

        if cmd == 'ldap_sync_all':
            if 'force_update' in self.args:
                # Override configuration param
                config['ckanext.georchestra.sync.force_update'] = True
            self.ldap_sync_all()
        elif cmd == 'purge_org': # needs you to provide the org id
            org_utils.delete(self.context, self.args[1])
        elif cmd == 'purge_all_orgs':
            purge_all = (len(self.args) > 1) and (self.args[1]=='delete_active')
            org_utils.delete_all_orgs(self.context, purge_all)
        else:
            print 'Command %s not recognized' % cmd

    def ldap_sync_all(self):
        # TODO: define the log level in config parameter
        log.setLevel(logging.DEBUG)

        self.georchestra_ldap = ldap_utils.GeorchestraLdap()
        self.sync_organizations()
        self.sync_users()


    def sync_organizations(self):
        processed_orgs = self.georchestra_ldap.orgs_scan_and_process(org_utils.update_or_create, self.clean_context())
        ckan_orgs_names_list = self.get_ckan_orgs()

        orgs_to_delete = set(ckan_orgs_names_list) - set (processed_orgs)
        org_utils.remove(self.clean_context(), orgs_to_delete)
        log.info("Synchronized {0} orgs".format(len(processed_orgs)))

    def sync_users(self, ):
        processed_users = self.georchestra_ldap.users_scan_and_process(user_utils.update_or_create, self.clean_context())
        ckan_users_list = self.get_ckan_users()

        # keep root sysadmin users (like the one running this current command) out of the sync process (we don't want
        # them removed...)
        notouch_userids = config['ckanext.georchestra.external_users'].split(",")
        users_to_delete = set(ckan_users_list) - set(processed_users + notouch_userids)
        for orphan in users_to_delete:
            user_utils.delete(self.clean_context(), orphan, config['ckanext.georchestra.orphans.users.purge'], config['ckanext.georchestra.orphans.users.orgname'])
        log.info("Synchronized {0} users".format(len(processed_users)))

    def get_ckan_orgs(self):
        # TODO: add a config parameter ckan.group_and_organization_list_max (defaults to 1000, might need to be higher for big instances). and document this
        orgs = toolkit.get_action('organization_list')(self.clean_context(), {'all_fields':False})
        return orgs

    def get_ckan_users(self):
        users = toolkit.get_action('user_list')(self.clean_context(), {'all_fields': False})
        return users

    def clean_context(self):
        return {'user': self.site_user_name}
