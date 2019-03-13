import logging
import dateutil

import ldap, ldap.filter
from ckan.lib.cli import CkanCommand
from ckan.plugins import toolkit
from ckan.plugins.toolkit import config

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
        # Get the organisation all users will be added to
        #organization_id = pylons.config['ckanext.georchestra.ldap.organization.id']
        #
        #try:
        #    toolkit.get_action('organization_show')(self.context, {'id': organization_id})
        #except logic.NotFound:
        #    toolkit.get_action('organization_create')(self.context, {'id': organization_id, 'name': organization_id})
        self.sync_organizations()
        pass

    def sync_organizations(self):
        organizations.preseed(self.context)
        ldap_orgs_list = self.get_ldap_orgs()
        ckan_orgs_names_list = self.get_ckan_orgs()

        ckan_orgs_set=set(ckan_orgs_names_list)

        orgs_exist = [ el for el in ldap_orgs_list if el['id'] in ckan_orgs_set ]
        orgs_missing = [ el for el in ldap_orgs_list if el['id'] not in ckan_orgs_set ]
        orgs_deprecated = list( ckan_orgs_set - set([el['id'] for el in ldap_orgs_list]))

        organizations.update(self.context,orgs_exist)
        organizations.add(self.context,orgs_missing)
        organizations.remove(self.context,orgs_deprecated)

        log.debug("ok !")

    def get_ldap_connection(self):
        """
        Use this function to get the LDA connection: this way, you ensure it will always be initialized
        :return: LDAP connection object
        """
        # TODO manage bytes_mode=False : see how to properly deal with unicode config. I can unicode(config[...]) every
        #      config file, but this looks dirty
        # TODO trace_level seems not possible to configure from ini files. Strange
        if self.cnx != None:
            return self.cnx

        cnx = ldap.initialize(config['ckanext.georchestra.ldap.uri'], bytes_mode=True, trace_level=2)

        if config.get('ckanext.georchestra.ldap.auth.dn'):
            try:
                if config['ckanext.georchestra.ldap.auth.method'] == 'SIMPLE':
                    cnx.bind_s(config['ckanext.georchestra.ldap.auth.dn'],
                               config['ckanext.georchestra.ldap.auth.password'])
                elif config['ckanext.georchestra.ldap.auth.method'] == 'SASL':
                    if config['ckanext.georchestra.ldap.auth.mechanism'] == 'DIGEST-MD5':
                        auth_tokens = ldap.sasl.digest_md5(config['ckanext.georchestra.ldap.auth.dn'],
                                                           config['ckanext.georchestra.ldap.auth.password'])
                        cnx.sasl_interactive_bind_s("", auth_tokens)
                    else:
                        log.error("SASL mechanism not supported: {0}".format(
                            config['ckanext.georchestra.ldap.auth.mechanism']))
                        return None
                else:
                    log.error(
                        "LDAP authentication method is not supported: {0}".format(
                            config['ckanext.georchestra.ldap.auth.method']))
                    return None
            except ldap.SERVER_DOWN:
                log.error('LDAP server is not reachable')
                return None
            except ldap.INVALID_CREDENTIALS:
                log.error(
                    'LDAP server credentials (ckanext.georchestra.ldap.auth.dn and ckanext.georchestra.ldap.auth.password) invalid')
                return None
            except ldap.LDAPError, e:
                log.error("Fatal LDAP Error: {0}".format(e))
                return None
        self.cnx=cnx
        return cnx

    def get_ldap_orgs(self):
        """
        Get LDAP organization list
        :return:
        """
        if self.ldap_orgs_list != None:
            return self.ldap_orgs_list

        cnx= self.get_ldap_connection()
        ldap_search_result = cnx.search_s(config['ckanext.georchestra.ldap.base_dn.orgs'], ldap.SCOPE_ONELEVEL,
                                          filterstr='(objectClass=groupOfMembers)',
                                          attrlist=['cn', 'o', 'seeAlso', 'modifytimestamp'])
        ldap_orgs_list = []
        for elt in ldap_search_result:
            ts=elt[1]['modifyTimestamp'][0]
            log.debug("timestamp {0}".format(ts.decode('utf8')))
            org = { 'name' : elt[1]['cn'][0].decode('utf_8'),
                    'id' : elt[1]['cn'][0].decode('utf_8'),
                    'title' : elt[1]['o'][0].decode('utf_8'),
                    'update_ts' : dateutil.parser.parse(elt[1]['modifyTimestamp'][0].decode('utf_8'))
                    }
            see_also_links = elt[1]['seeAlso']
            for link in see_also_links:
                res = cnx.search_s(link, ldap.SCOPE_BASE,
                                                  filterstr='(objectClass=*)', attrlist=None)
                if res[0][0].startswith('o='):
                    org['description'] = res[0][1]['description'][0]
                else:
                    #org['image_url'] =  res[0][1]['jpegPhoto'][0]
                    pass
            ldap_orgs_list.append(org)

        self.ldap_orgs_list = ldap_orgs_list
        return ldap_orgs_list

    def get_ldap_orgs_list(self):
        ldap_orgs = self.get_ldap_orgs()
        ldap_orgs_list = []
        for item in ldap_orgs:
            ldap_orgs_list.append(item['id'])
        return ldap_orgs_list

    def get_ckan_orgs(self):
        orgs = toolkit.get_action('organization_list')(self.context, {'limit': 1000, 'all_fields':False})
        return orgs