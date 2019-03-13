import logging
import pylons
from ckan.lib.cli import CkanCommand
from ckan.plugins import toolkit
from ckan import logic
from logic import ValidationError
import ldap, ldap.filter
from ckan.common import config
import dateutil


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

    def preseed(self):
        """
        Clean the ckan instance
        create some common orgs, some deprecated ones and leave some uncreated
        :return:
        """
        self.organization_create({'id':'fake', 'name':'fake'})
        for org in ['psc', 'c2c', 'cra']:
            try:
                toolkit.get_action('organization_purge')(self.context, {'id': org})
                log.debug("purged organization {0}".format(org))
                org = toolkit.get_action('organization_show')(self.context, {'id': org})
                log.debug("organization {0} already exists".format(org))
            except logic.NotFound:
                # Means the organization was not found => we create it
                if org in ['c2c','psc']:
                    self.organization_create({'id':org, 'name':org})

    def sync_organizations(self):
        self.preseed()
        ldap_orgs_list = self.get_ldap_orgs()
        ckan_orgs_names_list = self.get_ckan_orgs()

        ckan_orgs_set=set(ckan_orgs_names_list)

        orgs_exist = [ el for el in ldap_orgs_list if el['id'] in ckan_orgs_set ]
        orgs_missing = [ el for el in ldap_orgs_list if el['id'] not in ckan_orgs_set ]
        orgs_deprecated = list( ckan_orgs_set - set([el['id'] for el in ldap_orgs_list]))

        self.organizations_update(orgs_exist)
        self.organizations_add(orgs_missing)
        self.organizations_remove(orgs_deprecated)

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

    def organizations_update(self, orgs_list):
        for org in orgs_list:
            try:
                #current_org = toolkit.get_action('organization_show')(self.context, {'id': org['id'], 'include_extras':True})
                revisions = toolkit.get_action('organization_revision_list')(self.context,
                                                                      {'id': org['id']})
                # in order to be able to compare with LDAP timestamp, we need it to be seen as time-aware.
                # TODO: check it is really UTC time always
                #last_revision=dateutil.parser.parse(revisions[0]['timestamp']+'Z')
                last_revision = dateutil.parser.parse('20190208085726Z')
                if org['update_ts'] > last_revision:
                    # then we update it
                    log.debug("updating organization {0}".format(org['id']))
                    current_org = toolkit.get_action('organization_patch')(self.context,
                                                                          org)
                log.debug("ok")
            except:
                log.error("Could not read organization {0} (should exist though".format(org))

    def organizations_add(self, orgs_list):
        # trick to solve this SQLalchemy flushing issue. It seems 'group' info stays present in the self.session and
        # messes things up. Clearing the 'group' var seems to help.
        self.context['group'] = None
        for org in orgs_list:
            self.organization_create(org)
            log.debug("added organization {0}".format(org['id']))

    def organizations_remove(self, orgs_list):
        # TODO : check content and move all packages to a 'ghost' org before purging org
        for org in orgs_list:
            try:
                toolkit.get_action('organization_purge')(self.context, {'id': org})
                log.debug("purged organization {0}".format(org))
            except:
                log.error("could not purge organization {0}".format(org))

    def organization_create(self, data_dict):
        # Apply auth fix from https://github.com/datagovuk/ckanext-harvest/commit/f315f41c86cbde4a49ef869b6993598f8cb11e2d
        # to error message Action function organization_show did not call its auth function
        self.context.pop('__auth_audit', None)
        try:
            log.debug("creating organization {0}".format(data_dict['id']))
            toolkit.get_action('organization_create')(self.context, data_dict)
        except ValidationError, e:
            log.error(e['name'])

    def organization_delete(self, id):
        # TODO : resolve bug, see comment underneath
        """
        Don't use it. It generates an error from sqlalchemy :
        related attribute set' operation is not currently supported within the execution stage of the flush process
        already reported and closed (https://github.com/ckan/ckan/issues/2017). See if I can identify it or propose a
        reliable way to reproduce ut (seems pretty reliable right now : just run twice organization_delete then some
        organization_create and it all goes weird. For instance, my preseed function was like this :
        for org in ['psc', 'c2c', 'cra', 'fake']:
            self.organization_delete(org)

        self.organization_create("c2c", None))
        self.organization_create("fake", None)
        and it would not create c2c organization, after issuing the sqlalchemy error)
        """
        self.context.pop('__auth_audit', None)
        try:
            toolkit.get_action('organization_purge')(self.context, {'id': id})
            log.debug("purged organization {0}".format(id))
        except:
            log.error("could not delete org {0}".format(id))

