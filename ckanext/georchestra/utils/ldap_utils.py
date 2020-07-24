# encoding: utf-8

import logging
import dateutil
import re
import six
import base64
from collections import OrderedDict

import ldap, ldap.filter
from ldap.controls.libldap import SimplePagedResultsControl

from ckan.plugins.toolkit import config

log = logging.getLogger()

def get_ldap_roles_as_ordereddict(prefix=''):
    """
    Get a mapping between ROLES as defined by geOrchestra, and user roles as defined in CKAN
    :param prefix: depending on the circumstances, the geOrchestra role will be prefixed by 'ROLE_' or not. Defaults to
    ''
    :return: OrderedDict starting with higher credential level
    """
    ldap_roles_dict = OrderedDict([
            (prefix + config['ckanext.georchestra.role.sysadmin'], u'sysadmin'),
            (prefix + config['ckanext.georchestra.role.orgadmin'], u'admin'),
            (prefix + config['ckanext.georchestra.role.editor'], u'editor')
        ])
    return ldap_roles_dict


def get_ckan_role_from_security_proxy_roles(sec_roles):
    # define role for user (default is unprivileged 'member')
    default_role = u'member'  # default
    # security-proxy adds a prefix in front of the LDAP roles
    prefix = config['ckanext.georchestra.role.prefix']
    ldap_roles_dict = get_ldap_roles_as_ordereddict(prefix)
    if sec_roles:
        for key, role in ldap_roles_dict.iteritems():
            if key in sec_roles.split(";"):
                return role
    return default_role


class GeorchestraLdap():
    cnx = None
    nosync_users_list = None

    def __init__(self):
        self.nosync_users_list = config['ckanext.georchestra.ldap.users.nosync'].split(",")

    def _create_ldap_connection(self):
        """
        Initialize the LDAP connection. To get the LDAP connection object, prefer get_ldap_connection()
        :return: LDAP connection object
        """
        self.cnx = ldap.initialize(config['ckanext.georchestra.ldap.uri'], bytes_mode=False,
                              trace_level=config['ckanext.georchestra.ldap.trace_level'])

        if not config.get('ckanext.georchestra.ldap.admin.dn'):
            # don't authenticate
            return

        try:
            if config['ckanext.georchestra.ldap.auth.method'] == 'SIMPLE':
                self.cnx.bind_s(config['ckanext.georchestra.ldap.admin.dn'],
                           config['ckanext.georchestra.ldap.admin.password'])
            elif config['ckanext.georchestra.ldap.auth.method'] == 'SASL':
                if config['ckanext.georchestra.ldap.auth.mechanism'] == 'DIGEST-MD5':
                    auth_tokens = ldap.sasl.digest_md5(config['ckanext.georchestra.ldap.admin.dn'],
                                                       config['ckanext.georchestra.ldap.admin.password'])
                    self.cnx.sasl_interactive_bind_s("", auth_tokens)
                else:
                    log.error("SASL mechanism not supported: {0}".format(
                        config['ckanext.georchestra.ldap.auth.mechanism']))
                    return
            else:
                log.error(
                    "LDAP authentication method is not supported: {0}".format(
                        config['ckanext.georchestra.ldap.auth.method']))
                return
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            return
        except ldap.INVALID_CREDENTIALS:
            log.error(
                'LDAP server credentials (ckanext.georchestra.ldap.admin.dn and ckanext.georchestra.ldap.admin.password) invalid')
            return
        except ldap.LDAPError, e:
            log.error("Fatal LDAP Error: {0}".format(e))
            return

    def get_ldap_connection(self):
        """
        Reuses existing connection when possible
        :return: LDAP connection object
        """
        if not self.cnx:
            self._create_ldap_connection()
        return self.cnx

    def orgs_scan_and_process(self, external_process, context):
        """
        Retrieve every LDAP organization and apply the 'external_process' on each entry
        Search is paginated to support more than 1000 entries
        :param external_process (function): the function to apply to each LDAP entry returned by the search
        :param context: the ckan context
        :return: the list of the org names that have been processed
        """
        dn = config['ckanext.georchestra.ldap.orgs.rdn'] + u',' + config['ckanext.georchestra.ldap.base_dn']
        filter = u'(objectClass=groupOfMembers)'
        attributes = [u'dn', u'cn', u'o', u'member', u'seeAlso', u'modifytimestamp']
        processed_orgs = self._paginate_scan_and_process(dn, filter, attributes, self._process_org,
                                                          external_process, context)
        return processed_orgs

    def users_scan_and_process(self, external_process, context):
        """
        Retrieve every LDAP user and apply the 'external_process' on each entry
        Search is paginated to support more than 1000 entries
        :param external_process (function): the function to apply to each LDAP entry returned by the search
        :param context: the ckan context
        :return: the list of the user names that have been processed
        """
        dn = config['ckanext.georchestra.ldap.users.rdn'] + u',' + config['ckanext.georchestra.ldap.base_dn']
        filter = u'(objectClass=organizationalPerson)'
        attributes = [u'dn', u'uid', u'cn', u'description', u'givenName', u'mail', u'sn', u'memberOf']
        processed_users = self._paginate_scan_and_process(dn, filter, attributes, self._process_user,
                                                          external_process, context)
        return processed_users

    def _paginate_scan_and_process(self, dn, filter, attributes, process_item, external_process, context):
        """
        Retrieve every LDAP user and apply the 'process' on each entry
        Search is paginated to support more than 1000 entries
        :param process (function): the function to apply to each LDAP entry returned by the search
        :return: the list of the user names that have been processed
        """
        cnx = self.get_ldap_connection()

        # Create the page control to work from
        page_control = SimplePagedResultsControl(True, size=1000, cookie='')

        result = []
        pages = 0
        processed_items=[]
        response = None
        # Do searches until we run out of "pages" to get from
        # the LDAP server.
        while True:
            pages += 1
            # Send search request
            try:
                response = cnx.search_ext(dn,
                                      ldap.SCOPE_ONELEVEL,
                                      filter,
                                      attrlist=attributes,
                                      serverctrls=[page_control])
            except ldap.LDAPError as e:
                log.error('LDAP search failed: %s' % e)
                return None

            # Pull the results from the search request
            try:
                rtype, rdata, rmsgid, serverctrls = cnx.result3(response)
            except ldap.LDAPError as e:
                log.error('Could not pull LDAP results: %s' % e)

            # Each "rdata" is a tuple of the form (dn, attrs), where dn is
            # a string containing the DN (distinguished name) of the entry,
            # and attrs is a dictionary containing the attributes associated
            # with the entry. The keys of attrs are strings, and the associated
            # values are lists of strings.
            for item in rdata:
                processed_id = process_item(item, external_process, context)
                processed_items.append(processed_id)

            # Get cookie for next request
            result.extend(rdata)
            controls = [control for control in serverctrls
                        if control.controlType == SimplePagedResultsControl.controlType]
            if not controls:
                print('The server ignores RFC 2696 control')
                break

            # Ok, we did find the page control, yank the cookie from it and
            # insert it into the control for our next search. If however there
            # is no cookie, we are done!

            page_control.cookie = controls[0].cookie
            if not controls[0].cookie:
                break
        return processed_items

    def _process_org(self, org, external_process, context):
        """
        Applied to every organization entry listed during the LDAP scan
        :param org:
        :param external_process:
        :param context:
        :return:
        """
        org = self._org_format_and_complete(org)
        external_process(context, org)
        return org['id']

    def _process_user(self, user, external_process, context):
        """
        Applied to every user entry listed during the LDAP scan
        :param user:
        :param external_process:
        :param context:
        :return:
        """
        # filter out nosync users like geoserver_privileged_user
        if user[1]['uid'][0] in self.nosync_users_list:
            return None
        user = self._user_format_and_complete(user)
        external_process(context, user)
        return user['id']

    def _org_format_and_complete(self, org):
        """
        Gets complementary attributes from LDAP (organization information is split into 2 objects)
        :param org:
        :return:formatted organization dict, compliant with CKAN
        """
        cnx = self.get_ldap_connection()

        # Split the org tuple
        dn, attr = org
        organization = {'dn':dn,
                        'name': sanitize(attr['cn'][0]),
                        'id'  : sanitize(attr['cn'][0]),
                        'title': attr['o'][0],
                        'update_ts':dateutil.parser.parse(attr['modifyTimestamp'][0])}
        see_also_links = attr['seeAlso']

        # Retrieve additional information stored in the georchestraOrg object
        ldap_o_georchestra = [link for link in see_also_links if link.startswith('o=')]
        if ldap_o_georchestra:
            link = ldap_o_georchestra[0]
            attributes = [u'o', u'description', u'jpegPhoto', u'labeledURI', u'businessCategory', u'postalAddress', u'modifytimestamp']
            try:
                res = cnx.search_s(six.text_type(link, encoding='utf-8'), ldap.SCOPE_BASE,
                           filterstr=u'(objectClass=*)', attrlist=attributes)

                organization['description'] = getFirstValue(res[0][1].get('description'))
                # retrieve base64-encoded picture
                jpeg_photo = res[0][1].get('jpegPhoto')
                if jpeg_photo:
                    image_base_64 = base64.b64encode(jpeg_photo[0])
                    organization['image_url'] = 'data:image/jpeg;base64, {}'.format(image_base_64)
                labeled_uri = getFirstValue(res[0][1].get('labeledURI'))
                if labeled_uri:
                    organization['extras'] = [
                            { 'key' : 'site', 'value' : labeled_uri }
                        ]
                o_modified_time = dateutil.parser.parse( getFirstValue(res[0][1].get('modifyTimestamp')) )
                if organization['update_ts'] < o_modified_time:
                    organization['update_ts'] = o_modified_time
            except KeyError as e:
                log.error("This should not happen. Error {}".format(e))

            except ldap.NO_SUCH_OBJECT as e:
                log.error("{}".format(e))
                log.error('LDAP error in org entry: ')
                log.error('{}  -> seeAlso {}\n'.format(organization['dn'], ', '.join(map(str, see_also_links))))
        return organization

    def _user_format_and_complete(self, user):
        """
        Add role information from LDAP
        Warning : does not support pagination: we suppose a given user will have less than 1000 roles !
        :param user: (dn, attr) tuple returned by LDAP search
        :return: formatted user dict, compliant with CKAN
        """
        dn, attr = user
        user_dict = {'dn': dn,
                     'uid': getFirstValue(attr.get('uid')),
                     'name': sanitize(getFirstValue(attr.get('uid'))),
                     'id': sanitize(getFirstValue(attr.get('uid'))),
                     'cn': getFirstValue(attr.get('cn')),
                     'about': getFirstValue(attr.get('description')),
                     'fullname': getFirstValue(attr.get('givenName')) + u' '+getFirstValue(attr.get('sn')),
                     'display_name': getFirstValue(attr.get('givenName')) + u' '+getFirstValue(attr.get('sn')),
                     'email': getFirstValue(attr.get('mail')),
                     'sn': getFirstValue(attr.get('sn')),
                     'password': '12345678',
                     'state': 'active',
                     'sysadmin': False,
                     'role': 'member'
                    }

        ldap_roles_dict = get_ldap_roles_as_ordereddict ()

        try:
            # get ckan role
            # extract only the role label (cn) from the memberOf list
            search_string = u'cn=(.*),{0},{1}'.format(config['ckanext.georchestra.ldap.roles.rdn'],
                                                      config['ckanext.georchestra.ldap.base_dn'])
            roles_re = [ re.findall(search_string, m, re.U)[0]
                         for m in attr[u'memberOf'] if config['ckanext.georchestra.ldap.roles.rdn'] in m ]
            # we iterate from the highest level to the lowest, so that if multiple roles are declared, we get the
            # highest
            for k, v in ldap_roles_dict.iteritems():
                if k in roles_re:
                    user_dict['role'] = v
                    user_dict['sysadmin'] = (v=='sysadmin')
                    break

            # get the organization he is member of (if there is)
            # extract only the org label (cn) from the memberOf list
            search_string = u'cn=(.*),{0},{1}'.format(config['ckanext.georchestra.ldap.orgs.rdn'],
                                                      config['ckanext.georchestra.ldap.base_dn'])
            orgs_re = [re.findall(search_string, m, re.U)[0]
                        for m in attr[u'memberOf'] if config['ckanext.georchestra.ldap.orgs.rdn'] in m]

            if orgs_re:
                # get the first listed organization
                # TODO : we should deal with possibility that the user belongs to several orgs
                orgname = orgs_re[0]
                user_dict['org_id'] = sanitize(orgname)
        except KeyError as e:
            # means is not member of anything
            pass
        except ldap.LDAPError as e:
            log.error('LDAP search failed: %s' % e)

        return user_dict

def sanitize(s):
    """
    Make string compatible for usage as CKAN org name: make it lowercase and remove anything other than alphanumeric
    or -_
    :param s:
    :return:
    """
    if not s:
        return ''
    return re.sub(r'[^\w-]', '_',s).lower()

def getFirstValue(attr_list):
    """
    Get the  string value of the first element of the list or '' if not defined
    :param el:
    :return:
    """
    if not attr_list:
        return u''
    return six.text_type(attr_list[0], encoding='utf-8')