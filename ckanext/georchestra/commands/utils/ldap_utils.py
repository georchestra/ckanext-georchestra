import logging
import dateutil

import ldap, ldap.filter

from ckan.plugins.toolkit import config

log = logging.getLogger()

def get_ldap_connection():
    """
    :return: LDAP connection object
    """
    # TODO manage bytes_mode=False : see how to properly deal with unicode config. I can unicode(config[...]) every
    #      config file, but this looks dirty
    # TODO trace_level seems not possible to configure from ini files. Strange
    cnx = ldap.initialize(config['ckanext.georchestra.ldap.uri'], bytes_mode=True, trace_level=0)

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
    return cnx


def get_ldap_orgs(cnx):
    """
    Get LDAP organization list
    :return:
    """
    ldap_search_result = cnx.search_s(config['ckanext.georchestra.ldap.base_dn.orgs'], ldap.SCOPE_ONELEVEL,
                                      filterstr='(objectClass=groupOfMembers)',
                                      attrlist=['dn', 'cn', 'o', 'member', 'seeAlso', 'modifytimestamp'])
    ldap_orgs_list = []
    for elt in ldap_search_result:
        org = {'name': elt[1]['cn'][0].decode('utf_8'),
               'id': elt[1]['cn'][0].decode('utf_8'),
               'title': elt[1]['o'][0].decode('utf_8'),
               'update_ts': dateutil.parser.parse(elt[1]['modifyTimestamp'][0].decode('utf_8'))
               }
        members = elt[1]['member']
        members_list = []
        for member in members:
            members_list.append(member)
        org['members'] = members_list

        see_also_links = elt[1]['seeAlso']
        for link in see_also_links:
            res = cnx.search_s(link, ldap.SCOPE_BASE,
                               filterstr='(objectClass=*)', attrlist=None)
            if res[0][0].startswith('o='):
                org['description'] = res[0][1]['description'][0]
            else:
                # org['image_url'] =  res[0][1]['jpegPhoto'][0]
                pass
        ldap_orgs_list.append(org)

    return ldap_orgs_list

def get_roles_memberships(cnx):
    """
    Collect the CKAN roles defined in the LDAP
    :param cnx:
    :return: a dict of role entries with, for each entry, the list of members (their DN)
    """
    ldap_roles_values = [config['ckanext.georchestra.role.sysadmin'],
                         config['ckanext.georchestra.role.orgadmin'],
                         config['ckanext.georchestra.role.editor']
                         ]
    ldap_filter = '(|'
    for r in ldap_roles_values:
        ldap_filter += '(cn=' + r + ')'
    ldap_filter += ')'
    ldap_search_result = cnx.search_s(config['ckanext.georchestra.ldap.base_dn.roles'], ldap.SCOPE_ONELEVEL,
                                      filterstr=ldap_filter,
                                      attrlist=['cn', 'member', 'description'])
    roles = dict()
    for el in ldap_search_result:
        roles[el[1]['cn'][0].decode('utf_8')] = el[1]['member']
    log.debug("ok")
    return roles

def get_ldap_org_members(cnx, org):
    """
    Collect LDAP users members of the given organization
    (org is expected to ba a dict like provided by self.get_ldap_org with org['members'] list)
    :return:
    """
    ldap_users_list = []
    for member_dn in org['members']:
        res = cnx.search_s(member_dn, ldap.SCOPE_BASE,
                                      filterstr='(objectClass=person)',
                                      attrlist=None)
        user = {'dn': res[0][0].decode('utf_8'),
                'uid': res[0][1]['uid'][0].decode('utf_8'),
                'name': res[0][1]['uid'][0].decode('utf_8'),
                'id': res[0][1]['uid'][0].decode('utf_8'),
                'cn': res[0][1]['cn'][0].decode('utf_8'),
                'about': res[0][1]['description'][0].decode('utf_8'),
                'fullname': res[0][1]['givenName'][0].decode('utf_8'),
                'display_name': res[0][1]['givenName'][0].decode('utf_8'),
                'email': res[0][1]['mail'][0].decode('utf_8'),
                'sn': res[0][1]['sn'][0].decode('utf_8'),
                'password':'12345678'
                }
        ldap_users_list.append(user)
    return ldap_users_list