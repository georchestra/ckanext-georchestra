import logging
import dateutil
import re

import ldap, ldap.filter
from ldap.controls.libldap import SimplePagedResultsControl

from ckan.plugins.toolkit import config

log = logging.getLogger()

def get_ldap_connection():
    """
    :return: LDAP connection object
    """
    # TODO manage bytes_mode=False : see how to properly deal with unicode config. I can unicode(config[...]) every
    #      config file, but this looks dirty
    # TODO trace_level seems not possible to configure from ini files. Strange
    cnx = ldap.initialize(config['ckanext.georchestra.ldap.uri'], bytes_mode=False, trace_level=0)

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


def orgs_scan_and_process(cnx, process, context):
    """
    Retrieve every LDAP organization and apply the 'process' on each entry
    Search is paginated to support more than 1000 entries
    :param cnx: LDAP connection
    :param process (function): the function to apply to each LDAP entry returned by the search
    :return: the list of the org names that have been processed
    """
    # Create the page control to work from
    page_control = SimplePagedResultsControl(True, size=1000, cookie='')

    result = []
    pages = 0
    processed_orgs=[]
    # Do searches until we run out of "pages" to get from
    # the LDAP server.
    while True:
        pages += 1
        # Send search request
        try:
            response = cnx.search_ext(config['ckanext.georchestra.ldap.base_dn.orgs'],
                                  ldap.SCOPE_ONELEVEL,
                                  u'(objectClass=groupOfMembers)',
                                  attrlist=[u'dn', u'cn', u'o', u'member', u'seeAlso', u'modifytimestamp'],
                                  serverctrls=[page_control])
        except ldap.LDAPError as e:
            log.error('LDAP search failed: %s' % e)

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
        for org in rdata:
            org = org_format_and_complete(cnx, org)
            process(context, org)
            processed_orgs.append(org['id'])

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
    return processed_orgs


def org_format_and_complete(cnx, org):
    """
    Gets complementary attributes from LDAP (organization information is split into 3 objects)
    :param org:
    :return:formatted organization dict, compliant with CKAN
    """

    # Split the org tuple
    dn, attr = org
    organization = {'dn':dn,
                    'name': attr['cn'][0],
                    'id'  : attr['cn'][0],
                    'title': attr['o'][0],
                    'update_ts':dateutil.parser.parse(attr['modifyTimestamp'][0])}

    see_also_links = attr['seeAlso']
    for link in see_also_links:
        res = cnx.search_s(unicode(link, encoding='utf-8'), ldap.SCOPE_BASE,
                           filterstr=u'(objectClass=*)', attrlist=None)
        if res[0][0].startswith('o='):
            try :
                organization['description'] = res[0][1]['description'][0]
            except KeyError:
                organization['description'] = ''
        else:
            #TODO retrieve the image data and try to store it as base64 encoded URL
            # org['image_url'] =  'data:image/jpeg;base64, '+res[0][1]['jpegPhoto'][0]
            pass

    return organization


def users_scan_and_process(cnx, process, context):
    """
    Retrieve every LDAP user and apply the 'process' on each entry
    Search is paginated to support more than 1000 entries
    :param cnx: LDAP connection
    :param process (function): the function to apply to each LDAP entry returned by the search
    :return: the list of the user names that have been processed
    """
    nosync_users_list = config['ckanext.georchestra.ldap.users.nosync'].split(",")

    # Create the page control to work from
    page_control = SimplePagedResultsControl(True, size=1000, cookie='')

    result = []
    pages = 0
    processed_users=[]
    # Do searches until we run out of "pages" to get from
    # the LDAP server.
    while True:
        pages += 1
        # Send search request
        try:
            response = cnx.search_ext(config['ckanext.georchestra.ldap.base_dn.users'],
                                  ldap.SCOPE_ONELEVEL,
                                  u'(objectClass=organizationalPerson)',
                                  attrlist=None,
                                  serverctrls=[page_control])
        except ldap.LDAPError as e:
            log.error('LDAP search failed: %s' % e)

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
        for user in rdata:
            #filter out nosync users like geoserver_privileged_user
            if user[1]['uid'][0] in nosync_users_list:
                continue
            user = user_format_and_complete(cnx, user)
            process(context, user)
            processed_users.append(user['id'])

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
    return processed_users

def user_format_and_complete(cnx, user):
    """
    Add role information from LDAP
    Warning : does not support pagination: we suppose a given user will have less than 1000 roles !
    :param user:
    :return: formatted user dict, compliant with CKAN
    """
    dn, attr = user
    user_dict = {'dn': dn,
                 'uid': attr['uid'][0],
                 'name': attr['uid'][0],
                 'id': attr['uid'][0],
                 'cn': attr['cn'][0],
                 'about': attr['description'][0],
                 'fullname': attr['givenName'][0] + ' '+attr['sn'][0],
                 'display_name': attr['givenName'][0],
                 'email': attr['mail'][0],
                 'sn': attr['sn'][0],
                 'password': '12345678',
                 'state': 'active',
                 'sysadmin': False,
                 'role': 'member'
                }

    prefix = config['ckanext.georchestra.role.prefix']
    ldap_roles_dict = {
        config['ckanext.georchestra.role.sysadmin']: 'sysadmin',
        config['ckanext.georchestra.role.orgadmin']: 'admin',
        config['ckanext.georchestra.role.editor']: 'editor'
    }

    try:
        #TODO: integrate this search in the main users search above. It probably don't need to run another search
        memberships = cnx.search_s(config['ckanext.georchestra.ldap.base_dn.users'],
                              ldap.SCOPE_ONELEVEL,
                              u'(uid={0})'.format(user_dict['name']),
                              attrlist=[u'memberOf'])
        for ms in memberships:
            try:
                memberof_entries = ms[1]['memberOf']
            except KeyError:
                continue
            for m in memberof_entries:
                # get roles

                rolere = re.search(u'cn=(.*),{0}'.format(config['ckanext.georchestra.ldap.base_dn.roles']), m)
                if rolere:
                    rolename = rolere.group(1)
                    try:
                        # If this command works, it means the role is listed in the dict, hence CKAN role-related
                        r = ldap_roles_dict[rolename]
                        user_dict['role'] = r
                        user_dict['sysadmin'] = (r=='sysadmin')
                    except KeyError:
                        # means it is not CKAN roles-related membership. No interest for us. Not an error, though
                        pass
                # get the organization he is member of (if there is)
                orgre = re.search(u'cn=(.*),{0}'.format(config['ckanext.georchestra.ldap.base_dn.orgs']), m)
                if orgre:
                    orgname = orgre.group(1)
                    user_dict['orgid'] = orgname

    except ldap.LDAPError as e:
        log.error('LDAP search failed: %s' % e)

    return user_dict
