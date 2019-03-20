import logging
import dateutil

from ckan.plugins import toolkit
import ckan.model as model

log = logging.getLogger()


def update(context, ldap_user, ckan_user, org, force_update=False):
    # note : ckan does not provide revisions for user profile. This means we can't check timestamps.
    # so we use the user's profile, and check for differences on synced attributes
    #ckan_user = toolkit.get_action('user_show')(context, {'id':user['id']})

    # Update user profile
    diff = {k : ckan_user[k] for k in set(ckan_user) - set(ldap_user)}
    check_fields=['name','email', 'about','fullname', 'display_name','sysadmin', 'state']
    checks = [(ckan_user[f] != ldap_user[f]) for f in check_fields]
    needs_update=reduce(lambda x,y: x or y, checks)
    if needs_update or force_update:
        ckan_user = toolkit.get_action('user_update')(context, ldap_user)
        flush()
        log.debug("updated user {0}".format(ldap_user['id']))

    # Update user membership to organizations
    if (ldap_user['role']!= 'sysadmin'):
        updated_membership = False
        # Update membership on all organizations he belongs
        user_orgs_list = toolkit.get_action('organization_list_for_user')(context, {'id':ldap_user['id']})
        for o in user_orgs_list:
            log.debug("updating user {0} membership for organization {1}".format(ldap_user['id'], o['id']))
            if o['id'] == org['id']:
                if o['capacity'] != ldap_user['role']:
                    log.debug("changed {0} role for ".format(ldap_user['id'], o['id']))
                    toolkit.get_action('organization_member_create')(context,
                                                                     {'id': org['id'], 'username': ldap_user['id'],
                                                                      'role':ldap_user['role']})
                    flush()
                updated_membership=True
            else:
                log.debug("removing user {0} from organization {1}".format(ldap_user['id'], o['id']))
                toolkit.get_action('organization_member_delete')(context, {'id': org['id'],
                                                                           'username': ldap_user['id']})
                flush()
        # He not not have belonged to the current org. This is dealt with here
        if not updated_membership:
            toolkit.get_action('organization_member_create')(context,
                                                             {'id': org['id'], 'username': ldap_user['name'],
                                                              'role': ldap_user['role']})

    return ckan_user

def create(context, user, org):
    # Apply auth fix from https://github.com/datagovuk/ckanext-harvest/commit/f315f41c86cbde4a49ef869b6993598f8cb11e2d
    # to error message Action function organization_show did not call its auth function
    context.pop('__auth_audit', None)
    ckan_user = None
    try:
        # create user
        ckan_user = toolkit.get_action('user_create')(context, user)
        log.debug("created user {0}".format(user['id']))

        if (user['role'] != 'sysadmin'):
            # add it as member of the organization
            toolkit.get_action('organization_member_create')(context, {'id': org['id'], 'username': user['id'],
                                                                       'role': user['role']})
            flush()
    except Exception as e:
        log.error(e, exc_info=True)
    return ckan_user

def delete(context, id, purge=True):
    """
    remove a user from the users list
    :param id(string): id of the user to delete
    :param purge (Boolean): purge or simply set as 'state':'deleted'. (optional, default:True)
    :return:
    """
    try:
        if purge:
            # toolkit.get_action('user_delete')(self.context, {'id': orphan})
            # Beware : user_delete doesn't purge the user, it just shows it as deleted state.
            # This is how to do it (cf https://stackoverflow.com/questions/33881318/how-to-completely-delete-a-ckan-user)
            model.User.get(id).purge()
            flush()
        else:
            toolkit.get_action('user_delete')(context, {'id': id})
    except toolkit.ObjectNotFound, e:
        log.error("Not found orphan user when trying to remove it: {0}".format(e))


def flush():
    model.Session.commit()
    model.Session.remove()