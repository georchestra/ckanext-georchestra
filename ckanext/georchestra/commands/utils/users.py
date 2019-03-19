import logging
import dateutil

from ckan.plugins import toolkit
import ckan.model as model

log = logging.getLogger()


def update(context, user, ckan_user,org, force_update=False):
    # note : ckan does not provide revisions for user profile. This means we can't check timestamps.
    # so we use the user's profile, and check for differences on synced attributes
    #ckan_user = toolkit.get_action('user_show')(context, {'id':user['id']})

    diff = { k : ckan_user[k] for k in set(ckan_user)-set(user)}
    check_fields=['name','email', 'about','fullname', 'display_name','sysadmin', 'state']
    checks = [(ckan_user[f]!= user[f]) for f in check_fields]
    needs_update=reduce(lambda x,y: x or y, checks)
    if needs_update or force_update:
        ckan_user = toolkit.get_action('user_update')(context, user)
        log.debug("updated user {0}".format(user['id']))

    # TODO: remove user from other orgs
    if (user['role']!='sysadmin'):
        #TODO: check if role changed
        toolkit.get_action('organization_member_create')(context,
                                                     {'id': org['id'], 'username': user['id'], 'role':user['role']})
    return ckan_user

def add(context, orgs_list):
    pass

def remove(context, orgs_list):
    pass


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
            toolkit.get_action('organization_member_create')(context, {'id':org['id'], 'username':user['id'], 'role':user['role']})
    except Exception as e:
        log.error(e, exc_info=True)
    return ckan_user

def delete(context, id):
    r = { }
    pass
