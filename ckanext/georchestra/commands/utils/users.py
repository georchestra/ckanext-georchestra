import logging
import dateutil

from ckan.plugins import toolkit
import ckan.model as model

log = logging.getLogger()


def update_or_create(context, user, force_update=False):
    # note : ckan does not provide revisions for user profile. This means we can't check timestamps.
    # so we use the user's profile, and check for differences on synced attributes
    #ckan_user = toolkit.get_action('user_show')(context, {'id':user['id']})
    try:
        # Update user profile
        ckan_user = toolkit.get_action('user_show')(context.copy(), {'id': user['id']})
        check_fields = ['name', 'email', 'about', 'fullname', 'display_name', 'sysadmin', 'state']
        checks = [(ckan_user[f] != user[f]) for f in check_fields]
        needs_update = reduce(lambda x, y: x or y, checks)
        if needs_update or force_update:
            ckan_user = toolkit.get_action('user_update')(context.copy(), user)
            log.debug("updated user {0}".format(user['name']))
        else:
            log.debug("user {0} is up-to-date".format(user['name']))

        # Update user membership to organizations
        if (user['role'] != 'sysadmin'):
            updated_membership = False
            # Update membership on all organizations he belongs to (we remove him from all except the one listed in
            # his LDAP profile
            try:
                user_orgs_list = toolkit.get_action('organization_list_for_user')(context.copy(), {'id': user['id']})
                for o in user_orgs_list:
                    log.debug("Checking {0} membership for organization {1}".format(user['name'], o['name']))
                    if ('orgid' in user) and (o['name'] == user['orgid']):
                        if o['capacity'] != user['role']:
                            log.debug("changing {0} role for ".format(user['name'], o['name']))
                            toolkit.get_action('organization_member_create')(context.copy(),
                                                                             {'id': o['id'], 'username': user['name'],
                                                                              'role': user['role']})
                        updated_membership = True
                    else:
                        log.debug("removing user {0} from organization {1}".format(user['name'], o['name']))
                        toolkit.get_action('organization_member_delete')(context.copy(), {'id': o['id'],
                                                                                      'username': user['name']})
            except toolkit.ObjectNotFound as e:
                # this should not happen
                log.error(e, exc_info=True)
            # He might not have belonged to the current org. This is dealt with here
            if ('orgid' in user) and ( not updated_membership):
                toolkit.get_action('organization_member_create')(context.copy(),
                                                                 {'id': user['orgid'], 'username': user['name'],
                                                                  'role': user['role']})
    except toolkit.ObjectNotFound:
        # Means it doesn't exist yet => we create it
        create(context, user)
    pass


def create(context, user):
    ckan_user = None
    try:
        # create user
        log.debug("create user {0}".format(user['id']))
        ckan_user = toolkit.get_action('user_create')(context.copy(), user)

        if (user['role'] != 'sysadmin') and ('orgid' in user):
            # add it as member of the organization
            toolkit.get_action('organization_member_create')(context.copy(),
                                                             {'id': user['orgid'], 'username': user['id'],
                                                              'role': user['role']}
                                                             )
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
            toolkit.get_action('user_delete')(context.copy(), {'id': id})
    except toolkit.ObjectNotFound, e:
        log.error("Not found orphan user when trying to remove it: {0}".format(e))


def flush():
    model.Session.commit()
    model.Session.remove()