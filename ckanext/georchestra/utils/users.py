# encoding: utf-8

import logging

from ckan.plugins import toolkit
from ckan.logic import ValidationError
import ckan.model as model

import ckanext.georchestra.utils.organizations as organizations_utils
import ckanext.georchestra.utils.ldap_utils as ldap_utils


log = logging.getLogger()


def update_or_create(context, user):
    # note : ckan does not provide revisions for user profile. This means we can't check timestamps.
    # so we use the user's profile, and check for differences on synced attributes
    # ckan_user = toolkit.get_action('user_show')(context, {'id':user['id']})
    try:
        force_update = toolkit.config.get('ckanext.georchestra.sync.force_update', False)
        # Update user profile
        ckan_user = toolkit.get_action('user_show')(context.copy(), {'id': user['id']})
        check_fields = ['name', 'email', 'about', 'fullname', 'display_name', 'sysadmin', 'state']
        checks = [(ckan_user[f] != user[f]) for f in check_fields]
        needs_update = reduce(lambda x, y: x or y, checks)
        if needs_updating(check_fields, ckan_user, user) or force_update:
            toolkit.get_action('user_update')(context.copy(), user)
            log.debug("{1}updated user {0}".format(user['name'], 'force-' if force_update else ''))
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
                    if ('org_id' in user) and (o['name'] == user['org_id']) and (user['org_id']):
                        if o['capacity'] != user['role']:
                            log.debug("changing {0} role for ".format(user['name'], o['name']))
                            toolkit.get_action('organization_member_create')(context.copy(),
                                                                             {'id': o['id'], 'username': user['name'],
                                                                              'role': user['role']})
                        updated_membership = True
                    elif not (user['org_id']):
                        pass
                    else:
                        log.debug("removing user {0} from organization {1}".format(user['name'], o['name']))
                        toolkit.get_action('organization_member_delete')(context.copy(), {'id': o['id'],
                                                                                      'username': user['name']})
            except toolkit.ObjectNotFound as e:
                # this should not happen
                log.error(e, exc_info=True)
            # He might not have belonged to the current org. This is dealt with here
            if ('org_id' in user) and ( not updated_membership) and (user['org_id']):
                toolkit.get_action('organization_member_create')(context.copy(),
                                                                 {'id': user['org_id'], 'username': user['name'],
                                                                  'role': user['role']})
    except toolkit.ObjectNotFound:
        # Means it doesn't exist yet => we create it
        create(context, user)
    except ValidationError as e:
        # Means it isn't valid
        log.error("User parameters are invalid. Could not update the user {}. \n{}".format(user['name'], e))


def create(context, user):
    ckan_user = None
    try:
        # create user
        log.debug("create user {0}".format(user['id']))
        ckan_user = toolkit.get_action('user_create')(context.copy(), user)

        if (user['role'] != 'sysadmin') and ('org_id' in user) and (user['org_id']):
            # add it as member of the organization
            organizations_utils.organization_set_member_or_create(context.copy(), user['id'], user['org_id'],
                                                                  user['role'])
            #toolkit.get_action('organization_member_create')(context.copy(),
            #                                                 {'id': user['org_id'], 'username': user['id'],
            #                                                  'role': user['role']}
            #                                                 )
    except toolkit.ValidationError as e:
        log.error("User parameters are invalid. Could not create the user {}. \n{}".format(user['name'], e))
    return ckan_user


def delete(context, id, purge=True, orphan_org_name='orphan_users'):
    """
    remove a user from the users list
    :param id(string): id of the user to delete
    :param purge (Boolean): purge if True. If False, it moves the user to an 'orphan_users' org and removes it from
     any other organization (optional, default:True)
    :return:
    """
    if purge:
        # toolkit.get_action('user_delete')(context.copy(), {'id': orphan})
        # Beware : user_delete doesn't purge the user, it just shows it as deleted state.
        # This is how to do it (cf https://stackoverflow.com/questions/33881318/how-to-completely-delete-a-ckan-user)
        model.User.get(id).purge()
        flush()
        log.debug('Purged user {} from database (not present anymore in LDAP)'.format(id))
    else:
        #toolkit.get_action('user_delete')(context.copy(), {'id': id})
        # create orphan org if it doesn't exist
        orphan_org_id = ldap_utils.sanitize(orphan_org_name)
        try:
            toolkit.get_action('organization_create')(context.copy(), {'name': orphan_org_id, 'title':orphan_org_name})
        except Exception as e:
            # the org already exists
            pass

        try:
            # Add user to this org
            toolkit.get_action('organization_member_create')(context.copy(), {'id': orphan_org_id, 'username':id, 'role':'member'})

            # Remove user from other orgs
            user_orgs = toolkit.get_action('organization_list_for_user')(context.copy(), {'id': id})
            for org in user_orgs:
                if org['name'] == orphan_org_id:
                    continue
                toolkit.get_action('member_delete')(context.copy(), {'id': org['id'], 'object':id, 'object_type':'user'})
        except Exception as e:
            log.error('Error adding user {} to org {}'.format(id, orphan_org_id))
            log.error(e, exc_info=True)


def needs_updating(check_fields, ckan_user, userdict):
    """
    Checks equality for every listed field
    :param check_fields: list of field names (e.g. ['name', 'email', 'fullname', 'sysadmin', 'state'])
    :param ckan_user:
    :param userdict:
    :return:
    """
    checks = [(ckan_user[f] != userdict[f]) for f in check_fields]
    needs_update = reduce(lambda x, y: x or y, checks)
    return needs_update


def flush():
    model.Session.commit()
    model.Session.remove()