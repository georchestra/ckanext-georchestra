import logging
import dateutil

from ckan.plugins import toolkit

log = logging.getLogger()


def update(context, user, force_update=False):
    # TODO: check timestamps to determine if we update or no
    ckan_user = toolkit.get_action('user_update')(context, user)
    log.debug("updated user {0}".format(user['id']))
    return ckan_user

def add(context, orgs_list):
    pass

def remove(context, orgs_list):
    pass


def create(context, user):
    # Apply auth fix from https://github.com/datagovuk/ckanext-harvest/commit/f315f41c86cbde4a49ef869b6993598f8cb11e2d
    # to error message Action function organization_show did not call its auth function
    context.pop('__auth_audit', None)
    ckan_user = None
    try:
        ckan_user = toolkit.get_action('user_create')(context, user)
        log.debug("created user {0}".format(user['id']))
    except Exception as e:
        log.error(e, exc_info=True)
    return ckan_user

def delete(context, id):
    pass
