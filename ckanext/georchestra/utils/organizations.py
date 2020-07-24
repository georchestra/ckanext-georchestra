# encoding: utf-8

import logging
import dateutil
import time

from ckan.plugins import toolkit
from ckan import model

log = logging.getLogger()


def update_or_create(context, org):
    try:
        force_update = toolkit.config.get('ckanext.georchestra.sync.force_update', False)
        ckanorg = toolkit.get_action('organization_show')(context.copy(), {'id': org['id'], 'include_extras': True})
        revisions = toolkit.get_action('organization_revision_list')(context.copy(), {'id': org['id']})
        # If no error, also means the org exists

        # in order to be able to compare with LDAP timestamp, we need it to be seen as time-aware.
        # TODO: check it is really UTC time always
        last_revision = dateutil.parser.parse(revisions[0]['timestamp'] + 'Z')

        # last_revision = dateutil.parser.parse('20190208085726Z')
        # we have 3 update cases :
        #  - revision date in the LDAP is more recent than in the ckan db
        #  - the 'title' field is empty, meaning  we created it on-the-fly when a user needed it (see plugin.py)
        #  - force_update : mostly for testing purpose
        if (org['update_ts'] > last_revision) or (len(ckanorg['title']) == 0) or force_update:
            # then we update it
            log.debug("{1}updating organization {0}".format(org['name'], 'force-' if force_update else ''))
            # We need this to update the logo:
            if ('image_url' in org) and (org['image_url'] != ckanorg['image_url']): # 2nd part is needed to solve  https://github.com/ckan/ckan/issues/5293
                org['clear_upload'] = True
            toolkit.get_action('organization_patch')(context.copy(), org)
        else:
            log.debug("Organization {0} is up-to-date".format(org['id']))
    except toolkit.ObjectNotFound:
        # Means it doesn't exist yet => we create it
        log.debug("Creating organization {0}".format(org['name']))
        create(context, org)
    pass


def remove(context, orgs_list):
    ghost_prefix = toolkit.config['ckanext.georchestra.organization.ghosts.prefix']
    for id in orgs_list:
        org = toolkit.get_action('organization_show')(context.copy(), {'id': id})
        if org['package_count'] == 0:
            delete(context, id)
            log.debug("purged organization {0}".format(id))
        else:
            # TODO: discuss the proper way to manage ghost orgs
            # If we purge an org owning datasets, it will make them hard to manage.
            log.debug("renamed organization {0}".format(id))
            if not org['title'].startswith(ghost_prefix):
                org['title'] = ghost_prefix + org['title']
                # org['name'] = "ghost_" + org['name'] # makes datasets impossible to retrieve...
                current_org = toolkit.get_action('organization_patch')(context.copy(), org)
            for u in org['users']:
                toolkit.get_action('organization_member_delete')(context.copy(), {'id': org['id'], 'username': u['id']})


def create(context, data_dict):
    # Apply auth fix from https://github.com/datagovuk/ckanext-harvest/commit/f315f41c86cbde4a49ef869b6993598f8cb11e2d
    # to error message Action function organization_show did not call its auth function
    context.pop('__auth_audit', None)
    try:
        log.debug("creating organization {0}".format(data_dict['id']))
        toolkit.get_action('organization_create')(context.copy(), data_dict)
    except Exception as e:
        log.error(e, exc_info=True)


def delete(context, id):
    try:
        toolkit.get_action('organization_purge')(context.copy(), {'id': id})
        flush()
        log.debug("purged organization {0}".format(id))
    except toolkit.ValidationError as e:
        log.warning('Could not purge organization {0}. Error message states {1}'.format(id, e))
        # log.error(e, exc_info=True)


def delete_all_orgs(context, delete_active=False):
    try:
        # TODO: find a way to list also orgs in state 'deleted'. For now, I don't get them...
        orgs = toolkit.get_action('organization_list')(context.copy(), {'all_fields': True})
        for org in orgs:
            if org['state'] == 'deleted' or delete_active:
                delete(context, org['id'])
    except Exception as e:
        log.error(e, exc_info=True)


def organization_set_member_or_create(context, user_id, org_id, role):
    """
    Set user as member of the organization, with the given role.
    If the organization doesn't exist, create the organization, setting only its ID. The remaining information will
    be completed on next full sync (paster command)
    :param context:
    :param user_id:
    :param org_id:
    :param role:
    :return:
    """
    try:
        toolkit.get_action('organization_member_create')(context.copy(), {'id': org_id, 'username': user_id,
                                                                          'role': role})
        log.debug("added user to {0}".format(org_id))

    except toolkit.ValidationError:
        # Means the org doesn't exist yet => we create it
        log.debug("Creating organization {0}".format(org_id))
        toolkit.get_action('organization_create')(context.copy(), {'name': org_id})
        log.debug("adding user to {0}".format(org_id))
        toolkit.get_action('organization_member_create')(context.copy(), {'id': org_id, 'username': user_id,
                                                                          'role': role})


def flush():
    model.Session.commit()
    model.Session.remove()
