import logging
import dateutil

from ckan.plugins import toolkit
from ckan import model

log = logging.getLogger()


def preseed(context):
    """
    Clean the ckan instance
    create some common orgs, some deprecated ones and leave some uncreated
    :return:
    """
    create(context, {'id': 'fake', 'name': 'fake'})
    # for org in ['psc', 'c2c', 'cra']:
    for org in ['c2c']:
        try:
            toolkit.get_action('organization_purge')(context.copy(), {'id': org})
            log.debug("purged organization {0}".format(org))
            org = toolkit.get_action('organization_show')(context.copy(), {'id': org})
            log.debug("organization {0} already exists".format(org))
        except toolkit.ObjectNotFound:
            # Means the organization was not found => we create it
            if org in ['c2c', 'psc']:
                create(context, {'id': org, 'name': org})
        except Exception as e:
            log.error(e, exc_info=True)


def update_or_create(context, org, force_update=False):
    try:
        revisions = toolkit.get_action('organization_revision_list')(context.copy(), {'id': org['id']})
        # If no error, also means the org exists

        # in order to be able to compare with LDAP timestamp, we need it to be seen as time-aware.
        # TODO: check it is really UTC time always
        last_revision = dateutil.parser.parse(revisions[0]['timestamp'] + 'Z')

        #last_revision = dateutil.parser.parse('20190208085726Z')
        # we have 3 update cases :
        #  - revision date in the LDAP is more recent than in the ckan db
        #  - the 'title' field is empty, meaning  we created it on-the-fly when a user needed it (see plugin.py)
        #  - force_update : mostly for testing purpose
        if (org['update_ts'] > last_revision) or (len(org['title']) == 0) or force_update:
            # then we update it
            log.debug("updating organization {0}".format(org['name']))
            current_org = toolkit.get_action('organization_patch')(context.copy(), org)
        else:
            log.debug("Organization {0} is up-to-date".format(org['id']))
    except toolkit.ObjectNotFound:
        # Means it doesn't exist yet => we create it
        log.debug("Creating organization {0}".format(org['name']))
        create(context, org)
    pass


def remove(context, orgs_list):
    for id in orgs_list:
        org = toolkit.get_action('organization_show')(context.copy(), {'id': id})
        if org['package_count'] == 0:
            delete(context, id)
            log.debug("purged organization {0}".format(id))
        else:
            # TODO: discuss the proper way to manage ghost orgs
            # If we purge an org owning datasets, it will make them hard to manage.
            log.debug("renamed organization {0}".format(id))
            if not org['title'].startswith("[GHOST] "):
                org['title'] = "[GHOST] " + org['title']
                #org['name'] = "ghost_" + org['name'] # makes datasets impossible to retrieve...
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
    # TODO : check content and move all packages to a 'ghost' org before purging org
    context.pop('__auth_audit', None)
    try:
        toolkit.get_action('organization_purge')(context.copy(), {'id': id})
        flush()
        log.debug("purged organization {0}".format(id))
    except Exception, e:
        log.error(e, exc_info=True)

def flush():
    model.Session.commit()
    model.Session.remove()