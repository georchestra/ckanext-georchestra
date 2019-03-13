import logging
import dateutil

from ckan.plugins import toolkit

log = logging.getLogger()


def preseed(context):
    """
    Clean the ckan instance
    create some common orgs, some deprecated ones and leave some uncreated
    :return:
    """
    create(context, {'id': 'fake', 'name': 'fake'})
    for org in ['psc', 'c2c', 'cra']:
        try:
            toolkit.get_action('organization_purge')(context, {'id': org})
            log.debug("purged organization {0}".format(org))
            org = toolkit.get_action('organization_show')(context, {'id': org})
            log.debug("organization {0} already exists".format(org))
        except toolkit.ObjectNotFound:
            # Means the organization was not found => we create it
            if org in ['c2c', 'psc']:
                create(context, {'id': org, 'name': org})
        except Exception as e:
            log.error(e, exc_info=True)

def update(context, orgs_list):
    for org in orgs_list:
        try:
            #current_org = toolkit.get_action('organization_show')(context, {'id': org['id'], 'include_extras':True})
            revisions = toolkit.get_action('organization_revision_list')(context, {'id': org['id']})
            # in order to be able to compare with LDAP timestamp, we need it to be seen as time-aware.
            # TODO: check it is really UTC time always
            #last_revision=dateutil.parser.parse(revisions[0]['timestamp']+'Z')
            last_revision = dateutil.parser.parse('20190208085726Z')
            if org['update_ts'] > last_revision:
                # then we update it
                log.debug("updating organization {0}".format(org['id']))
                current_org = toolkit.get_action('organization_patch')(context, org)
            log.debug("ok")
        except:
            log.error("Could not read organization {0} (should exist though".format(org))

def add(context, orgs_list):
    # trick to solve this SQLalchemy flushing issue. It seems 'group' info stays present in the self.session and
    # messes things up. Clearing the 'group' var seems to help.
    context['group'] = None
    for org in orgs_list:
        create(context,org)
        log.debug("added organization {0}".format(org['id']))

def remove(context, orgs_list):
    # TODO : check content and move all packages to a 'ghost' org before purging org
    for org in orgs_list:
        try:
            toolkit.get_action('organization_purge')(context, {'id': org})
            log.debug("purged organization {0}".format(org))
        except:
            log.error("could not purge organization {0}".format(org))


def create(context, data_dict):
    # Apply auth fix from https://github.com/datagovuk/ckanext-harvest/commit/f315f41c86cbde4a49ef869b6993598f8cb11e2d
    # to error message Action function organization_show did not call its auth function
    context.pop('__auth_audit', None)
    try:
        log.debug("creating organization {0}".format(data_dict['id']))
        toolkit.get_action('organization_create')(context, data_dict)
    except Exception as e:
        log.error(e, exc_info=True)


def delete(context, id):
    # TODO : resolve bug, see comment underneath
    """
    Don't use it. It generates an error from sqlalchemy :
    related attribute set' operation is not currently supported within the execution stage of the flush process
    already reported and closed (https://github.com/ckan/ckan/issues/2017). See if I can identify it or propose a
    reliable way to reproduce ut (seems pretty reliable right now : just run twice organization_delete then some
    organization_create and it all goes weird. For instance, my preseed function was like this :
    for org in ['psc', 'c2c', 'cra', 'fake']:
        self.organization_delete(org)

    self.organization_create("c2c", None))
    self.organization_create("fake", None)
    and it would not create c2c organization, after issuing the sqlalchemy error)
    """
    context.pop('__auth_audit', None)
    try:
        toolkit.get_action('organization_purge')(context, {'id': id})
        log.debug("purged organization {0}".format(id))
    except Exception as e:
        log.error(e, exc_info=True)
