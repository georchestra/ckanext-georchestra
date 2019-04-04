# encoding: utf-8

from nose import tools as nosetools

import ckan.model as model
import ckan.tests.helpers as helpers
import ckan.plugins as plugins
from ckan.plugins.toolkit import NotAuthorized, ObjectNotFound
import ckan.tests.factories as factories
import ckanext.georchestra.utils.users as users


class TestCommandUserUtilsPlugin(object):
    '''Tests for the ckanext.georchestra.plugin module.

    '''

    @classmethod
    def setup_class(cls):
        '''Nose runs this method once to setup our test class.'''
        # Test code should use CKAN's plugins.load() function to load plugins
        # to be tested.
        plugins.load('georchestra')

    def teardown(self):
        '''Nose runs this method after each test method in our test class.'''
        # Rebuild CKAN's database after each test method, so that each test
        # method runs with a clean slate.
        model.repo.rebuild_db()

    @classmethod
    def teardown_class(cls):
        '''Nose runs this method once after all the test methods in our class
                have been run.

                '''
        # We have to unload the plugin we loaded, so it doesn't affect any
        # tests that run after ours.
        plugins.unload('georchestra')

    def test_user_delete_but_org_dont_exist(self):
        context = {'ignore_auth': True, 'user': 'ckan_default'}
        org_name = 'orphans'
        user = factories.User()
        users.delete(context, user['id'], False, org_name)
        org_object = plugins.toolkit.get_action('organization_show')(context.copy(), {'id': org_name, 'include_users':True})
        nosetools.assert_equal(len(org_object['users']), 1)

    def test_user_delete(self):
        context = {'ignore_auth': True, 'user': 'ckan_default'}
        org_name = 'orphans'
        user = factories.User()
        user2 = factories.User()
        org = factories.Organization(name=org_name, users=[{'name': user2['id'], 'capacity': 'member'}])
        users.delete(context, user['id'], False, org_name)
        org_object = plugins.toolkit.get_action('organization_show')(context.copy(), {'id': org['id'], 'include_users':True})
        usernames = [u['name'] for u in org_object['users']]
        nosetools.assert_in(user['name'], usernames)
