# encoding: utf-8

from nose import tools as nosetools

import ckan.tests.helpers as helpers
import ckan.plugins as plugins


class TestGeorchestraPlugin(helpers.FunctionalTestBase):
    '''Tests for the ckanext.georchestra.plugin module.

    '''
    @classmethod
    def setup_class(cls):
        super(TestGeorchestra, cls).setup_class()
        plugins.load('georchestra')

    @classmethod
    def teardown_class(cls):
        plugins.unload('georchestra')
        super(TestGeorchestra, cls).teardown_class()

    def test_dummytest(self):
        nosetools.assert_true('a'+'a' == 'aa')

    def test_dummyfailedtest(self):
        nosetools.assert_equal('a'+'a','aa')
