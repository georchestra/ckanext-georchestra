# encoding: utf-8

'''Tests for the ckanext.example_iauthfunctions extension.

'''

import unittest



class TestGeorchestraHeaders(unittest.TestCase):
    '''UnitTests for the ckanext.georchestra.plugin module.
    Verify that the headers from Security Proxy are properly retrieved and converted for CKAN
    Check for possible encoding issues with the headers come here too
    '''
    def setUp(self):
        pass

    def test_sec_headers_are_lowercased(self):
        '''
        Case is not guaranteed by security proxy => all header keys should be lowercased
        '''
        headers = {
            'Sec-Orgname': 'Région Hauts-de-France',
            'Sec-Roles': 'ROLE_GT_CHEMINS;ROLE_GN_ADMIN;ROLE_EXTRACTORAPP;ROLE_GN_EDITOR;ROLE_CKAN_EDITOR',
            'Sec-Firstname': 'François',
            'Sec-Email': 'fpomfont@pomfont.fr',
            'Sec-Tel': '03 74 00 00 00',
            'Sec-Username': 'fpomfont',
            'Sec-Lastname': 'Pomfont',
            'Sec-Org': 'region_hdf',
        }
        from ckanext.georchestra.plugin import _get_lowercased_sec_headers
        sec_headers = _get_lowercased_sec_headers(headers)
        expected_headers = {
            'sec-roles': 'ROLE_GT_CHEMINS;ROLE_GN_ADMIN;ROLE_EXTRACTORAPP;ROLE_GN_EDITOR;ROLE_CKAN_EDITOR',
            'sec-firstname': 'François',
            'sec-email': 'fpomfont@pomfont.fr',
            'sec-tel': '03 74 00 00 00',
            'sec-username': 'fpomfont',
            'sec-lastname': 'Pomfont',
            'sec-org': 'region_hdf',
        }
        self.assertDictEqual(sec_headers, expected_headers)

    def test_sec_headers_unicode_produce_valid_userdict(self):
        '''Headers should be unicode
        '''
        sec_headers = {
            'sec-roles': u'ROLE_GT_CHEMINS;ROLE_GN_ADMIN;ROLE_EXTRACTORAPP;ROLE_GN_EDITOR;ROLE_CKAN_EDITOR',
            'sec-firstname': u'François',
            'sec-email': u'fpomfont@pomfont.fr',
            'sec-tel': u'03 74 00 00 00',
            'sec-username': u'fpomfont',
            'sec-lastname': u'Pomfont',
            'sec-org': u'region_hdf',
        }
        from ckanext.georchestra.plugin import _user_dict_from_sec_headers
        user_dict = _user_dict_from_sec_headers(sec_headers)
        expected_dict = {
            'sysadmin': False,
            'state': u'active',
            'role': u'editor',
            'name': u'fpomfont',
            'fullname': u'François Pomfont',
            'password': u'12345678',
            'org_id': u'region_hdf',
            'id': u'fpomfont',
            'email': u'fpomfont@pomfont.fr'
        }
        self.assertDictEqual(user_dict, expected_dict)

    def test_no_ckan_role_in_sec_headers_end_as_member_role(self):
        '''Headers should be unicode
        '''
        sec_headers = {
            'sec-roles': u'ROLE_GT_CHEMINS;ROLE_GN_ADMIN;ROLE_EXTRACTORAPP;ROLE_GN_EDITOR',
            'sec-firstname': u'François',
            'sec-email': u'fpomfont@pomfont.fr',
            'sec-tel': u'03 74 00 00 00',
            'sec-username': u'fpomfont',
            'sec-lastname': u'Pomfont',
            'sec-org': u'region_hdf',
        }
        from ckanext.georchestra.plugin import _user_dict_from_sec_headers
        user_dict = _user_dict_from_sec_headers(sec_headers)
        expected_dict = {
            'sysadmin': False,
            'state': u'active',
            'role': u'member',
            'name': u'fpomfont',
            'fullname': u'François Pomfont',
            'password': u'12345678',
            'org_id': u'region_hdf',
            'id': u'fpomfont',
            'email': u'fpomfont@pomfont.fr'
        }
        self.assertDictEqual(user_dict, expected_dict)

    def test_sec_headers_latin1_produce_valid_userdict(self):
        '''It seems sometimes Pylons might return headers as latin1-encoded byte-strings
        '''
        sec_headers = {
            'sec-roles': b'ROLE_GT_CHEMINS;ROLE_GN_ADMIN;ROLE_EXTRACTORAPP;ROLE_GN_EDITOR;ROLE_CKAN_EDITOR',
            'sec-firstname': b'Fran\xe7ois',
            'sec-email': b'fpomfont@pomfont.fr',
            'sec-username': b'fpomfont',
            'sec-lastname': b'B\xf6rg',
            'sec-org': b'region_hdf',
        }
        from ckanext.georchestra.plugin import _user_dict_from_sec_headers
        user_dict = _user_dict_from_sec_headers(sec_headers)
        expected_dict = {
            'sysadmin': False,
            'state': u'active',
            'role': u'editor',
            'name': u'fpomfont',
            'fullname': u'François Börg',
            'password': u'12345678',
            'org_id': u'region_hdf',
            'id': u'fpomfont',
            'email': u'fpomfont@pomfont.fr'
        }
        self.assertDictEqual(user_dict, expected_dict)

    def test_sec_headers_group_and_username_are_sanitized(self):
        '''Username and id should be expunged of potentially complicated characters.
        '''
        sec_headers = {
            'sec-username': u'fPomfont',
            'sec-org': u'région hdf',
        }
        from ckanext.georchestra.plugin import _user_dict_from_sec_headers
        user_dict = _user_dict_from_sec_headers(sec_headers)
        assert user_dict['id'] == u'fpomfont' and user_dict['org_id'] == u'r_gion_hdf'


if __name__ == '__main__':
        unittest.main()

