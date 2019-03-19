import ckan.plugins as plugins
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from hashlib import md5
import logging

HEADER_USERNAME = "sec-username"
HEADER_ROLES = "sec-roles"
HEADER_ORG = "sec-org"
HEADER_EMAIL = "sec-email"
HEADER_FIRSTNAME = "sec-firstname"
HEADER_LASTNAME = "sec-lastname"
HEADER_TEL = "sec-tel"


def auth_function_disabled(context, data_dict=None):
    # TODO : consider to return true in some "sysadmin" context. For instance to create organization
    return {
        'success': True,
        'msg': 'Authentication is disabled on CKAN and is handled by geOrchestra.'
    }


log = logging.getLogger(__name__)


class GeorchestraPlugin(plugins.SingletonPlugin):
    pass