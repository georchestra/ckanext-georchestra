# encoding: utf-8
import urlparse
import urllib

from ckan.lib import base, helpers
from ckan.plugins import toolkit

render = base.render

class GeorchestraController(base.BaseController):
    '''
    Define custom controllers for login/logout using geOrchestra
    '''

    def georchestra_logout(self):
        '''Override logout with geOrchestra's logout'''
        return helpers.redirect_to(u'/logout')

    def georchestra_login(self):
        '''Override login with geOrchestra's login pattern
        Adds login=true to the current URL
        '''
        parsed = urlparse.urlsplit(toolkit.request.referer)
        query = urlparse.parse_qs(parsed.query)
        query['login'] = [u'true']
        parsed = parsed._replace(query=urllib.urlencode(query, True))
        url = urlparse.urlunsplit(parsed)
        return helpers.redirect_to(url)

