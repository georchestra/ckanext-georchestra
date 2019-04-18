# encoding: utf-8
import six

import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.plugins.toolkit as t

render = base.render


class GeorchestraController(base.BaseController):

    def georchestra_logout(self):
        '''Override logout with geOrchestra's logout'''
        return h.redirect_to(u'/logout')

    def georchestra_login(self):
        '''Override login with geOrchestra's login pattern'''
        referrer = six.text_type(t.request.referrer, encoding='utf-8')
        url = referrer+u'&login' if '?' in referrer else referrer+u'?login'
        return h.redirect_to(url)

