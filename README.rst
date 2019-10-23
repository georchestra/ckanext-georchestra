.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://travis-ci.org/georchestra/ckanext-georchestra.svg?branch=master
    :target: https://travis-ci.org/georchestra/ckanext-georchestra

.. image:: https://coveralls.io/repos/georchestra/ckanext-georchestra/badge.svg
  :target: https://coveralls.io/r/georchestra/ckanext-georchestra

.. image:: https://pypip.in/download/ckanext-georchestra/badge.svg
    :target: https://pypi.python.org/pypi//ckanext-georchestra/
    :alt: Downloads

.. image:: https://pypip.in/version/ckanext-georchestra/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-georchestra/
    :alt: Latest Version

.. image:: https://pypip.in/py_versions/ckanext-georchestra/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-georchestra/
    :alt: Supported Python versions

.. image:: https://pypip.in/status/ckanext-georchestra/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-georchestra/
    :alt: Development Status

.. image:: https://pypip.in/license/ckanext-georchestra/badge.svg
    :target: https://pypi.python.org/pypi/ckanext-georchestra/
    :alt: License

===================
ckanext-georchestra
===================

.. Put a description of your extension here:
   What does it do? What features does it have?
   Consider including some screenshots or embedding a video!

This ckan extension provides user, organization and user membership (in organizations) synchronization from
geOrchestra LDAP instance. User, organization and membership are managed in the geOrchestra console.

On user access, if the user profile needs to be updated, it is done on-the-fly : user profile sync, membership, and if
necessary the organization is created. In that case, the organization is really an empty shell (only the id is provided)
and the rest is set up on next full sync.

Full Synchronization is done running paster command::

   /usr/lib/ckan/default/bin/paster --plugin=ckanext-georchestra georchestra ldap_sync_all -c /etc/ckan/development.ini

This should be run on a regular basis, like in a cron task.

------------
Requirements
------------

- CKAN 2.8.2
- geOrchestra Security Proxy
- geOrchestra LDAP instance


------------
Installation
------------

.. Add any additional install steps to the list below.
   For example installing any non-Python dependencies or adding any required
   config settings.

To install ckanext-georchestra:

1. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

2. Install the ckanext-georchestra Python package into your virtual environment::

     pip install ckanext-georchestra

3. Add ``georchestra`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/production.ini``).

4. Configure the plugin (see Configuration below)

5. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload


------------------------
Development Installation
------------------------

To install ckanext-georchestra for development,
1. Install ckan from source as documented in `Installing from Source <https://docs.ckan.org/en/ckan-2.7.3/maintaining/installing/install-from-source.html>`_

2.activate your CKAN virtualenv and
do::

    git clone https://github.com/georchestra/ckanext-georchestra.git
    cd ckanext-georchestra
    python setup.py develop
    pip install -r dev-requirements.txt

3. Add ``georchestra`` to the ``ckan.plugins`` setting in your CKAN
   config file develpoment.ini

4. Set at least minimal configuration for the plugin in your develoment.ini file::

    ckanext.georchestra.ldap.uri = ldap://localhost:3899
    ckanext.georchestra.ldap.base_dn = dc=georchestra,dc=org
    ckanext.georchestra.ldap.orgs.rdn = ou=orgs
    ckanext.georchestra.ldap.roles.rdn = ou=roles
    ckanext.georchestra.ldap.users.rdn = ou=users
    ckanext.georchestra.ldap.admin.dn = cn=admin,dc=georchestra,dc=org
    ckanext.georchestra.ldap.admin.password = secret

5. run::

    gunicorn --timeout 120 --reload --paste development.ini

6. To fake the headers sent by the security proxy, your browser needs to provide the following headers::

    * sec-username = my_login
    * sec-roles = ROLE_CKAN_ADMIN
    * sec-org = psc
    * sec-orgname = PSC geOrchestra
    * sec-firstname = my_fisrtname
    * sec-lastname = my_lastname
    * sec-email = my_valid_email@provider.com

This can be done by using, for instance, the extension `modheader <https://chrome.google.com/webstore/detail/modheader/idgpnmonknjnojddfkpgkljpfnnfcklj?hl=en>`_

-----------------
Running the Tests
-----------------
Check you are configured to run tests. See
https://docs.ckan.org/en/2.8/contributing/test.html
Check ckan core tests run just fine.

To run the tests for the plugin, do::

    nosetests --nologcapture --with-pylons=test.ini

To run the tests and produce a coverage report, first make sure you have
coverage installed in your virtualenv (``pip install coverage``) then run::

    nosetests --nologcapture --with-pylons=test.ini --with-coverage --cover-package=ckanext.georchestra --cover-inclusive --cover-erase --cover-tests


---------------------------------------
Registering ckanext-georchestra on PyPI
---------------------------------------

ckanext-georchestra should be availabe on PyPI as
https://pypi.python.org/pypi/ckanext-georchestra. If that link doesn't work, then
you can register the project on PyPI for the first time by following these
steps:

1. Create a source distribution of the project::

     python setup.py sdist

2. Register the project::

     python setup.py register

3. Upload the source distribution to PyPI::

     python setup.py sdist upload

4. Tag the first release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.1 then do::

       git tag 0.0.1
       git push --tags


----------------------------------------------
Releasing a New Version of ckanext-georchestra
----------------------------------------------

ckanext-georchestra is availabe on PyPI as https://pypi.python.org/pypi/ckanext-georchestra.
To publish a new version to PyPI follow these steps:

1. Update the version number in the ``setup.py`` file.
   See `PEP 440 <http://legacy.python.org/dev/peps/pep-0440/#public-version-identifiers>`_
   for how to choose version numbers.

2. Create a source distribution of the new version::

     python setup.py sdist

3. Upload the source distribution to PyPI::

     python setup.py sdist upload

4. Tag the new release of the project on GitHub with the version number from
   the ``setup.py`` file. For example if the version number in ``setup.py`` is
   0.0.2 then do::

       git tag 0.0.2
       git push --tags

---------------------
Configuration options
---------------------
The plugin provides the **required** following required configuration items:

- `ckanext.georchestra.ldap.uri`: your LDAP server URI (e.g.`ldap://localhost:389`)
- `ckanext.georchestra.ldap.base_dn`: your LDAP base DN (e.g. `dc=georchestra,dc=org`)
- `ckanext.georchestra.ldap.orgs.rdn`: the relative DN associated to the organization objects (e.g. `ou=orgs`)
- `ckanext.georchestra.ldap.roles.rdn`: the relative DN associated to the organization objects (e.g. `ou=roles`)
- `ckanext.georchestra.ldap.users.rdn`: the relative DN associated to the organization objects (e.g. `ou=users`)
- `ckanext.georchestra.ldap.admin.dn`: the admin user dn (e.g.`cn=admin,dc=georchestra,dc=org`)
- `ckanext.georchestra.ldap.admin.password`: the admin user's password

Additionally, the plugin provides the following optional parameters:

- `ckanext.georchestra.ldap.users.nosync`: comma-separated list of users that we should not sync to CKAN (default: `geoserver_privileged_user`)
- `ckanext.georchestra.ldap.auth.method`: LDAP authentication method (default: `SIMPLE`)
- `ckanext.georchestra.ldap.auth.mechanism`: if `ckanext.georchestra.ldap.auth.method` is set to SASL, the authentication mechanism used (default: `DIGEST-MD5`)
- `ckanext.georchestra.ldap.trace_level`: LDAP logging level (default: 0)
- `ckanext.georchestra.role.prefix`: role prefix used in the header's roles list (default: `ROLE_`)
- `ckanext.georchestra.role.sysadmin`: CKAN sysadmin  role name as defined in geOrchestra's console (default: `CKAN_SYSADMIN`)
- `ckanext.georchestra.role.orgadmin`: CKAN admin role name as defined in geOrchestra's console (default: `CKAN_ADMIN`)
- `ckanext.georchestra.role.editor`: CKAN editor role name as defined in geOrchestra's console (default: `CKAN_EDITOR`)
- `ckanext.geOrchestra.external_users`: used to keep root sysadmin user out of the sync process (we don't want it removed...) (default: `ckan`)
- `ckanext.georchestra.orphans.users.purge`: If True, ckan users that don't belong to the LDAP base are purged from the database. If False, they are removed from all organizations and added to a orphan_users org (default `False`)
- `ckanext.georchestra.orphans.users.orgname`: orphan_users organization name (default: ` orphan_users`)
- `ckanext.georchestra.organization.ghosts.prefix`: Prefix added to the title of organizations that should be deleted but still contain datasets: they are referred as ghost, pending cleaning , for further deletion (default `[GHOST]`)


Setting configuration through environment variables
---------------------------------------------------
Some configuration options can be set using environment variables. The list is given in the plugin.py file :
```
CONFIG_FROM_ENV_VARS = {
    'ckanext.georchestra.ldap.uri': 'CKAN_LDAP_URL',
}
```
Variables set using environment variables override file-based ones.

---------------------
SP configuration
---------------------

From geOrchestra 19.06 on, CKAN requires that the SP **allowSemicolon** setting is switched to true in
https://github.com/georchestra/datadir/blob/e625656eaa47cb50a36c406dacd11f18d2217307/security-proxy/security-proxy.properties#L170-L172

Also, in the datadir's `security-proxy/security-mappings.xml`::

     <intercept-url pattern="/ckan/ckan-admin.*" access="ROLE_CKAN_SYSADMIN" />

