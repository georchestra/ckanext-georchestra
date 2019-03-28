.. You should enable this project on travis-ci.org and coveralls.io to make
   these badges work. The necessary Travis and Coverage config files have been
   generated for you.

.. image:: https://travis-ci.org/jahow/ckanext-georchestra.svg?branch=master
    :target: https://travis-ci.org/jahow/ckanext-georchestra

.. image:: https://coveralls.io/repos/jahow/ckanext-georchestra/badge.svg
  :target: https://coveralls.io/r/jahow/ckanext-georchestra

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
georchestra LDAP instance. User, organization and membership are managed in the georchestra console.

On user access, if the user profile needs to be updated, it is done on-the-fly : user profile sync, membership, and if
necessary the organization is created. In that case, the organization is really an empty shell (only the id is provided)
and the rest is set up on next full sync.

Full Synchronization is done running paster command::

   /usr/lib/ckan/default/bin/paster --plugin=ckanext-georchestra georchestra ldap_sync_all -c  ~/docker-ckan/ckan/root/etc/ckan/development.ini

This should be run on a regular basis, like in a cron task.

------------
Requirements
------------

- CKAN 2.8.2
- geOrchestra Security Proxy
- Georchestra LDAP instance


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
    ckanext.georchestra.ldap.base_dn.orgs = ou=orgs,dc=georchestra,dc=org
    ckanext.georchestra.ldap.base_dn.roles = ou=roles,dc=georchestra,dc=org
    ckanext.georchestra.ldap.base_dn.users = ou=users,dc=georchestra,dc=org
    ckanext.georchestra.ldap.auth.dn = cn=admin,dc=georchestra,dc=org
    ckanext.georchestra.ldap.auth.password = secret

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
