# ckanext-georchestra

## Presentation

This ckan extension aims to integrate a CKAN instance into a geOrchestra deployment : it uses the geOrchestra LDAP 
for user and organization management, and leverages geOrchestra's Single Sign-On (CAS).

User and Organization are then managed by geOrchestra's console. You can set the following roles, matching the CKAN 
classic roles: CKAN_SYSDAMIN, CKAN_ADMIN, CKAN_EDITOR

It provides 
 * a `paster` command to synchronize the users and organizations from the geOrchestra LDAP
 * the internal mechanisms that perform the integration into geOrchestra
   * authentication mechanism, using the headers provided by the security proxy
   * a support to manage out-of-sync users
   * templates modifications, to disable actions that should not be done on the CKAN side (user & org edition)


## Requirements

- CKAN 2.8.x
- geOrchestra Security Proxy
- geOrchestra LDAP instance

| CKAN version | Compatibility |
| ------------- | ------------- |
| 2.8  | yes  |
| 2.9  | Not tested yet  |

## Installation
To install ckanext-georchestra:
1. Activate your CKAN virtual environment, for example:

    `. /usr/lib/ckan/default/bin/activate`

2. Install the ckanext-georchestra Python package into your virtual environment:

    `pip install ckanext-georchestra`

3. Install dependencies:

    `pip install -r https://raw.githubusercontent.com/georchestra/ckanext-georchestra/master/requirements.txt`

4. Add `georchestra` to the ckan.plugins setting in your CKAN config file (by default the config file is located at /etc/ckan/default/production.ini).

5. Set at least the required configuration settings in your CKAN config file (see Configuration below)

6. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu:

    `sudo service apache2 reload`

7. Synchronize the users and organization from the geOrchestra LDAP database:
    `(pyenv) $ paster --plugin=ckanext-georchestra georchestra ldap_sync_all -c  /etc/ckan/default/production.ini`
    
    Although this extensions can deal with desynchronized data, it is recommended you run regularly the synchronization,
    for instance using a cron task.


### Config settings

#### CKAN

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
- `ckanext.georchestra.orphans.users.purge`: If True, ckan users that don't belong to the LDAP base are purged from the database. If False, they are removed from all organizations and added to a orphan_users org (default `False`).
In production, it is advised to set purge to True so that people removed from the LDAP are properly removed from the CKAN database too.
- `ckanext.georchestra.orphans.users.orgname`: orphan_users organization name (default: `orphan_users`)
- `ckanext.georchestra.organization.ghosts.prefix`: Prefix added to the title of organizations that should be deleted but still contain datasets: they are referred as ghost, pending cleaning , for further deletion (default `[GHOST]`)


#### Setting configuration through environment variables

Some configuration options can be set using environment variables. The list is given in the plugin.py file:
```
CONFIG_FROM_ENV_VARS = {
    'ckanext.georchestra.ldap.uri': 'CKAN_LDAP_URL',
    'ckanext.georchestra.sync.force_update': 'CKAN_LDAP_SYNC_FORCE',
    'ckanext.georchestra.orphans.users.purge': 'CKAN_LDAP_SYNC_ORPHANS_PURGE',
}
```
Variables set using environment variables override file-based ones.

#### geOrchestra: Security Proxy configuration

Declare ckan in in `security-proxy/targets-mapping.properties`
```
ckan=http://ckan:5000/
```

And in the datadir's `security-proxy/security-mappings.xml`
```
<intercept-url pattern="/ckan/ckan-admin.*" access="ROLE_CKAN_SYSADMIN" />
```

From geOrchestra 19.04 on, CKAN requires that the SP **allowSemicolon** setting is switched to true in
https://github.com/georchestra/datadir/blob/e625656eaa47cb50a36c406dacd11f18d2217307/security-proxy/security-proxy.properties#L170-L172. This is to allow fanstatic URLs


### Developer installation

To install ckanext-georchestra for development, activate your CKAN virtualenv and in the directory up from your local ckan repo:

git clone https://github.com/georchestra/ckanext-georchestra.git
cd ckanext-georchestra
python setup.py develop
pip install -r requirements.txt
pip install -r dev-requirements.txt


## Running the synchronization

This extension provides user, organization and user membership (in organizations) synchronization from
geOrchestra LDAP instance. User, organization and membership are managed in the geOrchestra console.

On user access, if the user profile needs to be updated, it is done on-the-fly : user profile sync, membership, and if
necessary the organization is created. In that case, the organization is really an empty shell (only the id is provided)
and the rest is set up on next full sync.

Full Synchronization is done running paster command
```
`(pyenv) $ paster --plugin=ckanext-georchestra georchestra ldap_sync_all -c  /etc/ckan/default/production.ini`
```

This should be run on a regular basis, like in a cron task.

## Criteria of update

**Organizations** in CKAN provide a `organization_revision_list` action, that can give the time of last update. This is 
compared with the  `modifyTimestamp` (internal) attribute from the LDAP database to decide if the organization needs to 
be updated. 

**Users** do not provide such a service. In consequence, we compare a 
[list of fields](https://github.com/georchestra/ckanext-georchestra/blob/master/ckanext/georchestra/utils/users.py#L23)
to determine if the entry needs updating.

Normally, this should be enough. But in case it is not, you can force the update on every entry:
- by setting `ckanext.georchestra.sync.force_update` to `True` in the configuration `.ini` file
- by setting a `CKAN_LDAP_SYNC_FORCE=True` environment variable
- by adding `force_update` in the paster command, just after `ldap_sync_all`

Each one of those options overrides the previous ones.


## Running tests
Look at the [test.ini](https://github.com/georchestra/ckanext-georchestra/blob/master/test.ini) file, you might need to 
adjust it, as well as the imported `test-core.ini` file (you can get it in your ckan source code. Copy it somewhere, 
adjust the values to your case, update the path in your test.ini file)
Read also [Testing CKAN](https://docs.ckan.org/en/2.8/contributing/test.html). If you can't run the CKAN core tests, 
you probably won't be able to run this extension's tests.

Run the tests:
```
nosetests --ckan --with-pylons=test.ini ckanext/georchestra/tests
```

## Releasing a New Version of ckanext-georchestra

ckanext-georchestra is available on PyPI as https://pypi.org/project/ckanext-georchestra.

To publish a new version to PyPI follow these steps:

1. Update the version number in the setup.py file. See PEP 440 for how to choose version numbers.

2. Update the CHANGELOG.

3. Make sure you have the latest version of necessary packages:

    `pip install --upgrade setuptools wheel twine`

4. Create source and binary distributions of the new version:

    `python setup.py sdist bdist_wheel && twine check dist/*`

    Fix any errors you get.

5. Upload the source distribution to TestPyPI:

    `twine upload --repository testpypi dist/*`
    
6. Check it, test it before pushing to PypI: you can load the package using pip:

    `pip install --index-url https://test.pypi.org/simple/ ckanext-georchestra`
    
7. Upload the source distribution to PyPI:

    `twine upload dist/*`

8. Commit any outstanding changes:

    ```
    git commit -a
    git push
    ```

9. Tag the new release of the project on GitHub with the version number from the setup.py file. For example if the version number in setup.py is 0.0.1 then do:
    ```
    git tag 0.2.0
    git push --tags
    ```
