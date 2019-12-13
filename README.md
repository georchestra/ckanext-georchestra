# ckanext-georchestra

This ckan extension provides user, organization and user membership (in organizations) synchronization from
geOrchestra LDAP instance. User, organization and membership are managed in the geOrchestra console.

On user access, if the user profile needs to be updated, it is done on-the-fly : user profile sync, membership, and if
necessary the organization is created. In that case, the organization is really an empty shell (only the id is provided)
and the rest is set up on next full sync.

Full Synchronization is done running paster command
```
/usr/lib/ckan/default/bin/paster --plugin=ckanext-georchestra georchestra ldap_sync_all -c /etc/ckan/development.ini
```

This should be run on a regular basis, like in a cron task.


## Requirements

- CKAN 2.8.x
- geOrchestra Security Proxy
- geOrchestra LDAP instance


## Configuration options

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


## Setting configuration through environment variables

Some configuration options can be set using environment variables. The list is given in the plugin.py file:
```
CONFIG_FROM_ENV_VARS = {
    'ckanext.georchestra.ldap.uri': 'CKAN_LDAP_URL',
}
```
Variables set using environment variables override file-based ones.


## Security Proxy configuration

Obviously, in `security-proxy/targets-mapping.properties`:
```
ckan=http://ckan:5000/
```

In the datadir's `security-proxy/security-mappings.xml`::
```
<intercept-url pattern="/ckan/ckan-admin.*" access="ROLE_CKAN_SYSADMIN" />
```

From geOrchestra 19.06 on, CKAN requires that the SP **allowSemicolon** setting is switched to true in
https://github.com/georchestra/datadir/blob/e625656eaa47cb50a36c406dacd11f18d2217307/security-proxy/security-proxy.properties#L170-L172


