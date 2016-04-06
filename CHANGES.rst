ChangeLog
=========

1.5.8 (unreleased)
------------------

- Nothing changed yet.


1.5.7 (2016-04-06)
------------------

* Update authorization expires_in [Pilar Marinas]
* Merge pull request #3 from pmarinas/patch-1 [Víctor Fernández de Alba]
*  [Víctor Fernández de Alba]
* Update authorization.py [Víctor Fernández de Alba]
* Update authorization.py [pmarinas]
*  [pmarinas]
* Solucionar error json datetime en token [pmarinas]

1.5.6 (2015-12-17)
------------------

* Fix empty username bug [Carles Bruguera]
* Fix query to check user existence [Carles Bruguera]
* Use all defined connectors [Carles Bruguera]

1.5.5 (2015-10-27)
------------------

* Accept json content-type requests [Carles Bruguera]
* Change ldap connection details [Carles Bruguera]
* By default normalize username to lowercase. [Victor Fernandez de Alba]

1.5.4 (2015-06-19)
------------------

* Don't issue token for unknown user on bypass [Carles Bruguera]
* Refactor authentication code with a facade OsirisConnector class [Carles Bruguera]

1.5.3 (2014-12-04)
------------------

* Prevent logging of requests within gevent [Carles Bruguera]

1.5.2 (2014-12-02)
------------------

* Fix legacy tween responseon invalid_grants [Carles Bruguera]

1.5.1 (2014-11-26)
------------------

* Enable authenticated mongodb login [Carles Bruguera]

1.5 (2014-11-25)
----------------

* Add bypassed token endpoint [Carles Bruguera]
* Add legacy support as a mock tween [Carles Bruguera]

1.4 (2014-05-26)
----------------

* Make Osiris support dual authentication (LDAP-based and WHO-based) with priority to the LDAP-based user repository. [Victor Fernandez de Alba]
* Add License [Victor Fernandez de Alba]
* Merge branch 'master' of github.com:sneridagh/osiris [Victor Fernandez de Alba]
* More tests, unify ldap config on .ini [Victor Fernandez de Alba]
* Unified extensions for README and CHANGES. Updated MANIFEST.in [Victor Fernandez de Alba]

1.3 (2013-08-02)
----------------

 * Added use of greenlets and handle reconnects if cluster is enabled [Victor Fernandez de Alba]
 * Support for mongoDB cluster [Victor Fernandez de Alba]

1.2 (2013-06-13)
------------------

- Update the deprecated method to connect to a MongoDB database.
- Added ability to connect to a MongoDB replica set.

1.1 (2013-06-04)
------------------

- Added a new way of parse LDAP settings to use with pyramid_ldap via a config
  file ldap.ini

1.0.1 (2013-06-04)
------------------

- Fix UnboundLocalError when LDAP plugin enabled

1.0 (2013-05-19)
----------------

- Improved test coverage (91% overall, 100% on implemented parts)
- Updated implementation to be standard with the final oAuth 2.0 spec.
- Polished scopes, error handling, return codes and error messaging
- Included support for pyramid_ldap plug-in, as it has a better implementation
  than the repoze.who one.
- Deprecate capped collections on mongodb_store


1.0 beta1 (2012-02-22)
----------------------

-  Initial version
