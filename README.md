deprecated, use https://github.com/RekGRpth/ngx_pq_module instead

About
=====
`ngx_postgres` is an upstream module that allows `nginx` to communicate directly with `PostgreSQL` database.


Configuration directives
========================
postgres_server
---------------
* **syntax**: `postgres_server connection_string`
* **default**: `none`
* **context**: `upstream`

Set user-specified string to obtain connection parameters. There are two accepted formats for these strings: plain keyword/value strings and URIs.

In the keyword/value format, each parameter setting is in the form `keyword=value`, with space(s) between settings.

The general form for a connection URI is:

`postgresql://[userspec@][hostspec][/dbname][?paramspec]`

where `userspec` is: `user[:password]`

and `hostspec` is: `[host][:port][,...]`

and `paramspec` is: `name=value[&...]`

The URI scheme designator can be either `postgresql://` or `postgres://`. Each of the remaining URI parts is optional.


postgres_keepalive
------------------
* **syntax**: `postgres_keepalive count [overflow=ignore|reject] [timeout=1h] [requests=1000]`
* **default**: `none`
* **context**: `upstream`

Configure keepalive parameters:

- `count`      - maximum number of keepalive connections (per worker process),
- `overflow`   - either `ignore` the fact that keepalive connection pool is full and allow request, but close connection afterwards or `reject` request with `503 Service Unavailable` response,
- `timeout`    - sets a timeout during which an idle keepalive connection to an upstream server will stay open,
- `requests`   - sets the maximum number of requests that can be served through one keepalive connection. After the maximum number of requests is made, the connection is closed. Closing connections periodically is necessary to free per-connection memory allocations. Therefore, using too high maximum number of requests could result in excessive memory usage and not recommended.


postgres_queue
------------------
* **syntax**: `postgres_queue count [overflow=ignore|reject] [timeout=60s]`
* **default**: `none`
* **context**: `upstream`

Configure queue parameters:

- `count`      - maximum number of queue requests (per connection),
- `overflow`   - either `ignore` the fact that queue request pool is full and allow request or `reject` request with `503 Service Unavailable` response,
- `timeout`    - sets a timeout during which a request to an upstream server will be in queue.


postgres_pass
-------------
* **syntax**: `postgres_pass upstream|connection_string`
* **default**: `none`
* **context**: `location`, `if location`

Set name of an upstream block that will be used for the database connections (it can include variables) or set connection_string as abow if not used explicit upstream.


postgres_query
--------------
* **syntax**: `postgres_query [methods] query`
* **default**: `none`
* **context**: `http`, `server`, `location`, `if location`

Set query string (it can include variables, but after them ::type must be specified). When methods are specified then query is used only for them, otherwise it's used for all methods.

This directive can be used more than once within same context.


postgres_rewrite
----------------
* **syntax**: `postgres_rewrite [methods] condition [=]status_code`
* **default**: `none`
* **context**: `http`, `server`, `location`, `if location`

Rewrite response `status_code` when given condition is met (first one wins!):

- `no_changes` - no rows were affected by the query,
- `changes`    - at least one row was affected by the query,
- `no_rows`    - no rows were returned in the result-set,
- `rows`       - at least one row was returned in the result-set.

When `status_code` is prefixed with `=` sign then original response body is send to the client instead of the default error page for given `status_code`.

By design both `no_changes` and `changes` apply only to `INSERT`, `UPDATE`, `DELETE`, `MOVE`, `FETCH` and `COPY` SQL queries.

This directive can be used more than once within same context.


postgres_output
---------------
* **syntax**: `postgres_output json|text|csv|value|binary|none`
* **default**: `none`
* **context**: `http`, `server`, `location`, `if location`

Set output format:

- `json`         - return all values from the result-set in `json` format (with appropriate `Content-Type`),
- `text`         - return all values from the result-set in `text` format (with appropriate `Content-Type`), values are separated by new line,
- `csv`          - return all values from the result-set in `csv` format (with appropriate `Content-Type`), values are separated by new line,
- `value`        - return single value from the result-set in `text` format (with default `Content-Type`),
- `binary`       - return single value from the result-set in `binary` format (with default `Content-Type`),
- `none`         - don't return anything, this should be used only when extracting values with `postgres_set` for use with other modules (without `Content-Type`).


postgres_set
------------
* **syntax**: `postgres_set $variable row column [optional|required]`
* **default**: `none`
* **context**: `http`, `server`, `location`

Get single value from the result-set and keep it in $variable.

When requirement level is set to `required` and value is either out-of-range, `NULL` or zero-length, then nginx returns `500 Internal Server Error` response.
Such condition is silently ignored when requirement level is set to `optional` (default).

Row and column numbers start at 0. Column name can be used instead of column number.

This directive can be used more than once within same context.


postgres_timeout
-----------------------
* **syntax**: `postgres_timeout timeout`
* **default**: `60s`
* **context**: `http`, `server`, `location`

Set timeout for receiving result from the database.


Build-in variables
=======================
$postgres_nfields
-----------------
Number of columns in received result-set.


$postgres_ntuples
--------------
Number of rows in received result-set.


$postgres_cmdtuples
------------------
Number of rows affected by `INSERT`, `UPDATE`, `DELETE`, `MOVE`, `FETCH` or `COPY` SQL query.


$postgres_cmdstatus
------------------
Status of SQL query.


$postgres_query
---------------
SQL query, as seen by `PostgreSQL` database.


$postgres_error
---------------
SQL error, as seen by `PostgreSQL` database.


Sample configurations
=====================
Sample configuration #1
-----------------------
Return content of table `cats` (in `plain` format).

    http {
        upstream database {
            postgres_server host=127.0.0.1 dbname=test user=test password=test;
        }
        server {
            location / {
                postgres_pass database;
                postgres_query "SELECT * FROM cats";
                postgres_output plain;
            }
        }
    }


Sample configuration #2
-----------------------
Return only those rows from table `sites` that match `host` filter which is evaluated for each request based on its `$http_host` variable.

    http {
        upstream database {
            postgres_server host=127.0.0.1 dbname=test user=test password=test;
        }
        server {
            location / {
                postgres_pass database;
                postgres_query "SELECT * FROM sites WHERE host=$http_host::text";
                postgres_output plain;
            }
        }
    }


Sample configuration #3
-----------------------
Pass request to the backend selected from the database (traffic router).

    http {
        upstream database {
            postgres_server host=127.0.0.1 dbname=test user=test password=test;
        }
        server {
            location / {
                eval_subrequest_in_memory off;
                eval $backend {
                    postgres_pass database;
                    postgres_query "SELECT * FROM backends LIMIT 1";
                    postgres_output value 0 0;
                }
                proxy_pass $backend;
            }
        }
    }

Required modules (other than `ngx_postgres`):

- [nginx-eval-module (agentzh's fork)](http://github.com/agentzh/nginx-eval-module).


Sample configuration #4
-----------------------
Restrict access to local files by authenticating against `PostgreSQL` database.

    http {
        upstream database {
            postgres_server host=127.0.0.1 dbname=test user=test password=test;
        }
        server {
            location = /auth {
                internal;
                postgres_pass database;
                postgres_query "SELECT login FROM users WHERE login=$remote_user::text AND pass=$remote_passwd::text";
                postgres_rewrite no_rows 403;
                postgres_output none;
            }
            location / {
                auth_request /auth;
                root /files;
            }
        }
    }

Required modules (other than `ngx_postgres`):

- [ngx_http_auth_request_module](http://mdounin.ru/hg/ngx_http_auth_request_module/)
- [ngx_coolkit](http://github.com/FRiCKLE/ngx_coolkit).


Sample configuration #5
-----------------------
Simple RESTful webservice returning JSON responses with appropriate HTTP status codes.

    http {
        upstream database {
            postgres_server host=127.0.0.1 dbname=test user=test password=test;
        }
        server {
            set $random 123;
            location = /numbers/ {
                postgres_pass database;
                postgres_query HEAD GET "SELECT * FROM numbers";
                postgres_query POST "INSERT INTO numbers VALUES($random::integer) RETURNING *";
                postgres_rewrite POST changes 201;
                postgres_query DELETE "DELETE FROM numbers";
                postgres_rewrite DELETE no_changes 204;
                postgres_rewrite DELETE changes 204;
            }

            location ~/numbers/(?<num>\d+) {
                postgres_pass database;
                postgres_query HEAD GET "SELECT * FROM numbers WHERE number=$num::integer";
                postgres_rewrite HEAD GET no_rows 410;
                postgres_query PUT "UPDATE numbers SET number=$num::integer WHERE number=$num::integer RETURNING *";
                postgres_rewrite PUT no_changes 410;
                postgres_query DELETE "DELETE FROM numbers WHERE number=$num::integer";
                postgres_rewrite DELETE no_changes 410;
                postgres_rewrite DELETE changes 204;
            }
        }
    }

Required modules (other than `ngx_postgres`):

- [ngx_rds_json](http://github.com/agentzh/rds-json-nginx-module).

Sample configuration #6
-----------------------
Use GET parameter in SQL query.

    location /quotes {
        set_unescape_uri $txt $arg_txt;
        postgres_pass database;
        postgres_query "SELECT * FROM quotes WHERE quote=$txt::text";
    }

Required modules (other than `ngx_postgres`):

- [ngx_set_misc](http://github.com/agentzh/set-misc-nginx-module).

Testing
=======
`ngx_postgres` comes with complete test suite based on [Test::Nginx](http://github.com/agentzh/test-nginx).

You can test core functionality by running:

`$ TEST_NGINX_IGNORE_MISSING_DIRECTIVES=1 prove`

You can also test interoperability with following modules:

- [ngx_coolkit](http://github.com/FRiCKLE/ngx_coolkit),
- [ngx_echo](github.com/agentzh/echo-nginx-module),
- [ngx_form_input](http://github.com/calio/form-input-nginx-module),
- [ngx_set_misc](http://github.com/agentzh/set-misc-nginx-module),
- [ngx_http_auth_request_module](http://mdounin.ru/hg/ngx_http_auth_request_module/),
- [nginx-eval-module (agentzh's fork)](http://github.com/agentzh/nginx-eval-module),
- [ngx_rds_json](http://github.com/agentzh/rds-json-nginx-module).

by running:

`$ prove`
