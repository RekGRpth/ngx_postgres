# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * (blocks() * 3);

$ENV{TEST_NGINX_POSTGRESQL_HOST} ||= 'postgres';
$ENV{TEST_NGINX_POSTGRESQL_PORT} ||= 5432;

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                         dbname=test user=test password=test sslmode=disable;
    }
_EOC_

our $config = <<'_EOC_';
    set $random  123;

    location = /auth {
        internal;

        postgres_pass       database;
        postgres_query      "SELECT login FROM users WHERE login=$remote_user::text AND pass=$remote_passwd::text";
        postgres_rewrite    no_rows 403;
        postgres_output     none;
    }

    location = /numbers/ {
        auth_request        /auth;
        postgres_pass       database;

        postgres_query      HEAD GET  "SELECT * FROM numbers";
        postgres_output     json;

        postgres_query      POST      "INSERT INTO numbers VALUES($random::int8) RETURNING *";
        postgres_output     json;
        postgres_rewrite    POST      changes 201;

        postgres_query      DELETE    "DELETE FROM numbers";
        postgres_output json;
        postgres_rewrite    DELETE    no_changes 204;
        postgres_rewrite    DELETE    changes 204;
    }

    location ~ /numbers/(?<number>\d+) {
        auth_request        /auth;
        postgres_pass       database;

        postgres_query      HEAD GET  "SELECT * FROM numbers WHERE number=$number::int8";
        postgres_output     json;
        postgres_rewrite    HEAD GET  no_rows 410;

        postgres_query      PUT       "UPDATE numbers SET number=$number::int8 WHERE number=$number::int8 RETURNING *";
        postgres_output     json;
        postgres_rewrite    PUT       no_changes 410;

        postgres_query      DELETE    "DELETE FROM numbers WHERE number=$number::int8";
        postgres_output     json;
        postgres_rewrite    DELETE    no_changes 410;
        postgres_rewrite    DELETE    changes 204;
    }
_EOC_

our $request_headers = <<'_EOC_';
Authorization: Basic bmd4X3Rlc3Q6bmd4X3Rlc3Q=
_EOC_

no_shuffle();
run_tests();

__DATA__

=== TEST 1: clean collection
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
DELETE /numbers/
--- error_code: 204
--- response_headers
! Content-Type
--- response_body eval
""
--- timeout: 10



=== TEST 2: list empty collection
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
GET /numbers/
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body chomp

--- timeout: 10



=== TEST 3: insert resource into collection
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
POST /numbers/
--- error_code: 201
--- response_headers
Content-Type: application/json
--- response_body chomp
{"number":123}
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 4: list collection
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
GET /numbers/
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body chomp
{"number":123}
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 5: get resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
GET /numbers/123
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body chomp
{"number":123}
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 6: update resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers
Authorization: Basic bmd4X3Rlc3Q6bmd4X3Rlc3Q=
Content-Length: 0
--- request
PUT /numbers/123
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body chomp
{"number":123}
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 7: remove resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
DELETE /numbers/123
--- error_code: 204
--- response_headers
! Content-Type
--- response_body eval
""
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 8: update non-existing resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers
Authorization: Basic bmd4X3Rlc3Q6bmd4X3Rlc3Q=
Content-Length: 0
--- request
PUT /numbers/123
--- error_code: 410
--- response_headers
Content-Type: text/html
--- response_body_like: 410 Gone
--- timeout: 10
--- skip_slave: 3: CentOS



=== TEST 9: get non-existing resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
GET /numbers/123
--- error_code: 410
--- response_headers
Content-Type: text/html
--- response_body_like: 410 Gone
--- timeout: 10



=== TEST 10: remove non-existing resource
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
DELETE /numbers/123
--- error_code: 410
--- response_headers
Content-Type: text/html
--- response_body_like: 410 Gone
--- timeout: 10



=== TEST 11: list empty collection (done)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config eval: $::config
--- more_headers eval: $::request_headers
--- request
GET /numbers/
--- error_code: 200
--- response_headers
Content-Type: application/json
--- response_body chomp

--- timeout: 10
