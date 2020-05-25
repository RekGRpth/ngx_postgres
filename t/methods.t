# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 - 2 * 2);

$ENV{TEST_NGINX_POSTGRESQL_HOST} ||= 'postgres';
$ENV{TEST_NGINX_POSTGRESQL_PORT} ||= 5432;

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                         dbname=test user=test password=test;
    }
_EOC_

no_shuffle();
run_tests();

__DATA__

=== TEST 1: default query
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'default' as echo";
        postgres_output     plain;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"default"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{07}\x{00}\x{00}\x{00}".  # field len
#"default".       # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 2: method-specific query
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      LOCK GET UNLOCK "select 'GET' as echo";
        postgres_output     plain;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"GET"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{03}\x{00}\x{00}\x{00}".  # field len
#"GET".           # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 3: method-specific complex query (check 1)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
        postgres_output     plain;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"GET"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{03}\x{00}\x{00}\x{00}".  # field len
#"GET".           # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 4: method-specific complex query (check 2)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
        postgres_output     plain;
    }
--- request
LOCK /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"LOCK"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{04}\x{00}\x{00}\x{00}".  # field len
#"LOCK".          # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 5: method-specific complex query (using not allowed method)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
        postgres_output     plain;
    }
--- request
HEAD /postgres
--- error_code: 405
--- timeout: 10



=== TEST 6: method-specific query and default query (using defined method)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'default' as echo";
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
        postgres_output     plain;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"GET"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{03}\x{00}\x{00}\x{00}".  # field len
#"GET".           # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 7: method-specific query and default query (using other method)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'default' as echo";
        postgres_output     plain;
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
    }
--- request
POST /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"default"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{07}\x{00}\x{00}\x{00}".  # field len
#"default".       # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 8: inheritance
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    postgres_query      "select 'default' as echo";
    postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
    postgres_output     plain;

    location /postgres {
        postgres_pass       database;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"GET"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{03}\x{00}\x{00}\x{00}".  # field len
#"GET".           # field data
#"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 9: inheritance (mixed, don't inherit)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    postgres_query      "select 'default' as echo";

    location /postgres {
        postgres_pass       database;
        postgres_query      LOCK GET UNLOCK "select $request_method::text as echo";
    }
--- request
HEAD /postgres
--- error_code: 405
--- timeout: 10



=== TEST 10: HTTP PATCH request method
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      PATCH "select $request_method::text as echo";
        postgres_output     plain;
    }
--- request
PATCH /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"echo".
"\x{0a}".
"PATCH"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{01}\x{00}".  # col count
#"\x{00}\x{80}".  # std col type (unknown/str)
#"\x{c1}\x{02}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"echo".          # col name data
#"\x{01}".        # valid row flag
#"\x{05}\x{00}\x{00}\x{00}".  # field len
#"PATCH".         # field data
#"\x{00}"         # row list terminator
--- timeout: 10
--- skip_nginx: 3: < 0.8.41
