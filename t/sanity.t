# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5) - 2;

$ENV{TEST_NGINX_POSTGRESQL_HOST} ||= 'postgres';
$ENV{TEST_NGINX_POSTGRESQL_PORT} ||= 5432;

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                         dbname=test user=test password=test sslmode=disable;
        postgres_keepalive 10;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: sanity
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config
    upstream database {
        postgres_server     host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                            dbname=test user=test password=test sslmode=disable;
#        postgres_keepalive  off;
    }
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select * from cats";
        postgres_output     rds;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
--- response_body eval
"\x{00}".        # endian
"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
"\x{00}".        # result type
"\x{00}\x{00}".  # std errcode
"\x{02}\x{00}".  # driver errcode
"\x{00}\x{00}".  # driver errstr len
"".              # driver errstr data
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
"\x{02}\x{00}".  # col count
"\x{09}\x{00}".  # std col type (integer/int)
"\x{17}\x{00}".  # driver col type
"\x{02}\x{00}".  # col name len
"id".            # col name data
"\x{06}\x{80}".  # std col type (varchar/str)
"\x{19}\x{00}".  # driver col type
"\x{04}\x{00}".  # col name len
"name".          # col name data
"\x{01}".        # valid row flag
"\x{01}\x{00}\x{00}\x{00}".  # field len
"2".             # field data
"\x{ff}\x{ff}\x{ff}\x{ff}".  # field len
"".              # field data
"\x{01}".        # valid row flag
"\x{01}\x{00}\x{00}\x{00}".  # field len
"3".             # field data
"\x{03}\x{00}\x{00}\x{00}".  # field len
"bob".           # field data
"\x{00}"         # row list terminator
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 2: keep-alive
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select * from cats";
        postgres_output     rds;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
--- response_body eval
"\x{00}".        # endian
"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
"\x{00}".        # result type
"\x{00}\x{00}".  # std errcode
"\x{02}\x{00}".  # driver errcode
"\x{00}\x{00}".  # driver errstr len
"".              # driver errstr data
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
"\x{02}\x{00}".  # col count
"\x{09}\x{00}".  # std col type (integer/int)
"\x{17}\x{00}".  # driver col type
"\x{02}\x{00}".  # col name len
"id".            # col name data
"\x{06}\x{80}".  # std col type (varchar/str)
"\x{19}\x{00}".  # driver col type
"\x{04}\x{00}".  # col name len
"name".          # col name data
"\x{01}".        # valid row flag
"\x{01}\x{00}\x{00}\x{00}".  # field len
"2".             # field data
"\x{ff}\x{ff}\x{ff}\x{ff}".  # field len
"".              # field data
"\x{01}".        # valid row flag
"\x{01}\x{00}\x{00}\x{00}".  # field len
"3".             # field data
"\x{03}\x{00}\x{00}\x{00}".  # field len
"bob".           # field data
"\x{00}"         # row list terminator
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 3: update
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update cats set name='bob' where name='bob'";
        postgres_output     rds;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
--- response_body eval
"\x{00}".        # endian
"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
"\x{00}".        # result type
"\x{00}\x{00}".  # std errcode
"\x{01}\x{00}".  # driver errcode
"\x{00}\x{00}".  # driver errstr len
"".              # driver errstr data
"\x{01}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
"\x{00}\x{00}".   # col count
"\x{00}"         # row list terminator
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 4: select empty result
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select * from cats where name='tom'";
        postgres_output     rds;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
--- response_body eval
"\x{00}".        # endian
"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
"\x{00}".        # result type
"\x{00}\x{00}".  # std errcode
"\x{02}\x{00}".  # driver errcode
"\x{00}\x{00}".  # driver errstr len
"".              # driver errstr data
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
"\x{02}\x{00}".  # col count
"\x{09}\x{00}".  # std col type (integer/int)
"\x{17}\x{00}".  # driver col type
"\x{02}\x{00}".  # col name len
"id".            # col name data
"\x{06}\x{80}".  # std col type (varchar/str)
"\x{19}\x{00}".  # driver col type
"\x{04}\x{00}".  # col name len
"name".          # col name data
"\x{00}"         # row list terminator
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 5: variables in postgres_pass
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        set                 $backend  database;
        postgres_pass       $backend;
        postgres_query      "update cats set name='bob' where name='bob'";
        postgres_output     plain;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{01}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{01}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{00}\x{00}"   # col count
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 6: HEAD request
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select * from cats";
        postgres_output     plain;
    }
--- request
HEAD /postgres
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
""
--- timeout: 10
--- no_error_log
[alert]
[error]



=== TEST 7: "if" pseudo-location
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        if ($arg_foo) {
            postgres_pass       database;
            postgres_query      "select * from cats";
            postgres_output     plain;
            break;
        }

        return 404;
    }
--- request
GET /postgres?foo=1
--- error_code: 200
--- response_headers
Content-Type: text/plain; charset=utf-8
--- response_body eval
"id".
"\x{09}".
"name".
"\x{0a}".
"2".
"\x{09}".
"\\N".
"\x{0a}".
"3".
"\x{09}".
"bob"
#"\x{00}".        # endian
#"\x{03}\x{00}\x{00}\x{00}".  # format version 0.0.3
#"\x{00}".        # result type
#"\x{00}\x{00}".  # std errcode
#"\x{02}\x{00}".  # driver errcode
#"\x{00}\x{00}".  # driver errstr len
#"".              # driver errstr data
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # rows affected
#"\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}\x{00}".  # insert id
#"\x{02}\x{00}".  # col count
#"\x{09}\x{00}".  # std col type (integer/int)
#"\x{17}\x{00}".  # driver col type
#"\x{02}\x{00}".  # col name len
#"id".            # col name data
#"\x{06}\x{80}".  # std col type (varchar/str)
#"\x{19}\x{00}".  # driver col type
#"\x{04}\x{00}".  # col name len
#"name".          # col name data
#"\x{01}".        # valid row flag
#"\x{01}\x{00}\x{00}\x{00}".  # field len
#"2".             # field data
#"\x{ff}\x{ff}\x{ff}\x{ff}".  # field len
#"".              # field data
#"\x{01}".        # valid row flag
#"\x{01}\x{00}\x{00}\x{00}".  # field len
#"3".             # field data
#"\x{03}\x{00}\x{00}\x{00}".  # field len
#"bob".           # field data
#"\x{00}"         # row list terminator
--- timeout: 10
--- no_error_log
[alert]
[error]
