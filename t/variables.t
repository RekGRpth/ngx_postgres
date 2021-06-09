# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 1 * 4 + 1 * 1 - 5 * 2);

$ENV{TEST_NGINX_POSTGRESQL_HOST} ||= 'postgres';
$ENV{TEST_NGINX_POSTGRESQL_PORT} ||= 5432;

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                         dbname=test user=test password=test sslmode=disable;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: sanity
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 0;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Test: test
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
"\x{01}\x{00}".  # col count
"\x{06}\x{80}".  # std col type (text/str)
"\x{19}\x{00}".  # driver col type
"\x{04}\x{00}".  # col name len
"echo".          # col name data
"\x{01}".        # valid row flag
"\x{04}\x{00}\x{00}\x{00}".  # field len
"test".          # field data
"\x{00}"         # row list terminator
--- timeout: 10



=== TEST 2: out-of-range value (optional)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 1;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Test
--- timeout: 10



=== TEST 3: NULL value (optional)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select NULL as echo";
        postgres_output     rds;
        postgres_set        $test 0 0;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Test
--- timeout: 10



=== TEST 4: zero-length value (optional)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select '' as echo";
        postgres_output     rds;
        postgres_set        $test 0 0;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Test
--- timeout: 10



=== TEST 5: out-of-range value (required)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 1 required;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 6: NULL value (required)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select NULL as echo";
        postgres_output     rds;
        postgres_set        $test 0 0 required;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 7: zero-length value (required)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select '' as echo";
        postgres_output     rds;
        postgres_set        $test 0 0 required;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 8: $postgres_nfields
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'a', 'b', 'c'";
        postgres_output     rds;
        add_header          "X-Columns" $postgres_nfields;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Columns: 3
--- timeout: 10



=== TEST 9: $postgres_ntuples
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'a', 'b', 'c'";
        postgres_output     rds;
        add_header          "X-Rows" $postgres_ntuples;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Rows: 1
--- timeout: 10



=== TEST 10: $postgres_query (simple value)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        add_header          "X-Query" $postgres_query;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Query: select 'test' as echo
--- timeout: 10



=== TEST 11: $postgres_query (simple value)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select $request_method::text as echo";
        postgres_output     rds;
        add_header          "X-Query" $postgres_query;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Query: select $1 as echo
--- timeout: 10



=== TEST 12: variables used in non-ngx_postgres location
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config
--- config
    location /etc {
        root                /;
        add_header          "X-Columns" $postgres_nfields;
        add_header          "X-Rows" $postgres_ntuples;
        add_header          "X-Affected" $postgres_cmdtuples;
        add_header          "X-Query" $postgres_query;
#        postgres_set        $pg 0 0 required;
#        add_header          "X-Custom" $pg;
    }
--- request
GET /etc/passwd
--- error_code: 200
--- response_headers
Content-Type: text/plain
! X-Columns
! X-Rows
! X-Affected
! X-Query
! X-Custom
--- timeout: 10



=== TEST 13: $postgres_cmdtuples (SELECT)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select $request_method::text as echo";
        postgres_output     rds;
        add_header          "X-Affected" $postgres_cmdtuples;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Affected
--- timeout: 10



=== TEST 14: $postgres_cmdtuples (UPDATE, no changes)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update cats set id=3 where name='noone'";
        postgres_output     rds;
        add_header          "X-Affected" $postgres_cmdtuples;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Affected: 0
--- timeout: 10



=== TEST 15: $postgres_cmdtuples (UPDATE, one change)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update cats set id=3 where name='bob'";
        postgres_output     rds;
        add_header          "X-Affected" $postgres_cmdtuples;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Affected: 1
--- timeout: 10



=== TEST 16: inheritance
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
#    postgres_set  $test 0 0 required;

    location /postgres {
        postgres_pass       database;
        postgres_query      "select NULL as echo";
        postgres_output     rds;
    postgres_set  $test 0 0 required;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 17: inheritance (mixed, don't inherit)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
#    postgres_set  $test 0 0 required;

    location /postgres {
        postgres_pass       database;
        postgres_query      "select NULL as echo";
        postgres_output     rds;
        postgres_set        $test2 2 2;
        add_header          "X-Test" $test2;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Test
--- timeout: 10



=== TEST 18: column by name (existing)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 "echo";
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
X-Test: test
--- timeout: 10



=== TEST 19: column by name (not existing, optional)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 "test" optional;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 200
--- response_headers
Content-Type: application/x-resty-dbd-stream; charset=utf-8
! X-Test
--- timeout: 10



=== TEST 20: column by name (not existing, required)
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select 'test' as echo";
        postgres_output     rds;
        postgres_set        $test 0 "test" required;
        add_header          "X-Test" $test;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10
