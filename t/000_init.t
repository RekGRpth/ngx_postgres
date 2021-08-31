# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  dbname=test user=test password=test sslmode=disable;
    }
_EOC_

no_shuffle();
run_tests();

__DATA__

=== TEST 1: cats - drop table
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "DROP TABLE cats";
        error_page 500  = /ignore;
    }

    location /ignore { echo "ignore"; }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 2: cats - create table
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "CREATE TABLE cats (id integer, name text)";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 3: cats - insert value
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "INSERT INTO cats (id) VALUES (2)";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 4: cats - insert value
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "INSERT INTO cats (id, name) VALUES (3, 'bob')";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 5: numbers - drop table
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "DROP TABLE numbers";
        error_page 500  = /ignore;
    }

    location /ignore { echo "ignore"; }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 6: numbers - create table
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "CREATE TABLE numbers (number integer)";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 7: users - drop table
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "DROP TABLE users";
        error_page 500  = /ignore;
    }

    location /ignore { echo "ignore"; }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 8: users - create table
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "CREATE TABLE users (login text, pass text)";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]



=== TEST 9: users - insert value
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /init {
        postgres_pass   database;
        postgres_query  "INSERT INTO users (login, pass) VALUES ('ngx_test', 'ngx_test')";
    }
--- request
GET /init
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]
