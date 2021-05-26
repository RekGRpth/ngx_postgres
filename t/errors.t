# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * blocks();

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

=== TEST 1: bad query
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "i'm bad";
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 2: wrong credentials
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config
    upstream database {
        postgres_server     host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                            dbname=ngx_test user=ngx_test password=wrong_pass sslmode=disable;
    }
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update cats set name='bob' where name='bob'";
    }
--- request
GET /postgres
--- error_code: 502
--- timeout: 10



=== TEST 3: no database
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config
    upstream database {
        postgres_server     host=$TEST_NGINX_POSTGRESQL_HOST port=1 dbname=ngx_test
                            user=ngx_test password=ngx_test sslmode=disable;
    }
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update cats set name='bob' where name='bob'";
    }
--- request
GET /postgres
--- error_code: 502
--- timeout: 10



=== TEST 4: multiple queries
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "select * from cats; select * from cats";
    }
--- request
GET /postgres
--- error_code: 200
--- timeout: 10



=== TEST 5: missing query
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 6: empty query
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        set $query          "";
        postgres_pass       database;
        postgres_query      $query;
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 7: empty pass
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        set $database       "";
        postgres_pass       $database;
        postgres_query      "update cats set name='bob' where name='bob'";
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10



=== TEST 8: non-existing table
--- main_config
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /postgres {
        postgres_pass       database;
        postgres_query      "update table_that_doesnt_exist set name='bob'";
    }
--- request
GET /postgres
--- error_code: 500
--- timeout: 10
