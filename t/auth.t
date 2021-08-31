# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 - 2 * 1);

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  dbname=postgres user=postgres password=postgres sslmode=disable;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: authorized (auth basic)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /auth {
        internal;
        postgres_pass       database;
        postgres_query      "select login from users where login=$remote_user::text and pass=$remote_passwd::text";
        postgres_rewrite    no_rows 403;
        postgres_set        $login 0 0 required;
        postgres_output     none;
    }

    location /test {
        auth_request        /auth;
        auth_request_set    $auth_user $login;
        echo -n             "hi, $auth_user!";
    }
--- more_headers
Authorization: Basic bmd4X3Rlc3Q6bmd4X3Rlc3Q=
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body chomp
hi, ngx_test!
--- timeout: 10



=== TEST 2: unauthorized (auth basic)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /auth {
        internal;
        postgres_pass       database;
        postgres_query      "select login from users where login=$remote_user::text and pass=$remote_passwd::text";
        postgres_rewrite    no_rows 403;
        postgres_set        $login 0 0 required;
        postgres_output     none;
    }

    location /test {
        auth_request        /auth;
        auth_request_set    $auth_user $login;
        echo -n             "hi, $auth_user!";
    }
--- more_headers
Authorization: Basic bW9udHk6c29tZV9wYXNz
--- request
GET /test
--- error_code: 403
--- response_headers
Content-Type: text/html
--- timeout: 10



=== TEST 3: unauthorized (no authorization header)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location = /auth {
        internal;
        postgres_pass       database;
        postgres_query      "select login from users where login=$remote_user::text and pass=$remote_passwd::text";
        postgres_rewrite    no_rows 403;
        postgres_set        $login 0 0 required;
        postgres_output     none;
    }

    location /test {
        auth_request        /auth;
        auth_request_set    $auth_user $login;
        echo -n             "hi, $auth_user!";
    }
--- request
GET /test
--- error_code: 403
--- response_headers
Content-Type: text/html
--- timeout: 10
