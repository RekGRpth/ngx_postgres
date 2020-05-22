# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

$ENV{TEST_NGINX_POSTGRESQL_HOST} ||= 'postgres';
$ENV{TEST_NGINX_POSTGRESQL_PORT} ||= 5432;

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  host=$TEST_NGINX_POSTGRESQL_HOST port=$TEST_NGINX_POSTGRESQL_PORT
                         dbname=test user=test password=test;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: sanity
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_eval_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /eval {
        eval_subrequest_in_memory  off;

        eval $backend {
            postgres_pass    database;
            postgres_query   "select $scheme::text||'://127.0.0.1:'||$server_port::text||'/echo'";
            postgres_output  value;
        }

        proxy_pass $backend;
    }

    location /echo {
        echo -n  "it works!";
    }
--- request
GET /eval
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body chomp
it works!
--- timeout: 10
--- skip_nginx: 3: < 0.8.25



=== TEST 2: sanity (simple case)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_eval_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
    location /eval {
        eval_subrequest_in_memory  off;

        eval $echo {
            postgres_pass    database;
            postgres_query   "select 'test' as echo";
            postgres_output  value;
        }

        echo -n  $echo;
    }
--- request
GET /eval
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body chomp
test
--- timeout: 10
