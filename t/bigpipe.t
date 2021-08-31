# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2);

our $http_config = <<'_EOC_';
    upstream database {
        postgres_server  dbname=postgres user=postgres password=postgres sslmode=disable;
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: synchronous
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
        location /bigpipe {
            echo                 "<html>(...template with javascript and divs...)";
            echo -n              "<script type=\"text/javascript\">loader.load(";
            echo_location        /_query1;
            echo                 ")</script>";
            echo -n              "<script type=\"text/javascript\">loader.load(";
            echo_location        /_query2;
            echo                 ")</script>";
            echo                 "</html>";
        }

        location /_query1 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id ASC";
            postgres_output      json;
        }

        location /_query2 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id DESC";
            postgres_output      json;
        }
--- request
GET /bigpipe
--- error_code: 200
--- response_body
<html>(...template with javascript and divs...)
<script type="text/javascript">loader.load([{"id":2,"name":null},{"id":3,"name":"bob"}])</script>
<script type="text/javascript">loader.load([{"id":3,"name":"bob"},{"id":2,"name":null}])</script>
</html>
--- timeout: 10
--- skip_nginx: 2: < 0.7.46



=== TEST 2: asynchronous (without echo filter)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
        location /bigpipe {
            echo                 "<html>(...template with javascript and divs...)";
            echo -n              "<script type=\"text/javascript\">loader.load(";
            echo_location_async  /_query1;
            echo                 ")</script>";
            echo -n              "<script type=\"text/javascript\">loader.load(";
            echo_location_async  /_query2;
            echo                 ")</script>";
            echo                 "</html>";
        }

        location /_query1 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id ASC";
            postgres_output      json;
        }

        location /_query2 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id DESC";
            postgres_output      json;
        }
--- request
GET /bigpipe
--- error_code: 200
--- response_body
<html>(...template with javascript and divs...)
<script type="text/javascript">loader.load([{"id":2,"name":null},{"id":3,"name":"bob"}])</script>
<script type="text/javascript">loader.load([{"id":3,"name":"bob"},{"id":2,"name":null}])</script>
</html>
--- timeout: 10
--- skip_nginx: 2: < 0.7.46



=== TEST 3: asynchronous (with echo filter)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_postgres_module.so;
--- http_config eval: $::http_config
--- config
        location /bigpipe {
            echo_before_body     "<html>(...template with javascript and divs...)";
            echo_before_body -n  "<script type=\"text/javascript\">loader.load(";
            echo -n              " "; # XXX we need this to help our echo filters
            echo_location_async  /_query1;
            echo                 ")</script>";
            echo -n              "<script type=\"text/javascript\">loader.load(";
            echo_location_async  /_query2;
            echo_after_body      ")</script>";
            echo_after_body      "</html>";
        }

        location /_query1 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id ASC";
            postgres_output      json;
        }

        location /_query2 {
            internal;
            postgres_pass        database;
            postgres_query       "SELECT * FROM cats ORDER BY id DESC";
            postgres_output      json;
        }
--- request
GET /bigpipe
--- error_code: 200
--- response_body
<html>(...template with javascript and divs...)
<script type="text/javascript">loader.load( [{"id":2,"name":null},{"id":3,"name":"bob"}])</script>
<script type="text/javascript">loader.load([{"id":3,"name":"bob"},{"id":2,"name":null}])</script>
</html>
--- timeout: 10
--- skip_nginx: 2: < 0.7.46
