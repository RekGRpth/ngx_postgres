# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

run_tests();

__DATA__

=== TEST 1: '
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "he'llo";
        set_quote_sql_str   $escaped $test;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'he\'llo'
--- timeout: 10



=== TEST 2: \
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "he\\llo";
        set_quote_sql_str   $escaped $test;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'he\\llo'
--- timeout: 10



=== TEST 3: \'
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "he\\'llo";
        set_quote_sql_str   $escaped $test;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'he\\\'llo'
--- timeout: 10



=== TEST 4: NULL
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set_quote_sql_str   $escaped $remote_user;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
''
--- timeout: 10



=== TEST 5: empty string
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set $empty          "";
        set_quote_sql_str   $escaped $empty;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
''
--- timeout: 10



=== TEST 6: UTF-8
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set $utf8           "你好";
        set_quote_sql_str   $escaped $utf8;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'你好'
--- timeout: 10



=== TEST 7: user arg
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set_quote_sql_str   $escaped $arg_say;
        echo                $escaped;
    }
--- request
GET /test?say=he'llo!
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'he\'llo!'
--- timeout: 10



=== TEST 8: NULL (empty)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set_quote_sql_str   $escaped =$remote_user;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'='
--- timeout: 10



=== TEST 9: empty string (empty)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set $empty          "";
        set_quote_sql_str   $escaped =$empty;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'='
--- timeout: 10



=== TEST 10: in-place escape
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "t'\\est";
        set_quote_sql_str   $test;
        echo                $test;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
't\'\\est'
--- timeout: 10



=== TEST 11: re-useable variable name (test1)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test1 {
        set                 $a "a";
        set_quote_sql_str   $escaped $a;
        echo                $escaped;
    }
    location /test2 {
        set                 $b "b";
        set_quote_sql_str   $escaped $b;
        echo                $escaped;
    }
--- request
GET /test1
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'a'
--- timeout: 10



=== TEST 12: re-useable variable name (test2)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test1 {
        set                 $a "a";
        set_quote_sql_str   $escaped $a;
        echo                $escaped;
    }
    location /test2 {
        set                 $b "b";
        set_quote_sql_str   $escaped $b;
        echo                $escaped;
    }
--- request
GET /test2
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'b'
--- timeout: 10



=== TEST 13: concatenate multiple sources
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "t'\\est";
        set                 $hello " he'llo";
        set_quote_sql_str   $escaped "$test$hello world!";
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
't\'\\est he\'llo world!'
--- timeout: 10



=== TEST 14: concatenate multiple empty sources
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $a "";
        set                 $b "";
        set_quote_sql_str   $escaped "$a$b";
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
''
--- timeout: 10



=== TEST 15: concatenate multiple empty sources (empty)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $a "";
        set                 $b "";
        set_quote_sql_str   $escaped "=$a$b";
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'='
--- timeout: 10



=== TEST 16: in-place escape on empty string
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "";
        set_quote_sql_str   $test;
        echo                $test;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
''
--- timeout: 10



=== TEST 17: in-place escape on empty string (empty)
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location /test {
        set                 $test "";
        set_quote_sql_str   $test;
        echo                $test;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
''
--- timeout: 10



=== TEST 18: escape anonymous regex capture
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location ~ /(.*) {
        set_quote_sql_str   $escaped $1;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'test'
--- timeout: 10



=== TEST 19: escape named regex capture
--- main_config
    load_module /etc/nginx/modules/ngx_http_set_misc_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
--- config
    location ~ /(?<test>.*) {
        set_quote_sql_str   $escaped $test;
        echo                $escaped;
    }
--- request
GET /test
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body
'test'
--- timeout: 10
--- skip_nginx: 3: < 0.8.25
