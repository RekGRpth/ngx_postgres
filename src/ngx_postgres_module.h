#ifndef _NGX_POSTGRES_MODULE_H_
#define _NGX_POSTGRES_MODULE_H_

#include <ngx_http.h>

extern ngx_module_t ngx_postgres_module;

typedef ngx_int_t (*ngx_postgres_handler_pt) (ngx_http_request_t *r);

typedef struct {
    ngx_flag_t binary;
    ngx_flag_t header;
    ngx_flag_t string;
    ngx_postgres_handler_pt handler;
    ngx_str_t null;
    u_char delimiter;
    u_char escape;
    u_char quote;
} ngx_postgres_output_t;

typedef struct {
    ngx_array_t ids;
    ngx_array_t params;
    ngx_array_t variables;
    ngx_flag_t listen;
    ngx_flag_t prepare;
    ngx_msec_t timeout;
    ngx_postgres_output_t output;
    ngx_str_t sql;
    ngx_uint_t percent;
} ngx_postgres_query_t;

typedef struct {
    ngx_array_t queries;
    ngx_flag_t append;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t conf;
    ngx_postgres_output_t *output;
    ngx_postgres_query_t *query;
    ngx_uint_t index;
} ngx_postgres_location_t;

#endif /* _NGX_POSTGRES_MODULE_H_ */
