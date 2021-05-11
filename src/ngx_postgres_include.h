#ifndef _NGX_POSTGRES_INCLUDE_H_
#define _NGX_POSTGRES_INCLUDE_H_

#include <libpq-fe.h>
#include <ngx_http.h>

extern ngx_module_t ngx_postgres_module;

typedef struct {
    ngx_queue_t queue;
    ngx_str_t channel;
    ngx_str_t command;
} ngx_postgres_listen_t;

typedef enum {
    state_connect = 1,
    state_prepare,
    state_query,
    state_result,
    state_idle
} ngx_postgres_state_t;

typedef struct {
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
#if (!T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_addr_t *addrs;
    ngx_str_t name;
    ngx_uint_t naddrs;
#endif
} ngx_postgres_connect_t;

typedef struct {
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    struct {
        ngx_flag_t reject;
        ngx_msec_t timeout;
        ngx_queue_t queue;
        ngx_uint_t max;
        ngx_uint_t size;
    } pd;
#else
    void *connect;
#endif
    struct {
        struct {
            ngx_flag_t reject;
            ngx_log_t *log;
            ngx_msec_t timeout;
            ngx_queue_t queue;
            ngx_uint_t max;
            ngx_uint_t requests;
            ngx_uint_t size;
        } save;
        struct {
            ngx_queue_t queue;
        } free;
    } ps;
    struct {
        ngx_flag_t deallocate;
        ngx_uint_t max;
    } prepare;
    struct {
        ngx_log_t *log;
    } trace;
    ngx_http_upstream_init_peer_pt peer_init;
    ngx_http_upstream_init_pt init_upstream;
} ngx_postgres_upstream_srv_conf_t;

typedef struct {
    struct {
        ngx_queue_t *queue;
        ngx_uint_t size;
    } prepare;
    struct {
        ngx_queue_t *queue;
    } listen;
    ngx_addr_t addr;
    ngx_connection_t *connection;
    ngx_postgres_upstream_srv_conf_t *pusc;
    ngx_postgres_state_t state;
    ngx_str_t charset;
    PGconn *conn;
} ngx_postgres_common_t;

typedef struct {
    ngx_str_t cmdStatus;
    ngx_str_t cmdTuples;
    ngx_str_t error;
    ngx_str_t sfields;
    ngx_str_t sql;
    ngx_str_t stuples;
    ngx_uint_t nfields;
    ngx_uint_t nsingle;
    ngx_uint_t ntuples;
    ngx_uint_t status;
    PGresult *res;
} ngx_postgres_result_t;

typedef struct {
    ngx_str_t sql;
    ngx_str_t stmtName;
    ngx_uint_t hash;
    ngx_uint_t nParams;
    Oid *paramTypes;
    u_char **paramValues;
} ngx_postgres_send_t;

typedef struct {
    ngx_array_t send;
    ngx_array_t variable;
    ngx_event_free_peer_pt peer_free;
    ngx_event_get_peer_pt peer_get;
#if (NGX_HTTP_SSL)
    ngx_event_save_peer_session_pt save_session;
    ngx_event_set_peer_session_pt set_session;
#endif
    ngx_http_request_t *request;
    ngx_postgres_common_t common;
    ngx_postgres_result_t result;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_event_t timeout;
    ngx_queue_t queue;
#endif
    ngx_uint_t index;
    void *peer_data;
} ngx_postgres_data_t;

typedef struct {
    ngx_postgres_common_t common;
    ngx_queue_t queue;
} ngx_postgres_save_t;

typedef ngx_int_t (*ngx_postgres_handler_pt) (ngx_postgres_data_t *pd);

typedef struct {
    ngx_flag_t binary;
    ngx_flag_t header;
    ngx_flag_t single;
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
    ngx_array_t rewrite;
    ngx_array_t variable;
    ngx_flag_t listen;
    ngx_flag_t prepare;
    ngx_msec_t timeout;
    ngx_postgres_output_t output;
    ngx_str_t sql;
    ngx_uint_t method;
    ngx_uint_t percent;
} ngx_postgres_query_t;

typedef struct {
    ngx_array_t query;
    ngx_flag_t append;
    ngx_flag_t prepare;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t upstream;
    ngx_msec_t timeout;
    ngx_uint_t variable;
} ngx_postgres_location_t;

char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));
ngx_int_t ngx_postgres_busy(ngx_postgres_common_t *common);
ngx_int_t ngx_postgres_consume_flush_busy(ngx_postgres_common_t *common);
ngx_int_t ngx_postgres_consume(ngx_postgres_common_t *common);
ngx_int_t ngx_postgres_flush(ngx_postgres_common_t *common);
ngx_int_t ngx_postgres_handler(ngx_http_request_t *r);
ngx_int_t ngx_postgres_output_chain(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_output_csv(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_output_json(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_output_plain(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_output_value(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data);
ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf);
ngx_int_t ngx_postgres_process_notify(ngx_postgres_common_t *common, ngx_flag_t send);
ngx_int_t ngx_postgres_rewrite_set(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf);
ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_variable_output(ngx_postgres_data_t *pd);
ngx_int_t ngx_postgres_variable_set(ngx_postgres_data_t *pd);
void ngx_postgres_free_connection(ngx_postgres_common_t *common);
void ngx_postgres_process_events(ngx_postgres_data_t *pd);

#if (!T_NGX_HTTP_DYNAMIC_RESOLVE)
ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type);
#endif

#endif /* _NGX_POSTGRES_INCLUDE_H_ */
