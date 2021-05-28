#ifndef _NGX_POSTGRES_INCLUDE_H_
#define _NGX_POSTGRES_INCLUDE_H_

#include <libpq-fe.h>
#include <ngx_http.h>
#include "queue.h"

#ifndef WIN32
typedef int pgsocket;
#define PGINVALID_SOCKET (-1)
#else
typedef SOCKET pgsocket;
#define PGINVALID_SOCKET INVALID_SOCKET
#endif

extern ngx_module_t ngx_postgres_module;

typedef struct {
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
#if (!T_NGX_HTTP_DYNAMIC_RESOLVE)
    struct {
        socklen_t socklen;
        struct sockaddr *sockaddr;
    } peer;
#endif
} ngx_postgres_connect_t;

typedef struct {
#if (!T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_array_t connect;
#endif
    struct {
        queue_t queue;
    } data;
    struct {
        ngx_http_upstream_init_peer_pt init;
        ngx_http_upstream_init_pt init_upstream;
    } peer;
    struct {
        ngx_flag_t deallocate;
        ngx_uint_t max;
    } prepare;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    struct {
        ngx_flag_t reject;
        ngx_msec_t timeout;
        ngx_uint_t max;
        queue_t queue;
    } request;
#endif
    struct {
        ngx_flag_t reject;
        ngx_log_t *log;
        ngx_msec_t timeout;
        ngx_uint_t max;
        ngx_uint_t requests;
        queue_t queue;
    } save;
    struct {
        ngx_log_t *log;
    } trace;
} ngx_postgres_upstream_srv_conf_t;

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
    ngx_flag_t binary;
    ngx_str_t sql;
    ngx_str_t stmtName;
    ngx_uint_t hash;
    ngx_uint_t nParams;
    Oid *paramTypes;
    u_char **paramValues;
} ngx_postgres_send_t;

typedef struct ngx_postgres_save_t {
    ngx_connection_t *connection;
    ngx_int_t (*handler) (struct ngx_postgres_save_t *s);
    ngx_postgres_upstream_srv_conf_t *usc;
    PGconn *conn;
    queue_t queue;
    struct {
        socklen_t socklen;
        struct sockaddr *sockaddr;
    } peer;
    struct {
        queue_t queue;
    } *prepare;
} ngx_postgres_save_t;

typedef struct {
    ngx_array_t send;
    ngx_array_t variable;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_event_t timeout;
#endif
    ngx_http_request_t *request;
    ngx_postgres_result_t result;
    ngx_postgres_save_t save;
    ngx_uint_t index;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    queue_t queue;
#endif
    struct {
        ngx_event_free_peer_pt free;
        ngx_event_get_peer_pt get;
#if (NGX_SSL || NGX_COMPAT)
        ngx_event_save_peer_session_pt save_session;
        ngx_event_set_peer_session_pt set_session;
#endif
        void *data;
    } peer;
} ngx_postgres_data_t;

typedef ngx_int_t (*ngx_postgres_data_handler_pt) (ngx_postgres_data_t *d);

typedef struct {
    ngx_flag_t binary;
    ngx_flag_t header;
    ngx_flag_t single;
    ngx_flag_t string;
    ngx_postgres_data_handler_pt handler;
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
char *PQerrorMessageMy(const PGconn *conn);
char *PQresultErrorMessageMy(const PGresult *res);
const char *ngx_postgres_status(PGconn *conn);
extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));
ngx_int_t ngx_postgres_busy(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_connect(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_consume_flush_busy(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_consume(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_flush(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_handler(ngx_http_request_t *r);
ngx_int_t ngx_postgres_notify(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_output_chain(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_csv(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_json(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_plain(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_value(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data);
ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *usc);
ngx_int_t ngx_postgres_prepare_or_query(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_rewrite_set(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf);
ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_variable_output(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_variable_set(ngx_postgres_data_t *d);
void ngx_postgres_close(ngx_postgres_save_t *s);
void ngx_postgres_data_handler(ngx_event_t *e);
void ngx_postgres_save_handler(ngx_event_t *e);

#if (!T_NGX_HTTP_DYNAMIC_RESOLVE)
ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type);
#endif

#endif /* _NGX_POSTGRES_INCLUDE_H_ */
