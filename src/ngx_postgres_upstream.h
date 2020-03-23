#ifndef _NGX_HTTP_UPSTREAM_POSTGRES_H_
#define _NGX_HTTP_UPSTREAM_POSTGRES_H_

#include <libpq-fe.h>
#include <ngx_http.h>

typedef struct {
    ngx_queue_t queue;
    ngx_str_t channel;
    ngx_str_t command;
} ngx_postgres_listen_t;

typedef enum {
    state_db_connect = 1,
    state_db_prepare,
    state_db_query,
    state_db_result,
    state_db_idle
} ngx_postgres_state_t;

typedef struct {
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
} ngx_postgres_connect_t;

typedef struct {
    ngx_addr_t addr;
    ngx_postgres_connect_t connect;
    ngx_queue_t queue;
    ngx_str_t host;
    u_char *value;
} ngx_postgres_peer_t;

typedef struct {
    struct {
        ngx_flag_t reject;
        ngx_msec_t timeout;
        ngx_queue_t queue;
        ngx_uint_t max;
        ngx_uint_t size;
    } pd;
    struct {
        ngx_flag_t reject;
        ngx_log_t *log;
        ngx_msec_t timeout;
        ngx_queue_t queue;
        ngx_uint_t max;
        ngx_uint_t requests;
        ngx_uint_t size;
    } ps;
    struct {
        ngx_flag_t deallocate;
        ngx_uint_t max;
    } prepare;
    struct {
        ngx_queue_t queue;
    } free;
    struct {
        ngx_log_t *log;
    } trace;
    ngx_queue_t peer;
} ngx_postgres_server_t;

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
    ngx_postgres_server_t *server;
    ngx_postgres_state_t state;
    ngx_str_t charset;
    PGconn *conn;
} ngx_postgres_common_t;

typedef struct {
    ngx_chain_t *response;
    ngx_int_t status;
    ngx_str_t cmdStatus;
    ngx_str_t cmdTuples;
    ngx_str_t error;
    ngx_str_t sfields;
    ngx_str_t sql;
    ngx_str_t stuples;
    ngx_uint_t nfields;
    ngx_uint_t ntuples;
    PGresult *res;
} ngx_postgres_result_t;

typedef struct {
    struct {
        ngx_event_t timeout;
        ngx_str_t sql;
        ngx_str_t stmtName;
        ngx_uint_t hash;
        ngx_uint_t index;
        ngx_uint_t nParams;
        Oid *paramTypes;
        u_char **paramValues;
    } query;
    ngx_array_t variables;
    ngx_http_request_t *request;
    ngx_postgres_common_t common;
    ngx_postgres_result_t result;
    ngx_queue_t queue;
} ngx_postgres_data_t;

typedef struct {
    ngx_postgres_common_t common;
    ngx_queue_t queue;
} ngx_postgres_save_t;

char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *PQerrorMessageMy(const PGconn *conn);
char *PQresultErrorMessageMy(const PGresult *res);
extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));
ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *pc);
ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf);
void ngx_postgres_free_connection(ngx_postgres_common_t *common);

#endif /* _NGX_HTTP_UPSTREAM_POSTGRES_H_ */
