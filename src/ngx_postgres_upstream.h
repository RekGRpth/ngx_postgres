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
    state_db_connect,
    state_db_prepare,
    state_db_query,
    state_db_result,
    state_db_idle
} ngx_postgres_state_t;

typedef struct {
    const char **keywords;
    const char **values;
    ngx_queue_t queue;
    ngx_str_t host;
    ngx_str_t name;
    socklen_t socklen;
    struct sockaddr *sockaddr;
    u_char *value;
} ngx_postgres_peer_t;

typedef struct {
    ngx_flag_t reject;
    ngx_log_t *log;
    ngx_msec_t keepalive;
    ngx_msec_t timeout;
//    ngx_pool_t *pool;
    ngx_queue_t data;
    ngx_queue_t free;
    ngx_queue_t peer;
    ngx_queue_t save;
    ngx_uint_t cur_data;
    ngx_uint_t cur_save;
    ngx_uint_t max_data;
    ngx_uint_t max_save;
    ngx_uint_t requests;
} ngx_postgres_server_t;

typedef struct {
    ngx_connection_t *connection;
    ngx_postgres_server_t *server;
    ngx_postgres_state_t state;
    ngx_queue_t *listen;
    ngx_queue_t *prepare;
    ngx_str_t charset;
    ngx_str_t name;
    PGconn *conn;
    socklen_t socklen;
    struct sockaddr *sockaddr;
} ngx_postgres_common_t;

typedef struct {
    ngx_int_t nfields;
    ngx_int_t ntuples;
    ngx_str_t cmdStatus;
    ngx_str_t cmdTuples;
    ngx_str_t error;
    ngx_str_t sfields;
    ngx_str_t sql;
    ngx_str_t stuples;
    PGresult *res;
} ngx_postgres_result_t;

typedef struct {
    ngx_array_t variables;
    ngx_chain_t *response;
    ngx_event_t timeout;
    ngx_http_request_t *request;
    ngx_int_t status;
    ngx_postgres_common_t common;
    ngx_postgres_result_t result;
    ngx_queue_t queue;
    ngx_str_t sql;
    ngx_uint_t hash;
    ngx_uint_t nParams;
    ngx_uint_t query;
    Oid *paramTypes;
    u_char **paramValues;
    u_char *stmtName;
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
void ngx_postgres_free_connection(ngx_postgres_common_t *common, ngx_flag_t delete);

#endif /* _NGX_HTTP_UPSTREAM_POSTGRES_H_ */
