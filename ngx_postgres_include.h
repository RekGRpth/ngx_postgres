#ifndef _NGX_POSTGRES_INCLUDE_H_
#define _NGX_POSTGRES_INCLUDE_H_

#include <ngx_http.h>
#include <libpq-fe.h>
#include "queue.h"
#include "resty_dbd_stream.h"

#ifndef NGX_YIELD
#define NGX_YIELD -7
#endif

typedef struct {
    char *message;
    ngx_log_handler_pt handler;
    void *data;
} ngx_postgres_log_t;

#define ngx_postgres_log_error(level, log, err, msg, fmt, ...) do { \
    ngx_postgres_log_t ngx_log_original = { \
        .data = log->data, \
        .handler = log->handler, \
        .message = (msg), \
    }; \
    (log)->data = &ngx_log_original; \
    (log)->handler = ngx_postgres_log_error_handler; \
    ngx_log_error(level, log, err, fmt, ##__VA_ARGS__); \
} while (0)

#ifndef WIN32
typedef int pgsocket;
#define PGINVALID_SOCKET (-1)
#else
typedef SOCKET pgsocket;
#define PGINVALID_SOCKET INVALID_SOCKET
#endif

extern ngx_module_t ngx_postgres_module;

typedef struct {
    const char *client_encoding;
    const char **keywords;
    const char **values;
    ngx_msec_t timeout;
    ngx_url_t url;
    PGVerbosity verbosity;
} ngx_postgres_connect_t;

typedef struct {
    ngx_array_t connect;
    struct {
        ngx_flag_t reject;
        ngx_msec_t timeout;
        ngx_uint_t max;
        queue_t queue;
    } data;
    struct {
        ngx_flag_t reject;
        ngx_log_t *log;
        ngx_msec_t timeout;
        ngx_uint_t max;
        ngx_uint_t requests;
        queue_t queue;
    } keep;
    struct {
        ngx_http_upstream_init_peer_pt init;
        ngx_http_upstream_init_pt init_upstream;
    } peer;
    struct {
        ngx_log_t *log;
    } trace;
    struct {
        queue_t queue;
    } work;
} ngx_postgres_upstream_srv_conf_t;

typedef struct ngx_postgres_data_t ngx_postgres_data_t;

typedef struct {
    ngx_array_t ids;
    ngx_array_t params;
    ngx_array_t rewrite;
    ngx_array_t variable;
    ngx_msec_t timeout;
    ngx_str_t sql;
    ngx_uint_t method;
    ngx_uint_t percent;
    struct {
        ngx_flag_t binary;
        ngx_flag_t header;
        ngx_flag_t single;
        ngx_flag_t string;
        ngx_int_t (*handler) (ngx_postgres_data_t *d);
        ngx_str_t null;
        u_char delimiter;
        u_char escape;
        u_char quote;
    } output;
} ngx_postgres_query_t;

typedef struct {
    ngx_str_t sql;
    ngx_uint_t nParams;
    Oid *paramTypes;
    u_char **paramValues;
} ngx_postgres_send_t;

typedef struct ngx_postgres_save_t ngx_postgres_save_t;
typedef struct ngx_postgres_save_t {
    ngx_connection_t *connection;
    ngx_int_t (*read_handler) (ngx_postgres_save_t *s);
    ngx_int_t (*write_handler) (ngx_postgres_save_t *s);
    ngx_postgres_connect_t *connect;
    ngx_postgres_upstream_srv_conf_t *conf;
    PGconn *conn;
    PGresult *res;
    queue_t queue;
    struct {
        socklen_t socklen;
        struct sockaddr *sockaddr;
    } peer;
} ngx_postgres_save_t;

typedef struct ngx_postgres_data_t {
    ngx_array_t variable;
    ngx_event_t timeout;
    ngx_http_request_t *request;
    ngx_postgres_save_t *save;
    ngx_uint_t query;
    queue_t queue;
    struct {
        ngx_event_free_peer_pt free;
        ngx_event_get_peer_pt get;
        void *data;
    } peer;
    struct {
        int nfields;
        int nsingle;
        int ntuples;
        ngx_str_t cmdStatus;
        ngx_str_t cmdTuples;
        ngx_str_t error;
        ngx_str_t sfields;
        ngx_str_t sql;
        ngx_str_t stuples;
    } result;
} ngx_postgres_data_t;

typedef struct {
    ngx_http_upstream_srv_conf_t *upstream;
    ngx_msec_t connect_timeout;
    ngx_msec_t next_upstream_timeout;
    ngx_str_t module;
    ngx_uint_t next_upstream;
} ngx_http_upstream_conf_t_my;

typedef struct {
    ngx_array_t query;
    ngx_flag_t read_request_body;
    ngx_http_complex_value_t complex;
    ngx_http_upstream_conf_t_my upstream;
    ngx_msec_t timeout;
    ngx_postgres_connect_t *connect;
    ngx_uint_t variable;
} ngx_postgres_loc_conf_t;

typedef ngx_int_t (*ngx_postgres_rewrite_handler_pt) (ngx_postgres_data_t *d, ngx_uint_t key, ngx_uint_t status);

typedef struct  {
    ngx_flag_t keep;
    ngx_postgres_rewrite_handler_pt handler;
    ngx_uint_t key;
    ngx_uint_t method;
    ngx_uint_t status;
} ngx_postgres_rewrite_t;

typedef enum {
    type_nfields = 1,
    type_ntuples,
    type_cmdTuples,
    type_cmdStatus,
} ngx_postgres_variable_type_t;

typedef struct {
    int col;
    int row;
    ngx_int_t (*handler) (ngx_postgres_data_t *d);
    ngx_postgres_variable_type_t type;
    ngx_str_t name;
    ngx_uint_t index;
    ngx_uint_t required;
    u_char *field;
} ngx_postgres_variable_t;

typedef struct {
    ngx_uint_t index;
    ngx_uint_t oid;
} ngx_postgres_param_t;

char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_rewrite_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *PQerrorMessageMy(const PGconn *conn);
char *PQresultErrorMessageMy(const PGresult *res);
extern ngx_int_t ngx_http_push_stream_add_msg_to_channel_my(ngx_log_t *log, ngx_str_t *id, ngx_str_t *text, ngx_str_t *event_id, ngx_str_t *event_type, ngx_flag_t store_messages, ngx_pool_t *temp_pool) __attribute__((weak));
extern ngx_int_t ngx_http_push_stream_delete_channel_my(ngx_log_t *log, ngx_str_t *id, u_char *text, size_t len, ngx_pool_t *temp_pool) __attribute__((weak));
ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
ngx_int_t ngx_postgres_handler(ngx_http_request_t *r);
ngx_int_t ngx_postgres_notify(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_output_csv_handler(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_json_handler(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_plain_handler(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_output_value_handler(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data);
ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *usc);
ngx_int_t ngx_postgres_rewrite_set(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_send_query(ngx_postgres_save_t *s);
ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf);
ngx_int_t ngx_postgres_variable_output(ngx_postgres_data_t *d);
ngx_int_t ngx_postgres_variable_set(ngx_postgres_data_t *d);
u_char *ngx_postgres_log_error_handler(ngx_log_t *log, u_char *buf, size_t len);
void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
void ngx_http_upstream_init_my(ngx_http_request_t *r);
void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_uint_t ft_type);
void ngx_postgres_close(ngx_postgres_save_t *s);
void ngx_postgres_data_read_handler(ngx_event_t *e);
void ngx_postgres_data_write_handler(ngx_event_t *e);

#endif /* _NGX_POSTGRES_INCLUDE_H_ */
