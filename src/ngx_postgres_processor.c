#include <postgresql/server/catalog/pg_type_d.h>
#include <avcall.h>

#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


static ngx_int_t ngx_postgres_done(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    r->upstream->headers_in.status_n = NGX_HTTP_OK; /* flag for keepalive */
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_postgres_common_t *common = &pd->common;
    common->state = state_db_idle;
    ngx_postgres_finalize_upstream(r, pd->status >= NGX_HTTP_SPECIAL_RESPONSE ? pd->status : NGX_OK);
    return NGX_DONE;
}


typedef struct {
    ngx_queue_t queue;
    ngx_uint_t hash;
} ngx_postgres_prepare_t;


static ngx_int_t ngx_postgres_send_query(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_postgres_common_t *common = &pd->common;
    if (!PQconsumeInput(common->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(common->conn)); return NGX_ERROR; }
    if (PQisBusy(common->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); return NGX_AGAIN; }
    ngx_connection_t *c = common->connection;
    if (common->state == state_db_connect || common->state == state_db_idle) {
        ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
        ngx_postgres_query_t *query = &location->query;
        ngx_str_t sql;
        sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
    //    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &query->sql);
        ngx_str_t *ids = NULL;
        ngx_str_t channel = ngx_null_string;
        ngx_str_t command = ngx_null_string;
        if (query->ids.nelts) {
            ngx_uint_t *elts = query->ids.elts;
            if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            for (ngx_uint_t i = 0; i < query->ids.nelts; i++) {
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, elts[i]);
                if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                    char *str = PQescapeIdentifier(common->conn, (const char *)value->data, value->len);
                    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(%*.*s) and %s", value->len, value->len, value->data, PQerrorMessageMy(common->conn)); return NGX_ERROR; }
                    ngx_str_t id = {ngx_strlen(str), NULL};
                    if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); return NGX_ERROR; }
                    ngx_memcpy(id.data, str, id.len);
                    PQfreemem(str);
                    ids[i] = id;
                    if (!i && query->listen && ngx_http_push_stream_add_msg_to_channel_my && ngx_http_push_stream_delete_channel_my) {
                        channel.len = value->len;
                        if (!(channel.data = ngx_pnalloc(c->pool, channel.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        ngx_memcpy(channel.data, value->data, value->len);
                        command.len = sizeof("UNLISTEN ") - 1 + id.len;
                        if (!(command.data = ngx_pnalloc(c->pool, command.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                        command.len = ngx_snprintf(command.data, command.len, "UNLISTEN %V", &id) - command.data;
                    }
                }
                sql.len += ids[i].len;
            }
        }
        if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        av_alist alist;
        u_char *last = NULL;
        av_start_ptr(alist, &ngx_snprintf, u_char *, &last);
        if (av_ptr(alist, u_char *, sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        if (av_ulong(alist, sql.len)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ulong"); return NGX_ERROR; }
        if (av_ptr(alist, char *, query->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->ids.nelts; i++) if (av_ptr(alist, ngx_str_t *, &ids[i])) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        if (av_call(alist)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_call"); return NGX_ERROR; }
        if (last != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); return NGX_ERROR; }
        *last = '\0';
    //    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &sql);
        pd->sql = sql; /* set $postgres_query */
        ngx_postgres_server_t *server = common->server;
        if (server->max_save) {
            if (query->listen && channel.data && command.data) {
                if (!common->listen) {
                    if (!(common->listen = ngx_pcalloc(c->pool, sizeof(ngx_queue_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                    ngx_queue_init(common->listen);
                }
                for (ngx_queue_t *queue = ngx_queue_head(common->listen); queue != ngx_queue_sentinel(common->listen); queue = ngx_queue_next(queue)) {
                    ngx_postgres_listen_t *listen = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
                    if (listen->channel.len == channel.len && !ngx_strncmp(listen->channel.data, channel.data, channel.len)) goto cont;
                }
                ngx_postgres_listen_t *listen = ngx_pcalloc(c->pool, sizeof(ngx_postgres_listen_t));
                if (!listen) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                listen->channel = channel;
                listen->command = command;
                ngx_queue_insert_tail(common->listen, &listen->queue);
                cont:;
            } else if (query->prepare) {
                if (!(pd->stmtName = ngx_pnalloc(r->pool, 32))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
                u_char *last = ngx_snprintf(pd->stmtName, 31, "ngx_%ul", (unsigned long)(pd->hash = ngx_hash_key(sql.data, sql.len)));
                *last = '\0';
            }
        }
        common->state = query->prepare ? state_db_prepare : state_db_query;
    }
    for (; (pd->result.res = PQgetResult(common->conn)); PQclear(pd->result.res)) switch(PQresultStatus(pd->result.res)) {
        case PGRES_FATAL_ERROR:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
            ngx_postgres_variable_set2(r);
            PQclear(pd->result.res);
            pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            if (pd->stmtName && common->prepare) {
                for (ngx_queue_t *queue = ngx_queue_head(common->prepare); queue != ngx_queue_sentinel(common->prepare); queue = ngx_queue_next(queue)) {
                    ngx_postgres_prepare_t *prepare = ngx_queue_data(queue, ngx_postgres_prepare_t, queue);
                    if (prepare->hash == pd->hash) { ngx_queue_remove(queue); break; }
                }
            }
            return ngx_postgres_done(r);
        default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQresultErrorMessageMy(pd->result.res)); break;
    }
    ngx_uint_t hash = 0;
    if (!pd->stmtName) {
        if (pd->nParams) {
            if (!PQsendQueryParams(common->conn, (const char *)pd->sql.data, pd->nParams, pd->paramTypes, (const char *const *)pd->paramValues, NULL, NULL, pd->resultFormat)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryParams(%s) and %s", pd->sql.data, PQerrorMessageMy(common->conn)); return NGX_ERROR; }
        } else {
            if (!PQsendQuery(common->conn, (const char *)pd->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(%s) and %s", pd->sql.data, PQerrorMessageMy(common->conn)); return NGX_ERROR; }
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(%s)", pd->sql.data);
    } else switch (common->state) {
        case state_db_prepare:
            if (common->prepare) for (ngx_queue_t *queue = ngx_queue_head(common->prepare); queue != ngx_queue_sentinel(common->prepare); queue = ngx_queue_next(queue)) {
                ngx_postgres_prepare_t *prepare = ngx_queue_data(queue, ngx_postgres_prepare_t, queue);
                if (prepare->hash == pd->hash) { hash = prepare->hash; break; }
            }
            if (hash) common->state = state_db_query; else {
                if (!PQsendPrepare(common->conn, (const char *)pd->stmtName, (const char *)pd->sql.data, pd->nParams, pd->paramTypes)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendPrepare(%s, %s) and %s", pd->stmtName, pd->sql.data, PQerrorMessageMy(common->conn)); return NGX_ERROR; }
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendPrepare(%s, %s)", pd->stmtName, pd->sql.data);
                if (!common->prepare) {
                    if (!(common->prepare = ngx_pcalloc(c->pool, sizeof(ngx_queue_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                    ngx_queue_init(common->prepare);
                }
                ngx_postgres_prepare_t *prepare = ngx_pcalloc(c->pool, sizeof(ngx_postgres_prepare_t));
                if (!prepare) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                prepare->hash = pd->hash;
                ngx_queue_insert_tail(common->prepare, &prepare->queue);
                common->state = state_db_query;
                return NGX_DONE;
            } // fall through
        case state_db_query:
            if (!PQsendQueryPrepared(common->conn, (const char *)pd->stmtName, pd->nParams, (const char *const *)pd->paramValues, NULL, NULL, pd->resultFormat)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryPrepared(%s, %s) and %s", pd->stmtName, pd->sql.data, PQerrorMessageMy(common->conn)); return NGX_ERROR; }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryPrepared(%s, %s)", pd->stmtName, pd->sql.data);
            break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "common->state == %i", common->state); return NGX_ERROR;
    }
    ngx_add_timer(c->read, r->upstream->conf->read_timeout); /* set result timeout */
    common->state = state_db_result;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_connect(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_postgres_common_t *common = &pd->common;
    switch (PQstatus(common->conn)) {
        case CONNECTION_AUTH_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_AUTH_OK"); break;
        case CONNECTION_AWAITING_RESPONSE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_AWAITING_RESPONSE"); break;
        case CONNECTION_BAD: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD and %s", PQerrorMessageMy(common->conn)); return NGX_ERROR;
        case CONNECTION_CHECK_WRITABLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_CHECK_WRITABLE"); break;
        case CONNECTION_CONSUME: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_CONSUME"); break;
        case CONNECTION_GSS_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_GSS_STARTUP"); break;
        case CONNECTION_MADE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_MADE"); break;
        case CONNECTION_NEEDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_NEEDED"); break;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_OK"); return ngx_postgres_send_query(r);
        case CONNECTION_SETENV: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_SETENV"); break;
        case CONNECTION_SSL_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_SSL_STARTUP"); break;
        case CONNECTION_STARTED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_STARTED"); break;
    }
again:
    switch (PQconnectPoll(common->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_FAILED and %s", PQerrorMessageMy(common->conn)); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_OK"); break;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_READING"); return NGX_AGAIN;
        case PGRES_POLLING_WRITING:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_WRITING");
            if (PQstatus(common->conn) == CONNECTION_MADE) goto again;
            return NGX_AGAIN;
    }
    ngx_connection_t *c = common->connection;
    if (c->write->timer_set) ngx_del_timer(c->write); /* remove connection timeout from new connection */
    const char *charset = PQparameterStatus(common->conn, "client_encoding");
    if (charset) {
        common->charset.len = ngx_strlen(charset);
        if (common->charset.len == sizeof("utf8") - 1 && !ngx_strncasecmp((u_char *)charset, (u_char *)"utf8", sizeof("utf8") - 1)) {
            ngx_str_set(&common->charset, "utf-8");
        } else if (common->charset.len == sizeof("windows1251") - 1 && !ngx_strncasecmp((u_char *)charset, (u_char *)"windows1251", sizeof("windows1251") - 1)) {
            ngx_str_set(&common->charset, "windows-1251");
        } else if (common->charset.len == sizeof("koi8r") - 1 && !ngx_strncasecmp((u_char *)charset, (u_char *)"koi8r", sizeof("koi8r") - 1)) {
            ngx_str_set(&common->charset, "koi8-r");
        } else {
            if (!(common->charset.data = ngx_pnalloc(r->pool, common->charset.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            ngx_memcpy(common->charset.data, charset, common->charset.len);
        }
    }
    return ngx_postgres_send_query(r);
}


static ngx_int_t ngx_postgres_process_response(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_postgres_variable_set(r) == NGX_ERROR) {
        ngx_postgres_data_t *pd = r->upstream->peer.data;
        pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_postgres_variable_set == NGX_ERROR");
        return NGX_DONE;
    }
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->output.handler) return location->output.handler(r);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_get_result(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_postgres_common_t *common = &pd->common;
    ngx_connection_t *c = common->connection;
    if (c->write->timer_set) ngx_del_timer(c->write); /* remove connection timeout from re-used keepalive connection */
    if (c->read->timer_set) ngx_del_timer(c->read); /* remove result timeout */
    if (!PQconsumeInput(common->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(common->conn)); return NGX_ERROR; }
    if (PQisBusy(common->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); return NGX_AGAIN; }
    ngx_int_t rc = NGX_DONE;
    for (; rc == NGX_DONE && (pd->result.res = PQgetResult(common->conn)); PQclear(pd->result.res)) switch(PQresultStatus(pd->result.res)) {
        case PGRES_FATAL_ERROR:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
            ngx_postgres_variable_set2(r);
            PQclear(pd->result.res);
            pd->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return ngx_postgres_done(r);
        case PGRES_COMMAND_OK: case PGRES_TUPLES_OK: rc = ngx_postgres_process_response(r); break;
        default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQresultErrorMessageMy(pd->result.res)); break;
    }
    return rc;
}


void ngx_postgres_process_events(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!ngx_postgres_is_my_peer(&r->upstream->peer)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_postgres_is_my_peer"); return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR); }
    ngx_postgres_data_t *pd = r->upstream->peer.data;
    ngx_postgres_common_t *common = &pd->common;
    ngx_int_t rc;
    switch (common->state) {
        case state_db_connect: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_db_connect"); rc = ngx_postgres_connect(r); break;
        case state_db_idle: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_db_idle"); rc = ngx_postgres_send_query(r); break;
        case state_db_prepare: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_db_prepare"); rc = ngx_postgres_send_query(r); break;
        case state_db_query: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_db_query"); rc = ngx_postgres_send_query(r); break;
        case state_db_result: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_db_result"); rc = ngx_postgres_get_result(r); break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "state == %i", common->state); return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) return ngx_postgres_finalize_upstream(r, rc);
    if (rc == NGX_ERROR) return ngx_postgres_next_upstream(r, NGX_HTTP_UPSTREAM_FT_ERROR);
    return;
}
