#include <postgresql/server/catalog/pg_type_d.h>
#include <avcall.h>
#include "ngx_postgres_include.h"


typedef struct {
    ngx_queue_t item;
    ngx_uint_t hash;
} ngx_postgres_prepare_t2;


static ngx_int_t ngx_postgres_prepare(ngx_postgres_data_t *pd);
static ngx_int_t ngx_postgres_query(ngx_postgres_data_t *pd);


static ngx_int_t ngx_postgres_done(ngx_postgres_data_t *pd, ngx_int_t rc) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (rc == NGX_OK) rc = ngx_postgres_output_chain(pd);
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_finalize_request(r, u, rc);
    return NGX_OK;
}


ngx_int_t ngx_postgres_prepare_or_query(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_connection_t *c = pd->share.connection;
#if (HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS)
    u->connect_timeout = NGX_MAX_INT_T_VALUE;
#else
    u->conf->connect_timeout = NGX_MAX_INT_T_VALUE;
#endif
    if (location->timeout) {
#if (HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS)
        u->connect_timeout = location->timeout;
#else
        u->conf->connect_timeout = location->timeout;
#endif
        if (!c->read->timer_set) ngx_add_timer(c->read, location->timeout);
        if (!c->write->timer_set) ngx_add_timer(c->write, location->timeout);
    }
    pd->handler = ngx_postgres_prepare_or_query;
    switch (ngx_postgres_consume_flush_busy(&pd->share)) {
        case NGX_AGAIN: return NGX_AGAIN;
        case NGX_ERROR: return NGX_ERROR;
        default: break;
    }
    for (; pd->index < location->query.nelts; pd->index++) if (!queryelts[pd->index].method || queryelts[pd->index].method & r->method) break;
    if (pd->index == location->query.nelts) return NGX_HTTP_NOT_ALLOWED;
    ngx_postgres_query_t *query = &queryelts[pd->index];
    if (query->timeout) {
#if (HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS)
        u->connect_timeout = query->timeout;
#else
        u->conf->connect_timeout = query->timeout;
#endif
        ngx_add_timer(c->read, query->timeout);
        ngx_add_timer(c->write, query->timeout);
    }
    ngx_postgres_send_t *send = &sendelts[pd->index];
    ngx_postgres_upstream_srv_conf_t *usc = pd->share.usc;
    ngx_flag_t prepare = usc->prepare.max && (location->prepare || query->prepare);
    if (!usc->prepare.max && (location->prepare || query->prepare)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ignoring prepare");
    ngx_str_t sql;
    sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &query->sql);
    ngx_str_t *ids = NULL;
    if (query->ids.nelts) {
        ngx_uint_t *idselts = query->ids.elts;
        if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(*ids)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->ids.nelts; i++) {
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, idselts[i]);
            if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                char *str = PQescapeIdentifier(pd->share.conn, (const char *)value->data, value->len);
                if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(%*.*s) and %s", value->len, value->len, value->data, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
                ngx_str_t id = {ngx_strlen(str), NULL};
                if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); return NGX_ERROR; }
                ngx_memcpy(id.data, str, id.len);
                PQfreemem(str);
                ids[i] = id;
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
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &sql);
    send->sql = sql;
    if (usc->ps.save.max) {
        if (prepare) {
            if (!(send->stmtName.data = ngx_pnalloc(r->pool, 31 + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
            u_char *last = ngx_snprintf(send->stmtName.data, 31, "ngx_%ul", (unsigned long)(send->hash = ngx_hash_key(sql.data, sql.len)));
            *last = '\0';
            send->stmtName.len = last - send->stmtName.data;
        }
    }
    return prepare ? ngx_postgres_prepare(pd) : ngx_postgres_query(pd);
}


static ngx_int_t ngx_postgres_query_result(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    pd->handler = ngx_postgres_query_result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[pd->index];
    ngx_int_t rc = NGX_OK;
    const char *value;
    ngx_postgres_output_t *output = &query->output;
    while (PQstatus(pd->share.conn) == CONNECTION_OK && (pd->result.res = PQgetResult(pd->share.conn))) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                ngx_postgres_rewrite_set(pd);
                PQclear(pd->result.res);
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
            case PGRES_COMMAND_OK:
            case PGRES_TUPLES_OK:
                if (rc == NGX_OK) {
                    rc = ngx_postgres_rewrite_set(pd);
                    if (rc < NGX_HTTP_SPECIAL_RESPONSE) rc = NGX_OK;
                }
                if (rc == NGX_OK) rc = ngx_postgres_variable_set(pd);
                if (rc == NGX_OK) rc = ngx_postgres_variable_output(pd);
                // fall through
            case PGRES_SINGLE_TUPLE:
                if (PQresultStatus(pd->result.res) == PGRES_SINGLE_TUPLE) pd->result.nsingle++;
                if (rc == NGX_OK && output->handler) rc = output->handler(pd); // fall through
            default:
                if ((value = PQcmdStatus(pd->result.res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(pd->result.res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(pd->result.res))); }
                break;
        }
        PQclear(pd->result.res);
        switch (ngx_postgres_consume_flush_busy(&pd->share)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    pd->handler = ngx_postgres_prepare_or_query;
    if (rc == NGX_OK && pd->index < location->query.nelts - 1) {
        for (pd->index++; pd->index < location->query.nelts; pd->index++) if (!queryelts[pd->index].method || queryelts[pd->index].method & r->method) break;
        if (pd->index < location->query.nelts) return NGX_AGAIN;
    }
    if (rc == NGX_OK && PQtransactionStatus(pd->share.conn) != PQTRANS_IDLE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
        ngx_postgres_query_t *query = ngx_array_push(&location->query);
        if (!query) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        ngx_memzero(query, sizeof(*query));
        ngx_str_set(&query->sql, "COMMIT");
        pd->index++;
        return NGX_AGAIN;
    }
    return ngx_postgres_done(pd, rc);
}


static ngx_int_t ngx_postgres_result(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[pd->index];
    ngx_postgres_output_t *output = &query->output;
    if (output->handler == ngx_postgres_output_plain || output->handler == ngx_postgres_output_csv) if (output->single && !PQsetSingleRowMode(pd->share.conn)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsetSingleRowMode and %s", PQerrorMessageMy(pd->share.conn));
    pd->handler = ngx_postgres_query_result;
    ngx_connection_t *c = pd->share.connection;
    c->write->active = 0;
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_query_prepared(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    pd->handler = ngx_postgres_query_prepared;
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    if (!PQsendQueryPrepared(pd->share.conn, (const char *)send->stmtName.data, send->nParams, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryPrepared(\"%V\", \"%V\", %i) and %s", &send->stmtName, &send->sql, send->nParams, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryPrepared(\"%V\", \"%V\", %i)", &send->stmtName, &send->sql, send->nParams);
    return ngx_postgres_result(pd);
}


static ngx_int_t ngx_postgres_prepare_result(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    pd->handler = ngx_postgres_prepare_result;
    while (PQstatus(pd->share.conn) == CONNECTION_OK && (pd->result.res = PQgetResult(pd->share.conn))) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); break;
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQcmdStatus(pd->result.res), PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                PQclear(pd->result.res);
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        PQclear(pd->result.res);
        switch (ngx_postgres_consume_flush_busy(&pd->share)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    return ngx_postgres_query_prepared(pd);
}


static ngx_int_t ngx_postgres_query(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    pd->handler = ngx_postgres_query;
    while (PQstatus(pd->share.conn) == CONNECTION_OK && (pd->result.res = PQgetResult(pd->share.conn))) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                PQclear(pd->result.res);
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
            default: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQcmdStatus(pd->result.res)); break;
        }
        PQclear(pd->result.res);
        switch (ngx_postgres_consume_flush_busy(&pd->share)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    if (send->nParams || send->binary) {
        if (!PQsendQueryParams(pd->share.conn, (const char *)send->sql.data, send->nParams, send->paramTypes, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryParams(\"%V\", %i) and %s", &send->sql, send->nParams, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryParams(\"%V\", %i)", &send->sql, send->nParams);
    } else {
        if (!PQsendQuery(pd->share.conn, (const char *)send->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &send->sql, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &send->sql);
    }
    return ngx_postgres_result(pd);
}


static ngx_int_t ngx_postgres_deallocate_result(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    pd->handler = ngx_postgres_deallocate_result;
    while (PQstatus(pd->share.conn) == CONNECTION_OK && (pd->result.res = PQgetResult(pd->share.conn))) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); break;
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQcmdStatus(pd->result.res), PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                PQclear(pd->result.res);
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        PQclear(pd->result.res);
        switch (ngx_postgres_consume_flush_busy(&pd->share)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    return ngx_postgres_prepare(pd);
}


static ngx_int_t ngx_postgres_deallocate(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    char *str = PQescapeIdentifier(pd->share.conn, (const char *)send->stmtName.data, send->stmtName.len);
    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(\"%V\") and %s", &send->stmtName, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
    ngx_str_t id = {ngx_strlen(str), NULL};
    if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    ngx_memcpy(id.data, str, id.len);
    ngx_str_t sql = {sizeof("DEALLOCATE PREPARE ") - 1 + id.len, NULL};
    if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    u_char *last = sql.data;
    if ((last = ngx_snprintf(last, sql.len, "DEALLOCATE PREPARE %V", &id)) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); return NGX_ERROR; }
    *last = '\0';
    if (!PQsendQuery(pd->share.conn, (const char *)sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &sql, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &sql);
    ngx_queue_t *queue = ngx_queue_head(&pd->share.prepare->head);
    ngx_queue_remove(queue);
    pd->share.prepare->size--;
    pd->handler = ngx_postgres_deallocate_result;
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_prepare(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    pd->handler = ngx_postgres_prepare;
    while (PQstatus(pd->share.conn) == CONNECTION_OK && (pd->result.res = PQgetResult(pd->share.conn))) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                PQclear(pd->result.res);
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
            default: ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQcmdStatus(pd->result.res)); break;
        }
        PQclear(pd->result.res);
        switch (ngx_postgres_consume_flush_busy(&pd->share)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_postgres_send_t *send = &sendelts[pd->index];
    ngx_queue_each(&pd->share.prepare->head, item) {
        ngx_postgres_prepare_t2 *prepare = ngx_queue_data(item, ngx_postgres_prepare_t2, item);
        if (prepare->hash == send->hash) return ngx_postgres_query_prepared(pd);
    }
    ngx_postgres_upstream_srv_conf_t *usc = pd->share.usc;
    if (pd->share.prepare->size >= usc->prepare.max && usc->prepare.deallocate) return ngx_postgres_deallocate(pd);
    if (!PQsendPrepare(pd->share.conn, (const char *)send->stmtName.data, (const char *)send->sql.data, send->nParams, send->paramTypes)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendPrepare(\"%V\", \"%V\") and %s", &send->stmtName, &send->sql, PQerrorMessageMy(pd->share.conn)); return NGX_ERROR; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendPrepare(\"%V\", \"%V\")", &send->stmtName, &send->sql);
    ngx_connection_t *c = pd->share.connection;
    ngx_postgres_prepare_t2 *prepare = ngx_pcalloc(c->pool, sizeof(*prepare));
    if (!prepare) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    prepare->hash = send->hash;
    ngx_queue_insert_tail(&pd->share.prepare->head, &prepare->item);
    pd->share.prepare->size++;
    pd->handler = ngx_postgres_prepare_result;
    return NGX_AGAIN;
}


const char *ngx_postgres_status(PGconn *conn) {
    switch (PQstatus(conn)) {
        case CONNECTION_AUTH_OK: return "CONNECTION_AUTH_OK";
        case CONNECTION_AWAITING_RESPONSE: return "CONNECTION_AWAITING_RESPONSE";
        case CONNECTION_BAD: return "CONNECTION_BAD";
#if (PG_VERSION_NUM >= 130000)
        case CONNECTION_CHECK_TARGET: return "CONNECTION_CHECK_TARGET";
#endif
        case CONNECTION_CHECK_WRITABLE: return "CONNECTION_CHECK_WRITABLE";
        case CONNECTION_CONSUME: return "CONNECTION_CONSUME";
        case CONNECTION_GSS_STARTUP: return "CONNECTION_GSS_STARTUP";
        case CONNECTION_MADE: return "CONNECTION_MADE";
        case CONNECTION_NEEDED: return "CONNECTION_NEEDED";
        case CONNECTION_OK: return "CONNECTION_OK";
        case CONNECTION_SETENV: return "CONNECTION_SETENV";
        case CONNECTION_SSL_STARTUP: return "CONNECTION_SSL_STARTUP";
        case CONNECTION_STARTED: return "CONNECTION_STARTED";
    }
    return "";
}


ngx_int_t ngx_postgres_connect(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = pd->share.connection;
    pd->handler = ngx_postgres_connect;
    ngx_postgres_upstream_srv_conf_t *usc = pd->share.usc;
    switch (PQstatus(pd->share.conn)) {
        case CONNECTION_BAD: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD and %s", PQerrorMessageMy(pd->share.conn)); return NGX_ERROR;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_OK"); goto connected;
        default: break;
    }
    switch (PQconnectPoll(pd->share.conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_ACTIVE and %s", ngx_postgres_status(pd->share.conn)); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGRES_POLLING_FAILED and %s and %s", ngx_postgres_status(pd->share.conn), PQerrorMessageMy(pd->share.conn)); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_OK and %s", ngx_postgres_status(pd->share.conn)); goto connected;
        case PGRES_POLLING_READING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_READING and %s", ngx_postgres_status(pd->share.conn)); c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_WRITING and %s", ngx_postgres_status(pd->share.conn)); c->read->active = 0; break;
    }
    return NGX_AGAIN;
connected:
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    return ngx_postgres_prepare_or_query(pd);
}


char *PQerrorMessageMy(const PGconn *conn) {
    char *err = PQerrorMessage(conn);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    if (err[len - 1] == '\n') err[len - 1] = '\0';
    return err;
}


char *PQresultErrorMessageMy(const PGresult *res) {
    char *err = PQresultErrorMessage(res);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    if (err[len - 1] == '\n') err[len - 1] = '\0';
    return err;
}
