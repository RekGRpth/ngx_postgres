#include <postgresql/server/catalog/pg_type_d.h>
#include <avcall.h>
#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_prepare(ngx_postgres_save_t *s);


static ngx_int_t ngx_postgres_done(ngx_postgres_data_t *d, ngx_int_t rc) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "rc = %i", rc);
    if (rc == NGX_OK) rc = ngx_postgres_output_chain(d);
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_finalize_request(r, u, rc);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_result_t *result = &d->result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = &((ngx_postgres_query_t *)location->query.elts)[d->index];
    result->sql = query->sql;
    PGresult *res = result->res;
    result->ntuples = 0;
    result->nfields = 0;
    if (result->stuples.data) ngx_pfree(r->pool, result->stuples.data);
    if (result->sfields.data) ngx_pfree(r->pool, result->sfields.data);
    if (result->cmdTuples.data) ngx_pfree(r->pool, result->cmdTuples.data);
    if (result->cmdStatus.data) ngx_pfree(r->pool, result->cmdStatus.data);
    ngx_str_null(&result->stuples);
    ngx_str_null(&result->sfields);
    ngx_str_null(&result->cmdTuples);
    ngx_str_null(&result->cmdStatus);
    const char *value;
    if ((value = PQresultErrorMessage(res)) && !result->error.len && (result->error.len = ngx_strlen(value))) {
        if (!(result->error.data = ngx_pnalloc(r->pool, result->error.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        ngx_memcpy(result->error.data, value, result->error.len);
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_query_result(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    s->handler = ngx_postgres_query_result;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[d->index];
    ngx_int_t rc = NGX_OK;
    const char *value;
    ngx_postgres_output_t *output = &query->output;
    if (d->result.res) {
        switch (PQresultStatus(d->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(d->result.res));
                ngx_postgres_variable_error(d);
                ngx_postgres_rewrite_set(d);
                return ngx_postgres_done(d, NGX_HTTP_INTERNAL_SERVER_ERROR);
            case PGRES_COMMAND_OK:
            case PGRES_TUPLES_OK:
                if (rc == NGX_OK) {
                    rc = ngx_postgres_rewrite_set(d);
                    if (rc < NGX_HTTP_SPECIAL_RESPONSE) rc = NGX_OK;
                }
                if (rc == NGX_OK) rc = ngx_postgres_variable_set(d);
                if (rc == NGX_OK) rc = ngx_postgres_variable_output(d);
                // fall through
            case PGRES_SINGLE_TUPLE:
                if (PQresultStatus(d->result.res) == PGRES_SINGLE_TUPLE) d->result.nsingle++;
                if (rc == NGX_OK && output->handler) rc = output->handler(d); // fall through
            default:
                if ((value = PQcmdStatus(d->result.res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s and %s", PQresStatus(PQresultStatus(d->result.res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, PQresStatus(PQresultStatus(d->result.res))); }
                break;
        }
        return rc;
    }
    s->handler = ngx_postgres_prepare_or_query;
    if (rc == NGX_OK && d->index < location->query.nelts - 1) {
        for (d->index++; d->index < location->query.nelts; d->index++) if (!queryelts[d->index].method || queryelts[d->index].method & r->method) break;
        if (d->index < location->query.nelts) return NGX_AGAIN;
    }
    if (rc == NGX_OK && PQtransactionStatus(s->conn) != PQTRANS_IDLE) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
        ngx_postgres_query_t *query = ngx_array_push(&location->query);
        if (!query) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        ngx_memzero(query, sizeof(*query));
        ngx_str_set(&query->sql, "COMMIT");
        d->index++;
        return NGX_AGAIN;
    }
    return ngx_postgres_done(d, rc);
}


static ngx_int_t ngx_postgres_result(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[d->index];
    ngx_postgres_output_t *output = &query->output;
    if (output->handler == ngx_postgres_output_plain || output->handler == ngx_postgres_output_csv) if (output->single && !PQsetSingleRowMode(s->conn)) ngx_log_error(NGX_LOG_WARN, c->log, 0, "!PQsetSingleRowMode and %s", PQerrorMessageMy(s->conn));
    s->handler = ngx_postgres_query_result;
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_query_prepared(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    if (!PQsendQueryPrepared(s->conn, (const char *)send->stmtName.data, send->nParams, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQueryPrepared(\"%V\", \"%V\", %i) and %s", &send->stmtName, &send->sql, send->nParams, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQueryPrepared(\"%V\", \"%V\", %i)", &send->stmtName, &send->sql, send->nParams);
    return ngx_postgres_result(s);
}


static ngx_int_t ngx_postgres_prepare_result(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    s->handler = ngx_postgres_prepare_result;
    if (d->result.res) {
        switch (PQresultStatus(d->result.res)) {
            case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); break;
            default:
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(d->result.res)), PQcmdStatus(d->result.res), PQresultErrorMessageMy(d->result.res));
                ngx_postgres_variable_error(d);
                return ngx_postgres_done(d, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return NGX_OK;
    }
    return ngx_postgres_query_prepared(s);
}


static ngx_int_t ngx_postgres_query(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    s->handler = ngx_postgres_query;
    if (d->result.res) {
        switch (PQresultStatus(d->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(d->result.res));
                ngx_postgres_variable_error(d);
                return ngx_postgres_done(d, NGX_HTTP_INTERNAL_SERVER_ERROR);
            default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(d->result.res)), PQcmdStatus(d->result.res)); break;
        }
        return NGX_OK;
    }
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    if (send->nParams || send->binary) {
        if (!PQsendQueryParams(s->conn, (const char *)send->sql.data, send->nParams, send->paramTypes, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQueryParams(\"%V\", %i) and %s", &send->sql, send->nParams, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQueryParams(\"%V\", %i)", &send->sql, send->nParams);
    } else {
        if (!PQsendQuery(s->conn, (const char *)send->sql.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%V\") and %s", &send->sql, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(\"%V\")", &send->sql);
    }
    return ngx_postgres_result(s);
}


static ngx_int_t ngx_postgres_deallocate_result(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    s->handler = ngx_postgres_deallocate_result;
    if (d->result.res) {
        switch (PQresultStatus(d->result.res)) {
            case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); break;
            default:
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(d->result.res)), PQcmdStatus(d->result.res), PQresultErrorMessageMy(d->result.res));
                ngx_postgres_variable_error(d);
                return ngx_postgres_done(d, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        return NGX_OK;
    }
    return ngx_postgres_prepare(s);
}


static ngx_int_t ngx_postgres_deallocate(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    queue_t *q = queue_last(&s->prepare.queue);
    queue_remove(q);
    ngx_postgres_prepare_t *prepare = queue_data(q, typeof(*prepare), queue);
    ngx_str_t stmtName;
    ngx_int_t rc = NGX_ERROR;
    if (!(stmtName.data = ngx_pnalloc(r->pool, 31 + 1))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
    u_char *last = ngx_snprintf(stmtName.data, 31, "ngx_%ul", (unsigned long)(prepare->hash));
    *last = '\0';
    stmtName.len = last - stmtName.data;
    char *str = PQescapeIdentifier(s->conn, (const char *)stmtName.data, stmtName.len);
    if (!str) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQescapeIdentifier(\"%V\") and %s", &stmtName, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_str_t sql = {sizeof("DEALLOCATE PREPARE ") - 1 + ngx_strlen(str), NULL};
    if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); goto free; }
    if ((last = ngx_snprintf(sql.data, sql.len, "DEALLOCATE PREPARE %s", str)) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_snprintf"); goto free; }
    *last = '\0';
    if (!PQsendQuery(s->conn, (const char *)sql.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%V\") and %s", &sql, PQerrorMessageMy(s->conn)); goto free; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(\"%V\")", &sql);
    s->handler = ngx_postgres_deallocate_result;
    rc = NGX_AGAIN;
free:
    PQfreemem(str);
    return rc;
}


static ngx_int_t ngx_postgres_prepare(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    s->handler = ngx_postgres_prepare;
    if (d->result.res) {
        switch (PQresultStatus(d->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(d->result.res));
                ngx_postgres_variable_error(d);
                return ngx_postgres_done(d, NGX_HTTP_INTERNAL_SERVER_ERROR);
            default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(d->result.res)), PQcmdStatus(d->result.res)); break;
        }
        return NGX_OK;
    }
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    queue_each(&s->prepare.queue, q) {
        ngx_postgres_prepare_t *prepare = queue_data(q, typeof(*prepare), queue);
        if (prepare->hash == send->hash) return ngx_postgres_query_prepared(s);
    }
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (usc && usc->prepare.deallocate && queue_size(&s->prepare.queue) >= usc->prepare.max) return ngx_postgres_deallocate(s);
    if (!PQsendPrepare(s->conn, (const char *)send->stmtName.data, (const char *)send->sql.data, send->nParams, send->paramTypes)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendPrepare(\"%V\", \"%V\") and %s", &send->stmtName, &send->sql, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendPrepare(\"%V\", \"%V\")", &send->stmtName, &send->sql);
    ngx_postgres_prepare_t *prepare = ngx_pcalloc(c->pool, sizeof(*prepare));
    if (!prepare) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    prepare->hash = send->hash;
    queue_insert_head(&s->prepare.queue, &prepare->queue);
    s->handler = ngx_postgres_prepare_result;
    return NGX_AGAIN;
}


ngx_int_t ngx_postgres_prepare_or_query(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    u->conf->connect_timeout = NGX_MAX_INT_T_VALUE;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->timeout) {
        u->conf->connect_timeout = location->timeout;
        if (!c->read->timer_set) ngx_add_timer(c->read, location->timeout);
        if (!c->write->timer_set) ngx_add_timer(c->write, location->timeout);
    }
    s->handler = ngx_postgres_prepare_or_query;
    ngx_postgres_query_t *queryelts = location->query.elts;
    for (; d->index < location->query.nelts; d->index++) if (!queryelts[d->index].method || queryelts[d->index].method & r->method) break;
    if (d->index == location->query.nelts) return NGX_HTTP_NOT_ALLOWED;
    ngx_postgres_query_t *query = &queryelts[d->index];
    if (query->timeout) {
        u->conf->connect_timeout = query->timeout;
        ngx_add_timer(c->read, query->timeout);
        ngx_add_timer(c->write, query->timeout);
    }
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->index];
    ngx_str_t sql;
    sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
    ngx_str_t *ids = NULL;
    if (query->ids.nelts) {
        ngx_uint_t *idselts = query->ids.elts;
        if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(*ids)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->ids.nelts; i++) {
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, idselts[i]);
            if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                char *str = PQescapeIdentifier(s->conn, (const char *)value->data, value->len);
                if (!str) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQescapeIdentifier(%*.*s) and %s", value->len, value->len, value->data, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
                ngx_str_t id = {ngx_strlen(str), NULL};
                if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); PQfreemem(str); return NGX_ERROR; }
                ngx_memcpy(id.data, str, id.len);
                PQfreemem(str);
                ids[i] = id;
            }
            sql.len += ids[i].len;
        }
    }
    if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    av_alist alist;
    u_char *last = NULL;
    av_start_ptr(alist, &ngx_snprintf, u_char *, &last);
    if (av_ptr(alist, u_char *, sql.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "av_ptr"); return NGX_ERROR; }
    if (av_ulong(alist, sql.len)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "av_ulong"); return NGX_ERROR; }
    if (av_ptr(alist, char *, query->sql.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "av_ptr"); return NGX_ERROR; }
    for (ngx_uint_t i = 0; i < query->ids.nelts; i++) if (av_ptr(alist, ngx_str_t *, &ids[i])) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "av_ptr"); return NGX_ERROR; }
    if (av_call(alist)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "av_call"); return NGX_ERROR; }
    if (last != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_snprintf"); return NGX_ERROR; }
    *last = '\0';
    send->sql = sql;
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (usc && usc->save.max && usc->prepare.max && (location->prepare || query->prepare)) {
        if (!(send->stmtName.data = ngx_pnalloc(r->pool, 31 + 1))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
        u_char *last = ngx_snprintf(send->stmtName.data, 31, "ngx_%ul", (unsigned long)(send->hash = ngx_hash_key(sql.data, sql.len)));
        *last = '\0';
        send->stmtName.len = last - send->stmtName.data;
        return ngx_postgres_prepare(s);
    }
    return ngx_postgres_query(s);
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


ngx_int_t ngx_postgres_connect(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    s->handler = ngx_postgres_connect;
    switch (PQstatus(s->conn)) {
        case CONNECTION_BAD: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQstatus == CONNECTION_BAD and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQstatus == CONNECTION_OK"); goto connected;
        default: break;
    }
    switch (PQconnectPoll(s->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PGRES_POLLING_ACTIVE and %s", ngx_postgres_status(s->conn)); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PGRES_POLLING_FAILED and %s and %s", ngx_postgres_status(s->conn), PQerrorMessageMy(s->conn)); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PGRES_POLLING_OK and %s", ngx_postgres_status(s->conn)); goto connected;
        case PGRES_POLLING_READING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PGRES_POLLING_READING and %s", ngx_postgres_status(s->conn)); break;
        case PGRES_POLLING_WRITING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PGRES_POLLING_WRITING and %s", ngx_postgres_status(s->conn)); break;
    }
    return NGX_AGAIN;
connected:
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    return ngx_postgres_prepare_or_query(s);
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
