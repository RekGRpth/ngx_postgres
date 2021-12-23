#include <avcall.h>
#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_result_deallocate_or_prepare_or_query(ngx_postgres_save_t *s);
static ngx_int_t ngx_postgres_send_deallocate_or_prepare_or_query(ngx_postgres_save_t *s);
static ngx_int_t ngx_postgres_send_prepare(ngx_postgres_data_t *d);


static ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_query_t *query = &queryelts[d->query];
    ngx_memzero(&d->result, sizeof(d->result));
    d->result.sql = query->sql;
    const char *value;
    ngx_postgres_save_t *s = d->save;
    if ((value = PQresultErrorMessageMy(s->res)) && !d->result.error.len && (d->result.error.len = ngx_strlen(value))) {
        if (!(d->result.error.data = ngx_pnalloc(r->pool, d->result.error.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        ngx_memcpy(d->result.error.data, value, d->result.error.len);
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_error(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    const char *value;
    ngx_postgres_save_t *s = d->save;
    if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(s->res)), value, PQresultErrorMessageMy(s->res)); }
    else { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQresultErrorMessageMy(s->res)); }
    ngx_postgres_variable_error(d);
    ngx_postgres_rewrite_set(d);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t ngx_postgres_result_query(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_int_t rc = NGX_OK;
    const char *value;
    ngx_postgres_save_t *s = d->save;
    if (s->res) switch (PQresultStatus(s->res)) {
#ifdef LIBPQ_HAS_PIPELINING
        case PGRES_PIPELINE_SYNC: return NGX_AGAIN;
        case PGRES_PIPELINE_ABORTED:
#endif
        case PGRES_FATAL_ERROR: return ngx_postgres_error(d);
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
            if (PQresultStatus(s->res) == PGRES_SINGLE_TUPLE) d->result.nsingle++;
            if (rc == NGX_OK && queryelts[d->query].output.handler) rc = queryelts[d->query].output.handler(d); // fall through
        default:
            if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(s->res)), value); }
            else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(s->res))); }
            return rc;
    }
#ifdef LIBPQ_HAS_PIPELINING
    if ((s->res = PQgetResult(s->conn)) && PQresultStatus(s->res) != PGRES_PIPELINE_SYNC) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus != PGRES_PIPELINE_SYNC"); return NGX_ERROR; }
    if ((s->res = PQgetResult(s->conn))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQgetResult"); return NGX_ERROR; }
    if (!PQexitPipelineMode(s->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQexitPipelineMode and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR; }
#endif
    s->handler = ngx_postgres_send_deallocate_or_prepare_or_query;
    if (rc == NGX_OK && d->query < location->query.nelts - 1) {
        for (d->query++; d->query < location->query.nelts; d->query++) if (!queryelts[d->query].method || queryelts[d->query].method & r->method) break;
        if (d->query < location->query.nelts) return NGX_AGAIN;
    }
    if (rc == NGX_OK && PQtransactionStatus(s->conn) != PQTRANS_IDLE) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
        ngx_postgres_query_t *query = ngx_array_push(&location->query);
        if (!query) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        ngx_memzero(query, sizeof(*query));
        ngx_str_set(&query->sql, "COMMIT");
        d->query++;
        return NGX_AGAIN;
    }
    return rc;
}


static ngx_int_t ngx_postgres_send_query_prepared(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    ngx_postgres_save_t *s = d->save;
    if (!PQsendQueryPrepared(s->conn, (const char *)send->stmtName.data, send->nParams, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryPrepared(\"%V\", \"%V\", %i) and %s", &send->stmtName, &send->sql, send->nParams, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryPrepared(\"%V\", \"%V\", %i)", &send->stmtName, &send->sql, send->nParams);
    ngx_postgres_query_t *query = send->query;
    if (query->output.handler == ngx_postgres_output_plain || query->output.handler == ngx_postgres_output_csv) if (query->output.single && !PQsetSingleRowMode(s->conn)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsetSingleRowMode and %s", PQerrorMessageMy(s->conn));
    s->handler = ngx_postgres_result_deallocate_or_prepare_or_query;
    if (!send->state) send->state = state_query;
#ifdef LIBPQ_HAS_PIPELINING
    if (!PQpipelineSync(s->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQpipelineSync and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR; }
#endif
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_result_prepare(ngx_postgres_data_t *d) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    ngx_postgres_save_t *s = d->save;
    if (s->res) switch (PQresultStatus(s->res)) {
        case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); return NGX_OK;
        default: return ngx_postgres_error(d);
    }
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
#ifdef LIBPQ_HAS_PIPELINING
    send->state = state_query;
    return NGX_AGAIN;
#else
    send->state = 0;
    return ngx_postgres_send_query_prepared(d);
#endif
}


static ngx_int_t ngx_postgres_send_query(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    ngx_postgres_save_t *s = d->save;
    if (send->nParams || send->binary) {
        if (!PQsendQueryParams(s->conn, (const char *)send->sql.data, send->nParams, send->paramTypes, (const char *const *)send->paramValues, NULL, NULL, send->binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryParams(\"%V\", %i) and %s", &send->sql, send->nParams, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryParams(\"%V\", %i)", &send->sql, send->nParams);
    } else {
        if (!PQsendQuery(s->conn, (const char *)send->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &send->sql, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &send->sql);
    }
    ngx_postgres_query_t *query = send->query;
    if (query->output.handler == ngx_postgres_output_plain || query->output.handler == ngx_postgres_output_csv) if (query->output.single && !PQsetSingleRowMode(s->conn)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsetSingleRowMode and %s", PQerrorMessageMy(s->conn));
    s->handler = ngx_postgres_result_deallocate_or_prepare_or_query;
    if (!send->state) send->state = state_query;
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_result_deallocate(ngx_postgres_data_t *d) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    ngx_postgres_save_t *s = d->save;
    if (s->res) switch (PQresultStatus(s->res)) {
        case PGRES_COMMAND_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "PQresultStatus == PGRES_COMMAND_OK"); return NGX_OK;
        default: return ngx_postgres_error(d);
    }
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
#ifdef LIBPQ_HAS_PIPELINING
    send->state = state_prepare;
    return NGX_AGAIN;
#else
    send->state = 0;
    return ngx_postgres_send_prepare(d);
#endif
}


static ngx_int_t ngx_postgres_deallocate_prepare(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_save_t *s = d->save;
    queue_t *q = queue_last(&s->prepare.queue);
    queue_remove(q);
    ngx_postgres_prepare_t *prepare = queue_data(q, typeof(*prepare), queue);
    ngx_str_t stmtName;
    if (!(stmtName.data = ngx_pnalloc(r->pool, 31 + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
    u_char *last = ngx_snprintf(stmtName.data, 31, "ngx_%ul", (unsigned long)(prepare->hash));
    *last = '\0';
    stmtName.len = last - stmtName.data;
    char *str = PQescapeIdentifier(s->conn, (const char *)stmtName.data, stmtName.len);
    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(\"%V\") and %s", &stmtName, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_str_t sql = {sizeof("DEALLOCATE PREPARE ") - 1 + ngx_strlen(str), NULL};
    if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); return NGX_ERROR; }
    if ((last = ngx_snprintf(sql.data, sql.len, "DEALLOCATE PREPARE %s", str)) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); PQfreemem(str); return NGX_ERROR; }
    *last = '\0';
    PQfreemem(str);
    if (!PQsendQuery(s->conn, (const char *)sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &sql, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &sql);
    s->handler = ngx_postgres_result_deallocate_or_prepare_or_query;
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    if (!send->state) send->state = state_deallocate;
#ifdef LIBPQ_HAS_PIPELINING
    return ngx_postgres_send_prepare(d);
#else
    return NGX_AGAIN;
#endif
}


static ngx_int_t ngx_postgres_send_prepare(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    ngx_postgres_save_t *s = d->save;
    queue_each(&s->prepare.queue, q) {
        ngx_postgres_prepare_t *prepare = queue_data(q, typeof(*prepare), queue);
        if (prepare->hash == send->hash) return ngx_postgres_send_query_prepared(d);
    }
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (usc && usc->prepare.deallocate && queue_size(&s->prepare.queue) >= usc->prepare.max) return ngx_postgres_deallocate_prepare(d);
    if (!PQsendPrepare(s->conn, (const char *)send->stmtName.data, (const char *)send->sql.data, send->nParams, send->paramTypes)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendPrepare(\"%V\", \"%V\") and %s", &send->stmtName, &send->sql, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendPrepare(\"%V\", \"%V\")", &send->stmtName, &send->sql);
    ngx_postgres_prepare_t *prepare = ngx_pcalloc(s->connection->pool, sizeof(*prepare));
    if (!prepare) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    prepare->hash = send->hash;
    queue_insert_head(&s->prepare.queue, &prepare->queue);
    s->handler = ngx_postgres_result_deallocate_or_prepare_or_query;
    if (!send->state) send->state = state_prepare;
#ifdef LIBPQ_HAS_PIPELINING
    return ngx_postgres_send_query_prepared(d);
#else
    return NGX_AGAIN;
#endif
}


static ngx_int_t ngx_postgres_result_deallocate_or_prepare_or_query(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    switch (send->state) {
        case state_deallocate: return ngx_postgres_result_deallocate(d);
        case state_prepare: return ngx_postgres_result_prepare(d);
        case state_query: return ngx_postgres_result_query(d);
    }
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_charset(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_save_t *s = d->save;
    if (!s->connect->client_encoding) return NGX_OK;
    const char *charset = PQparameterStatus(s->conn, "client_encoding");
    if (!charset) return NGX_OK;
    if (!ngx_strcasecmp((u_char *)charset, (u_char *)"utf8")) {
        ngx_str_set(&r->headers_out.charset, "utf-8");
    } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"windows1251")) {
        ngx_str_set(&r->headers_out.charset, "windows-1251");
    } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"koi8r")) {
        ngx_str_set(&r->headers_out.charset, "koi8-r");
    } else if (!(r->headers_out.charset.data = ngx_pnalloc(r->pool, r->headers_out.charset.len = ngx_strlen(charset)))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc");
        return NGX_ERROR;
    } else {
        ngx_memcpy(r->headers_out.charset.data, charset, r->headers_out.charset.len);
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_send_deallocate_or_prepare_or_query(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    u->conf->connect_timeout = NGX_MAX_INT_T_VALUE;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->timeout) {
        u->conf->connect_timeout = location->timeout;
        if (!c->read->timer_set) ngx_add_timer(c->read, location->timeout);
        if (!c->write->timer_set) ngx_add_timer(c->write, location->timeout);
    }
    while (PQstatus(s->conn) == CONNECTION_OK && (s->res = PQgetResult(s->conn))) {
        switch (PQresultStatus(s->res)) {
#ifdef LIBPQ_HAS_PIPELINING
            case PGRES_PIPELINE_ABORTED:
#endif
            case PGRES_FATAL_ERROR: if (d->catch) { PQclear(s->res); return ngx_postgres_error(d); } ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQresultErrorMessageMy(s->res)); break;
            default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQcmdStatus(s->res)); break;
        }
        PQclear(s->res);
        switch (ngx_postgres_consume_flush_busy(s)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    d->catch = 1;
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_postgres_send_t *send = &sendelts[d->query];
    ngx_postgres_query_t *query = send->query;
    if (query->timeout) {
        u->conf->connect_timeout = query->timeout;
        ngx_add_timer(c->read, query->timeout);
        ngx_add_timer(c->write, query->timeout);
    }
#ifdef LIBPQ_HAS_PIPELINING
    if (send->hash && !PQenterPipelineMode(s->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQenterPipelineMode and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR; }
#endif
    return send->hash ? ngx_postgres_send_prepare(d) : ngx_postgres_send_query(d);
}


ngx_int_t ngx_postgres_send(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!r->headers_out.charset.data && ngx_postgres_charset(d) == NGX_ERROR) return NGX_ERROR;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = location->query.elts;
    for (; d->query < location->query.nelts; d->query++) if (!queryelts[d->query].method || queryelts[d->query].method & r->method) break;
    if (ngx_array_init(&d->send, r->pool, location->query.nelts, sizeof(ngx_postgres_send_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
    d->send.nelts = location->query.nelts;
    ngx_memzero(d->send.elts, d->send.nelts * d->send.size);
    ngx_postgres_send_t *sendelts = d->send.elts;
    ngx_uint_t nelts = 0;
    ngx_postgres_save_t *s = d->save;
    for (ngx_uint_t i = 0; i < location->query.nelts; i++) {
        ngx_postgres_query_t *query = &queryelts[i];
        ngx_postgres_send_t *send = &sendelts[i];
        send->query = query;
        nelts += query->variable.nelts;
        if (!query->method || query->method & r->method); else continue;
        send->binary = query->output.binary;
        send->sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
        ngx_str_t *ids = NULL;
        if (query->ids.nelts) {
            ngx_uint_t *idselts = query->ids.elts;
            if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(*ids)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            for (ngx_uint_t j = 0; j < query->ids.nelts; j++) {
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, idselts[j]);
                if (!value || !value->data || !value->len) { ngx_str_set(&ids[j], "NULL"); } else {
                    char *str = PQescapeIdentifier(s->conn, (const char *)value->data, value->len);
                    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(%*.*s) and %s", value->len, value->len, value->data, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
                    ngx_str_t id = {ngx_strlen(str), NULL};
                    if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); return NGX_ERROR; }
                    ngx_memcpy(id.data, str, id.len);
                    PQfreemem(str);
                    ids[j] = id;
                }
                send->sql.len += ids[j].len;
            }
        }
        if (!(send->sql.data = ngx_pnalloc(r->pool, send->sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        av_alist alist;
        u_char *last = NULL;
        av_start_ptr(alist, &ngx_snprintf, u_char *, &last);
        if (av_ptr(alist, u_char *, send->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        if (av_ulong(alist, send->sql.len)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ulong"); return NGX_ERROR; }
        if (av_ptr(alist, char *, query->sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        for (ngx_uint_t j = 0; j < query->ids.nelts; j++) if (av_ptr(alist, ngx_str_t *, &ids[j])) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
        if (av_call(alist)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_call"); return NGX_ERROR; }
        if (last != send->sql.data + send->sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); return NGX_ERROR; }
        *last = '\0';
        if (s->usc && s->usc->save.max && s->usc->prepare.max && (location->prepare || query->prepare)) {
            send->hash = query->hash;
            send->stmtName = query->stmtName;
        }
        if (!query->params.nelts) continue;
        ngx_postgres_param_t *param = query->params.elts;
        send->nParams = query->params.nelts;
        if (!(send->paramTypes = ngx_pnalloc(r->pool, query->params.nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (!(send->paramValues = ngx_pnalloc(r->pool, query->params.nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t j = 0; j < query->params.nelts; j++) {
            send->paramTypes[j] = param[j].oid;
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[j].index);
            if (!value || !value->data || !value->len) send->paramValues[j] = NULL; else {
                if (!(send->paramValues[j] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                (void)ngx_cpystrn(send->paramValues[j], value->data, value->len + 1);
            }
        }
    }
    if (nelts) {
        if (ngx_array_init(&d->variable, r->pool, nelts, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_memzero(d->variable.elts, nelts * d->variable.size);
        d->variable.nelts = nelts;
    }
    s->handler = ngx_postgres_send_deallocate_or_prepare_or_query;
    return ngx_postgres_send_deallocate_or_prepare_or_query(s);
}


ngx_int_t ngx_postgres_connect(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    switch (PQstatus(s->conn)) {
        case CONNECTION_BAD: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_OK"); goto connected;
        default: break;
    }
    switch (PQconnectPoll(s->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PGRES_POLLING_FAILED and %s", PQerrorMessageMy(s->conn)); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_OK"); goto connected;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_READING"); break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PGRES_POLLING_WRITING"); break;
    }
    return NGX_AGAIN;
connected:
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    return ngx_postgres_send(d);
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
