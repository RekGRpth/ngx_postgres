#include <avcall.h>
#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_send_query_handler(ngx_postgres_save_t *s);


static ngx_int_t ngx_postgres_variable_error(ngx_postgres_data_t *d) {
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = plc->query.elts;
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
    if ((value = PQcmdStatus(s->res)) && ngx_strlen(value)) { ngx_postgres_log_error(NGX_LOG_ERR, r->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), value); }
    else { ngx_postgres_log_error(NGX_LOG_ERR, r->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s", PQresStatus(PQresultStatus(s->res))); }
    ngx_postgres_variable_error(d);
    ngx_postgres_rewrite_set(d);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t ngx_postgres_result_query_handler(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = plc->query.elts;
    ngx_int_t rc = NGX_OK;
    const char *value;
    if (s->res) switch (PQresultStatus(s->res)) {
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
    if (rc != NGX_OK) return rc;
    for (d->query++; d->query < plc->query.nelts; d->query++) if (!queryelts[d->query].method || queryelts[d->query].method & r->method) break;
    s->read_handler = NULL;
    s->write_handler = ngx_postgres_send_query_handler;
    c->read->active = 0;
    c->write->active = 1;
    if (d->query < plc->query.nelts) return NGX_AGAIN;
    if (PQtransactionStatus(s->conn) == PQTRANS_IDLE) return NGX_OK;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
    ngx_postgres_query_t *query = ngx_array_push(&plc->query);
    if (!query) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
    ngx_memzero(query, sizeof(*query));
    ngx_str_set(&query->sql, "COMMIT");
    d->query++;
    return NGX_AGAIN;
}


static ngx_int_t ngx_postgres_send_query_handler(ngx_postgres_save_t *s) {
    if (PQisBusy(s->conn)) { ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "PQisBusy"); return NGX_AGAIN; }
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_send_t *send = ngx_pcalloc(r->pool, sizeof(*send));
    if (!send) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = plc->query.elts;
    ngx_postgres_query_t *query = &queryelts[d->query];
    send->sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
    ngx_str_t *ids = NULL;
    if (query->ids.nelts) {
        ngx_uint_t *idselts = query->ids.elts;
        if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(*ids)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t j = 0; j < query->ids.nelts; j++) {
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, idselts[j]);
            if (!value || !value->data || !value->len) { ngx_str_set(&ids[j], "NULL"); } else {
                char *str = PQescapeIdentifier(s->conn, (const char *)value->data, value->len);
                if (!str) { ngx_postgres_log_error(NGX_LOG_ERR, r->connection->log, 0, PQerrorMessageMy(s->conn), "!PQescapeIdentifier(%*.*s)", value->len, value->len, value->data); return NGX_ERROR; }
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
    if (query->params.nelts) {
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
    ngx_http_upstream_t *u = r->upstream;
    u->conf->connect_timeout = NGX_MAX_INT_T_VALUE;
    if (plc->timeout) {
        u->conf->connect_timeout = plc->timeout;
        if (!c->read->timer_set) ngx_add_timer(c->read, plc->timeout);
        if (!c->write->timer_set) ngx_add_timer(c->write, plc->timeout);
    }
    if (query->timeout) {
        u->conf->connect_timeout = query->timeout;
        ngx_add_timer(c->read, query->timeout);
        ngx_add_timer(c->write, query->timeout);
    }
    if (!PQsendQueryParams(s->conn, (const char *)send->sql.data, send->nParams, send->paramTypes, (const char *const *)send->paramValues, NULL, NULL, query->output.binary)) { ngx_postgres_log_error(NGX_LOG_ERR, r->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendQueryParams(\"%V\", %i)", &send->sql, send->nParams); return NGX_ERROR; }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryParams(\"%V\", %i)", &send->sql, send->nParams);
    if (query->output.handler == ngx_postgres_output_plain_handler || query->output.handler == ngx_postgres_output_csv_handler) if (query->output.single && !PQsetSingleRowMode(s->conn)) ngx_postgres_log_error(NGX_LOG_WARN, r->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsetSingleRowMode");
    s->read_handler = ngx_postgres_result_query_handler;
    s->write_handler = NULL;
    c->read->active = 1;
    c->write->active = 0;
    return NGX_AGAIN;
}


ngx_int_t ngx_postgres_send_query(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_postgres_data_t *d = c->data;
    ngx_http_request_t *r = d->request;
    if (s->connect->client_encoding) {
        const char *charset = PQparameterStatus(s->conn, "client_encoding");
        if (charset) {
            if (!ngx_strcasecmp((u_char *)charset, (u_char *)"utf8")) {
                ngx_str_set(&r->headers_out.charset, "utf-8");
            } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"windows1251")) {
                ngx_str_set(&r->headers_out.charset, "windows-1251");
            } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"koi8r")) {
                ngx_str_set(&r->headers_out.charset, "koi8-r");
            } else if (!(r->headers_out.charset.data = ngx_pnalloc(r->pool, r->headers_out.charset.len = ngx_strlen(charset)))) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc");
                return NGX_ERROR;
            } else {
                ngx_memcpy(r->headers_out.charset.data, charset, r->headers_out.charset.len);
            }
        }
    }
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *queryelts = plc->query.elts;
    for (; d->query < plc->query.nelts; d->query++) if (!queryelts[d->query].method || queryelts[d->query].method & r->method) break;
    ngx_uint_t nelts = 0;
    for (ngx_uint_t i = 0; i < plc->query.nelts; i++) nelts += queryelts[i].variable.nelts;
    if (nelts) {
        if (ngx_array_init(&d->variable, r->pool, nelts, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_memzero(d->variable.elts, nelts * d->variable.size);
        d->variable.nelts = nelts;
    }
    s->read_handler = NULL;
    s->write_handler = ngx_postgres_send_query_handler;
    return s->write_handler(s);
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
