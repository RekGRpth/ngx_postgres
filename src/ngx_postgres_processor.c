#include <postgresql/server/catalog/pg_type_d.h>
#include <avcall.h>
#include "ngx_postgres_include.h"


static ngx_int_t ngx_postgres_done(ngx_postgres_data_t *pd, ngx_int_t rc) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->timeout) {
        ngx_connection_t *c = pdc->connection;
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
    }
    if (rc == NGX_DONE) rc = ngx_postgres_output_chain(pd);
    ngx_http_upstream_finalize_request(r, u, rc);
    return NGX_DONE;
}


typedef struct {
    ngx_queue_t queue;
    ngx_uint_t hash;
} ngx_postgres_prepare_t;


static ngx_int_t ngx_postgres_query(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_connection_t *c = pdc->connection;
    if (!PQconsumeInput(pdc->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
    if (PQisBusy(pdc->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); return NGX_AGAIN; }
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *elts = location->queries.elts;
    ngx_uint_t i;
    for (i = pd->query.index; i < location->queries.nelts; i++) if (!elts[i].methods || elts[i].methods & r->method) break;
    if (i == location->queries.nelts) return NGX_HTTP_NOT_ALLOWED;
    pd->query.index = i;
    ngx_postgres_query_t *query = &elts[pd->query.index];
    if (query->timeout) {
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
    }
    ngx_postgres_upstream_srv_conf_t *pusc = pdc->pusc;
    ngx_flag_t prepare = pusc->prepare.max && (location->prepare || query->prepare);
    if (!pusc->prepare.max && (location->prepare || query->prepare)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ignoring prepare");
    if (pdc->state == state_connect || pdc->state == state_idle) {
        ngx_str_t sql;
        sql.len = query->sql.len - 2 * query->ids.nelts - query->percent;
    //    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &query->sql);
        ngx_str_t *ids = NULL;
        ngx_str_t channel = ngx_null_string;
        ngx_str_t command = ngx_null_string;
        if (query->ids.nelts) {
            ngx_uint_t *elts = query->ids.elts;
            if (!(ids = ngx_pnalloc(r->pool, query->ids.nelts * sizeof(*ids)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            for (ngx_uint_t i = 0; i < query->ids.nelts; i++) {
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, elts[i]);
                if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                    char *str = PQescapeIdentifier(pdc->conn, (const char *)value->data, value->len);
                    if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(%*.*s) and %s", value->len, value->len, value->data, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
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
        pd->query.sql = sql; /* set $postgres_query */
        if (pusc->ps.max) {
            if (query->listen && channel.data && command.data) {
                if (!pdc->listen.queue) {
                    if (!(pdc->listen.queue = ngx_pcalloc(c->pool, sizeof(ngx_queue_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                    ngx_queue_init(pdc->listen.queue);
                }
                for (ngx_queue_t *queue = ngx_queue_head(pdc->listen.queue); queue != ngx_queue_sentinel(pdc->listen.queue); queue = ngx_queue_next(queue)) {
                    ngx_postgres_listen_t *listen = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
                    if (listen->channel.len == channel.len && !ngx_strncmp(listen->channel.data, channel.data, channel.len)) goto cont;
                }
                ngx_postgres_listen_t *listen = ngx_pcalloc(c->pool, sizeof(*listen));
                if (!listen) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                listen->channel = channel;
                listen->command = command;
                ngx_queue_insert_tail(pdc->listen.queue, &listen->queue);
                cont:;
            } else if (prepare) {
                if (!(pd->query.stmtName.data = ngx_pnalloc(r->pool, 31 + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
                u_char *last = ngx_snprintf(pd->query.stmtName.data, 31, "ngx_%ul", (unsigned long)(pd->query.hash = ngx_hash_key(sql.data, sql.len)));
                *last = '\0';
                pd->query.stmtName.len = last - pd->query.stmtName.data;
            }
        }
        pdc->state = prepare ? state_prepare : state_query;
    }
    for (; (pd->result.res = PQgetResult(pdc->conn)); PQclear(pd->result.res)) {
        switch(PQresultStatus(pd->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                PQclear(pd->result.res);
                if (prepare && pdc->prepare.queue) {
                    for (ngx_queue_t *queue = ngx_queue_head(pdc->prepare.queue); queue != ngx_queue_sentinel(pdc->prepare.queue); queue = ngx_queue_next(queue)) {
                        ngx_postgres_prepare_t *prepare = ngx_queue_data(queue, ngx_postgres_prepare_t, queue);
                        if (prepare->hash == pd->query.hash) { ngx_queue_remove(queue); pdc->prepare.size--; break; }
                    }
                }
                return ngx_postgres_done(pd, NGX_HTTP_INTERNAL_SERVER_ERROR);
            default: ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(pd->result.res)), PQcmdStatus(pd->result.res)); break;
        }
        if (!PQconsumeInput(pdc->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(pdc->conn)); PQclear(pd->result.res); return NGX_ERROR; }
        if (PQisBusy(pdc->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); PQclear(pd->result.res); return NGX_AGAIN; }
    }
    ngx_int_t rc = ngx_postgres_process_notify(pdc, 0);
    if (rc != NGX_DONE) return rc;
    ngx_uint_t hash = 0;
    if (!prepare) {
        if (pd->query.nParams) {
            if (!PQsendQueryParams(pdc->conn, (const char *)pd->query.sql.data, pd->query.nParams, pd->query.paramTypes, (const char *const *)pd->query.paramValues, NULL, NULL, query->output.binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryParams(\"%V\") and %s", &pd->query.sql, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryParams(\"%V\")", &pd->query.sql);
        } else {
            if (!PQsendQuery(pdc->conn, (const char *)pd->query.sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &pd->query.sql, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &pd->query.sql);
        }
    } else switch (pdc->state) {
        case state_prepare:
            if (pdc->prepare.queue) for (ngx_queue_t *queue = ngx_queue_head(pdc->prepare.queue); queue != ngx_queue_sentinel(pdc->prepare.queue); queue = ngx_queue_next(queue)) {
                ngx_postgres_prepare_t *prepare = ngx_queue_data(queue, ngx_postgres_prepare_t, queue);
                if (prepare->hash == pd->query.hash) { hash = prepare->hash; break; }
            }
            if (hash) pdc->state = state_query; else if (pdc->prepare.size >= pusc->prepare.max && pusc->prepare.deallocate) {
                char *str = PQescapeIdentifier(pdc->conn, (const char *)pd->query.stmtName.data, pd->query.stmtName.len);
                if (!str) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQescapeIdentifier(\"%V\") and %s", &pd->query.stmtName, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
                ngx_str_t id = {ngx_strlen(str), NULL};
                if (!(id.data = ngx_pnalloc(r->pool, id.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                ngx_memcpy(id.data, str, id.len);
                ngx_str_t sql = {sizeof("DEALLOCATE PREPARE ") - 1 + id.len, NULL};
                if (!(sql.data = ngx_pnalloc(r->pool, sql.len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                u_char *last = sql.data;
                if ((last = ngx_snprintf(last, sql.len, "DEALLOCATE PREPARE %V", &id)) != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); return NGX_ERROR; }
                *last = '\0';
                if (!PQsendQuery(pdc->conn, (const char *)sql.data)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQuery(\"%V\") and %s", &sql, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQuery(\"%V\")", &sql);
                ngx_queue_t *queue = ngx_queue_head(pdc->prepare.queue);
                ngx_queue_remove(queue);
                pdc->prepare.size--;
                return NGX_AGAIN;
            } else {
                if (!PQsendPrepare(pdc->conn, (const char *)pd->query.stmtName.data, (const char *)pd->query.sql.data, pd->query.nParams, pd->query.paramTypes)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendPrepare(\"%V\", \"%V\") and %s", &pd->query.stmtName, &pd->query.sql, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendPrepare(\"%V\", \"%V\")", &pd->query.stmtName, &pd->query.sql);
                if (!pdc->prepare.queue) {
                    if (!(pdc->prepare.queue = ngx_pcalloc(c->pool, sizeof(ngx_queue_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                    ngx_queue_init(pdc->prepare.queue);
                }
                ngx_postgres_prepare_t *prepare = ngx_pcalloc(c->pool, sizeof(*prepare));
                if (!prepare) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
                prepare->hash = pd->query.hash;
                ngx_queue_insert_tail(pdc->prepare.queue, &prepare->queue);
                pdc->prepare.size++;
                pdc->state = state_query;
                return NGX_DONE;
            } // fall through
        case state_query:
            if (!PQsendQueryPrepared(pdc->conn, (const char *)pd->query.stmtName.data, pd->query.nParams, (const char *const *)pd->query.paramValues, NULL, NULL, query->output.binary)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQsendQueryPrepared(\"%V\", \"%V\") and %s", &pd->query.stmtName, &pd->query.sql, PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQsendQueryPrepared(\"%V\", \"%V\")", &pd->query.stmtName, &pd->query.sql);
            break;
        default: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pdc->state == %i", pdc->state); return NGX_ERROR;
    }
    ngx_postgres_output_t *output = &query->output;
    if (output->handler == ngx_postgres_output_plain || output->handler == ngx_postgres_output_csv) if (output->single && !PQsetSingleRowMode(pdc->conn)) ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsetSingleRowMode and %s", PQerrorMessageMy(pdc->conn));
    if (location->timeout) {
        if (!c->read->timer_set) ngx_add_timer(c->read, location->timeout);
        if (!c->write->timer_set) ngx_add_timer(c->write, location->timeout);
    } else if (query->timeout) {
        ngx_add_timer(c->read, query->timeout);
        ngx_add_timer(c->write, query->timeout);
    }
    pdc->state = state_result;
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_connect(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_common_t *pdc = &pd->common;
    switch (PQstatus(pdc->conn)) {
        case CONNECTION_AUTH_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_AUTH_OK"); break;
        case CONNECTION_AWAITING_RESPONSE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_AWAITING_RESPONSE"); break;
        case CONNECTION_BAD: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD and %s", PQerrorMessageMy(pdc->conn)); return NGX_ERROR;
        case CONNECTION_CHECK_WRITABLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_CHECK_WRITABLE"); break;
        case CONNECTION_CONSUME: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_CONSUME"); break;
        case CONNECTION_GSS_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_GSS_STARTUP"); break;
        case CONNECTION_MADE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_MADE"); break;
        case CONNECTION_NEEDED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_NEEDED"); break;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_OK"); return ngx_postgres_query(pd);
        case CONNECTION_SETENV: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_SETENV"); break;
        case CONNECTION_SSL_STARTUP: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_SSL_STARTUP"); break;
        case CONNECTION_STARTED: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQstatus == CONNECTION_STARTED"); break;
    }
again:
    switch (PQconnectPoll(pdc->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_FAILED and %s", PQerrorMessageMy(pdc->conn)); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_OK"); break;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_READING"); return NGX_AGAIN;
        case PGRES_POLLING_WRITING:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQconnectPoll == PGRES_POLLING_WRITING");
            if (PQstatus(pdc->conn) == CONNECTION_MADE) goto again;
            return NGX_AGAIN;
    }
    ngx_connection_t *c = pdc->connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    const char *charset = PQparameterStatus(pdc->conn, "client_encoding");
    if (charset) {
        if (!ngx_strcasecmp((u_char *)charset, (u_char *)"utf8")) {
            ngx_str_set(&pdc->charset, "utf-8");
        } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"windows1251")) {
            ngx_str_set(&pdc->charset, "windows-1251");
        } else if (!ngx_strcasecmp((u_char *)charset, (u_char *)"koi8r")) {
            ngx_str_set(&pdc->charset, "koi8-r");
        } else {
            pdc->charset.len = ngx_strlen(charset);
            if (!(pdc->charset.data = ngx_pnalloc(r->pool, pdc->charset.len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            ngx_memcpy(pdc->charset.data, charset, pdc->charset.len);
        }
    }
    return ngx_postgres_query(pd);
}


static ngx_int_t ngx_postgres_result(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_common_t *pdc = &pd->common;
    if (!PQconsumeInput(pdc->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(pdc->conn)); return NGX_ERROR; }
    if (PQisBusy(pdc->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); return NGX_AGAIN; }
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *elts = location->queries.elts;
    ngx_postgres_query_t *query = &elts[pd->query.index];
    if (query->timeout) {
        ngx_connection_t *c = pdc->connection;
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
    }
    ngx_int_t rc = NGX_DONE;
    const char *value;
    ngx_postgres_output_t *output = &query->output;
    for (; (pd->result.res = PQgetResult(pdc->conn)); PQclear(pd->result.res)) {
        switch (PQresultStatus(pd->result.res)) {
            case PGRES_FATAL_ERROR:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(pd->result.res));
                ngx_postgres_variable_error(pd);
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
            case PGRES_COMMAND_OK:
            case PGRES_TUPLES_OK:
                if (ngx_postgres_variable_set(pd) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_postgres_variable_set != NGX_OK");
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                } else if (output->handler && ngx_postgres_variable_output(pd) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_postgres_variable_output != NGX_OK");
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                } // fall through
            case PGRES_SINGLE_TUPLE:
                if (PQresultStatus(pd->result.res) == PGRES_SINGLE_TUPLE) pd->result.nsingle++;
                if (rc == NGX_DONE && output->handler) rc = output->handler(pd); // fall through
            default:
                if ((value = PQcmdStatus(pd->result.res)) && ngx_strlen(value)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s and %s", PQresStatus(PQresultStatus(pd->result.res)), value); }
                else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, PQresStatus(PQresultStatus(pd->result.res))); }
                break;
        }
        if (!PQconsumeInput(pdc->conn)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(pdc->conn)); PQclear(pd->result.res); return NGX_ERROR; }
        if (PQisBusy(pdc->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "PQisBusy"); PQclear(pd->result.res); return NGX_AGAIN; }
    }
    pdc->state = state_idle;
    if (rc == NGX_DONE) rc = ngx_postgres_process_notify(pdc, 0);
    if (rc == NGX_DONE && pd->query.index < location->queries.nelts - 1) {
        ngx_uint_t i;
        for (i = pd->query.index + 1; i < location->queries.nelts; i++) if (!elts[i].methods || elts[i].methods & r->method) break;
        if (i < location->queries.nelts) {
            pd->query.index = i;
            return NGX_AGAIN;
        }
    }
    if (PQtransactionStatus(pdc->conn) != PQTRANS_IDLE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
        ngx_postgres_query_t *query = location->query = ngx_array_push(&location->queries);
        if (!query) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NGX_ERROR; }
        ngx_memzero(query, sizeof(*query));
        ngx_str_set(&query->sql, "COMMIT");
        pd->query.index++;
        return NGX_AGAIN;
    }
    return ngx_postgres_done(pd, rc);
}


void ngx_postgres_process_events(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_handler_pt handler;
    switch (pdc->state) {
        case state_connect: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_connect"); handler = ngx_postgres_connect; break;
        case state_idle: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_idle"); handler = ngx_postgres_query; break;
        case state_prepare: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_prepare"); handler = ngx_postgres_query; break;
        case state_query: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_query"); handler = ngx_postgres_query; break;
        case state_result: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state == state_result"); handler = ngx_postgres_result; break;
    }
    ngx_int_t rc = handler(pd);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) return ngx_http_upstream_finalize_request(r, u, rc);
    if (rc == NGX_ERROR) return ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
    return;
}
