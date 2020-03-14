/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <postgresql/server/catalog/pg_type_d.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static void ngx_postgres_idle_to_free(ngx_postgres_data_t *pd, ngx_postgres_save_t *ps) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_peer_connection_t *pc = &r->upstream->peer;
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    pd->common = ps->common;
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_tail(&ps->common.server->free, &ps->queue);
    pc->cached = 1;
    pc->connection = pd->common.connection;
    pc->connection->idle = 0;
//    pc->connection->log = pc->log;
//    pc->connection->read->log = pc->log;
//    pc->connection->write->log = pc->log;
    pc->name = pd->common.name;
    pc->sockaddr = pd->common.sockaddr;
    pc->socklen = pd->common.socklen;
}


static ngx_int_t ngx_postgres_peer_single(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (ngx_queue_empty(&pd->common.server->idle)) return NGX_DECLINED;
    ngx_queue_t *queue = ngx_queue_head(&pd->common.server->idle);
    ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    ngx_postgres_idle_to_free(pd, ps);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_peer_multi(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    for (ngx_queue_t *queue = ngx_queue_head(&pd->common.server->idle); queue != ngx_queue_sentinel(&pd->common.server->idle); queue = ngx_queue_next(queue)) {
        ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ngx_memn2cmp((u_char *)pd->common.sockaddr, (u_char *)ps->common.sockaddr, pd->common.socklen, ps->common.socklen)) continue;
        ngx_postgres_idle_to_free(pd, ps);
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


static ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_postgres_data_t *pd = data;
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    pd->failed = 0;
    if (pd->common.server->max_save && pd->common.server->single && ngx_postgres_peer_single(pd) != NGX_DECLINED) { ngx_postgres_process_events(r); return NGX_AGAIN; }
    ngx_queue_t *queue = ngx_queue_head(&pd->common.server->peer);
    ngx_postgres_peer_t *peer = ngx_queue_data(queue, ngx_postgres_peer_t, queue);
    ngx_queue_remove(&peer->queue);
    ngx_queue_insert_tail(&pd->common.server->peer, &peer->queue);
    pc->cached = 0;
//    pc->name = peer->name;
//    pc->sockaddr = peer->sockaddr;
//    pc->socklen = peer->socklen;
    pd->common.name = peer->name;
    pd->common.sockaddr = peer->sockaddr;
    pd->common.socklen = peer->socklen;
    if (pd->common.server->max_save && !pd->common.server->single && ngx_postgres_peer_multi(pd) != NGX_DECLINED) { ngx_postgres_process_events(r); return NGX_AGAIN; }
    if (!pd->common.server->ignore && pd->common.server->save >= pd->common.server->max_save) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "max_save"); return NGX_DECLINED; }
    const char *host = peer->values[0];
    peer->values[0] = (const char *)peer->value;
    const char *options = peer->values[2];
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->output.append) {
        size_t len = options ? ngx_strlen(options) : 0;
        u_char *buf = ngx_pnalloc(r->pool, len + (len ? 1 : 0) + sizeof("-c config.append_type_to_column_name=true") - 1 + 1);
        if (!buf) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_DECLINED; }
        u_char *p = buf;
        if (options) {
            p = ngx_copy(p, options, len);
            *p++ = ' ';
        }
        p = ngx_copy(p, "-c config.append_type_to_column_name=true", sizeof("-c config.append_type_to_column_name=true") - 1);
        *p = '\0';
        peer->values[2] = (const char *)buf;
    }
    pd->common.conn = PQconnectStartParams(peer->keywords, peer->values, 0); /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    peer->values[0] = host;
    peer->values[2] = options;
    if (PQstatus(pd->common.conn) == CONNECTION_BAD || PQsetnonblocking(pd->common.conn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD or PQsetnonblocking == -1 and %s in upstream \"%V\"", PQerrorMessageMy(pd->common.conn), peer->name);
        PQfinish(pd->common.conn);
        pd->common.conn = NULL;
        return NGX_DECLINED;
    }
//    PQtrace(pd->common.conn, stderr);
    pd->common.server->save++; /* take spot in keepalive connection pool */
    int fd;
    if ((fd = PQsocket(pd->common.conn)) == -1) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQsocket == -1"); goto invalid; }
    if (!(pd->common.connection = ngx_get_connection(fd, pc->log))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_get_connection"); goto invalid; }
    pd->common.connection->log = pc->log;
    pd->common.connection->log_error = pc->log_error;
    pd->common.connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    pd->common.connection->read->log = pc->log;
    pd->common.connection->write->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(pd->common.connection) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_conn != NGX_OK"); goto invalid; }
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (ngx_add_event(pd->common.connection->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
        if (ngx_add_event(pd->common.connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (ngx_add_event(pd->common.connection->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
        if (ngx_add_event(pd->common.connection->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
    } else goto bad_add;
    pd->common.state = state_db_connect;
    pc->connection = pd->common.connection;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_event_flags not NGX_USE_RTSIG_EVENT or NGX_USE_CLEAR_EVENT or NGX_USE_LEVEL_EVENT");
invalid:
    ngx_postgres_free_connection(&pd->common, 0);
    return NGX_ERROR;
}


static void ngx_postgres_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
}


static void ngx_postgres_process_notify(ngx_postgres_common_t *common) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "%s", __func__);
    for (PGnotify *notify; (notify = PQnotifies(common->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "notify: relname=\"%s\", extra=\"%s\", be_pid=%i.", notify->relname, notify->extra, notify->be_pid);
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(8192, common->connection->log);
        if (!temp_pool) continue;
        switch (ngx_http_push_stream_add_msg_to_channel_my(common->connection->log, &id, &text, NULL, NULL, 0, temp_pool)) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_WARN, common->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
            case NGX_DECLINED:
                ngx_log_error(NGX_LOG_WARN, common->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED");
                char *str = PQescapeIdentifier(common->conn, (const char *)id.data, id.len);
                if (!str) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "!PQescapeIdentifier(%V) and %s", id, PQerrorMessageMy(common->conn)); break; }
                ngx_str_t channel = {ngx_strlen(str), (u_char *)str};
                u_char *command = ngx_pnalloc(temp_pool, sizeof("BEGIN;\nUNLISTEN ;\nCOMMIT;\nSELECT pg_listening_channels()") - 1 + channel.len + 1);
                if (!command) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); break; }
                u_char *last = ngx_snprintf(command, sizeof("BEGIN;\nUNLISTEN ;\nCOMMIT;\nSELECT pg_listening_channels()") - 1 + channel.len, "BEGIN;\nUNLISTEN %V;\nCOMMIT;\nSELECT pg_listening_channels()", &channel);
                PQfreemem(str);
                if (last != command + sizeof("BEGIN;\nUNLISTEN ;\nCOMMIT;\nSELECT pg_listening_channels()") - 1 + channel.len) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "ngx_snprintf"); break; }
                *last = '\0';
                if (!PQsendQuery(common->conn, (const char *)command)) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "!PQsendQuery and %s", PQerrorMessageMy(common->conn)); break; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "%s sent successfully", command);
                common->state = state_db_listen;
                ngx_destroy_pool(temp_pool);
                return;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "notify ok"); break;
            default: ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == unknown"); break;
        }
        ngx_destroy_pool(temp_pool);
    }
}


typedef struct {
    ngx_str_t channel;
    ngx_str_t command;
} ngx_postgres_listen_t;


static void ngx_postgres_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    if (c->close) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "c->close"); goto close; }
    if (!PQconsumeInput(ps->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(ps->common.conn)); goto close; }
    if (PQisBusy(ps->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "PQisBusy"); goto close; }
    for (PGresult *res; (res = PQgetResult(ps->common.conn)); PQclear(res)) switch(PQresultStatus(res)) {
        case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, ev->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
        case PGRES_TUPLES_OK:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PQresultStatus == PGRES_TUPLES_OK");
            if (ps->common.state == state_db_listen) {
                if (ps->common.listen) ngx_array_destroy(ps->common.listen);
                if (!PQntuples(res) || !PQnfields(res)) ps->common.listen = NULL; else
                if (!(ps->common.listen = ngx_array_create(ps->common.connection->pool, PQntuples(res), sizeof(ngx_postgres_listen_t)))) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!ngx_array_create"); break; }
                for (int row = 0; row < PQntuples(res); row++) {
                    if (PQgetisnull(res, row, 0)) continue;
                    ngx_postgres_listen_t *listen = ngx_array_push(ps->common.listen);
                    if (!listen) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!ngx_array_push"); continue; }
                    ngx_memzero(listen, sizeof(ngx_str_t));
                    listen->channel.len = PQgetlength(res, row, 0);
                    if (!(listen->channel.data = ngx_pnalloc(ps->common.connection->pool, listen->channel.len))) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!ngx_pnalloc"); continue; }
                    ngx_memcpy(listen->channel.data, (u_char *)PQgetvalue(res, row, 0), listen->channel.len);
                    char *str = PQescapeIdentifier(ps->common.conn, (const char *)listen->channel.data, listen->channel.len);
                    if (!str) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!PQescapeIdentifier(%V) and %s", &listen->channel, PQerrorMessageMy(ps->common.conn)); continue; }
                    ngx_str_t channel = {ngx_strlen(str), (u_char *)str};
                    listen->command.len = channel.len + sizeof("LISTEN ") - 1;
                    if (!(listen->command.data = ngx_pnalloc(ps->common.connection->pool, listen->command.len))) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!ngx_pnalloc"); PQfreemem(str); continue; }
                    listen->command.len = ngx_snprintf(listen->command.data, listen->command.len, "LISTEN %V", &channel) - listen->command.data;
                    PQfreemem(str);
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%V", &listen->command);
                }
                ps->common.state = state_db_idle;
            }
            break;
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PQresultStatus == %s", PQresStatus(PQresultStatus(res))); break;
    }
    ngx_postgres_process_notify(&ps->common);
    return;
close:
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    ngx_postgres_free_connection(&ps->common, 0);
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_tail(&ps->common.server->free, &ps->queue);
}


static void ngx_postgres_timeout(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    ngx_postgres_free_connection(&ps->common, 1);
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_tail(&ps->common.server->free, &ps->queue);
}


static u_char *ngx_postgres_listen(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_postgres_common_t *common = &pd->common;
    u_char *listen = (u_char *)"SELECT pg_listening_channels()";
    if (!common || !common->listen || !common->listen->nelts) return listen;
    ngx_postgres_listen_t *elts = common->listen->elts;
    size_t len = sizeof("BEGIN;\nCOMMIT;\nSELECT pg_listening_channels()") - 1;
    for (ngx_uint_t i = 0; i < common->listen->nelts; i++) len += elts[i].command.len + sizeof(";\n") - 1;
    if (!(listen = ngx_pnalloc(r->pool, len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return (u_char *)"SELECT pg_listening_channels()"; }
    u_char *p = listen;
    p = ngx_cpymem(p, "BEGIN;\n", sizeof("BEGIN;\n") - 1);
    for (ngx_uint_t i = 0; i < common->listen->nelts; i++) {
        p = ngx_cpymem(p, elts[i].command.data, elts[i].command.len);
        *p++ = ';';
        *p++ = '\n';
    }
    p = ngx_cpymem(p, "COMMIT;\n", sizeof("COMMIT;\n") - 1);
    p = ngx_cpymem(p, "SELECT pg_listening_channels()", sizeof("SELECT pg_listening_channels()") - 1);
    *p = '\0';
    return listen;
}


static void ngx_postgres_free_peer(ngx_postgres_data_t *pd) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_peer_connection_t *pc = &r->upstream->peer;
    ngx_postgres_common_t *common = &pd->common;
    if (pd->failed || !common || !common->connection || r->upstream->headers_in.status_n != NGX_HTTP_OK) return;
    if (common->connection->read->timer_set) ngx_del_timer(common->connection->read);
    if (common->connection->write->timer_set) ngx_del_timer(common->connection->write);
    if (common->connection->write->active && ngx_event_flags & NGX_USE_LEVEL_EVENT && ngx_del_event(common->connection->write, NGX_WRITE_EVENT, 0) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_del_event != NGX_OK"); return; }
    if (common->server->max_requests && ++common->requests > common->server->max_requests) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "max_requests"); return; }
    ngx_postgres_save_t *ps;
    if (ngx_queue_empty(&common->server->free)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_queue_empty");
        ngx_queue_t *queue = ngx_queue_head(&common->server->idle);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
        ngx_postgres_free_connection(&ps->common, 1);
    } else {
        ngx_queue_t *queue = ngx_queue_head(&common->server->free);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    }
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_tail(&common->server->idle, &ps->queue);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "free keepalive peer: saving connection %p", common->connection);
    pc->connection = NULL;
    ps->common = pd->common;
    common->connection->data = ps;
    common->connection->idle = 1;
    common->connection->read->handler = ngx_postgres_read_handler;
    common->connection->write->handler = ngx_postgres_write_handler;
    if (common->server->timeout) {
        ps->timeout.log = ngx_cycle->log;
        ps->timeout.data = common->connection;
        ps->timeout.handler = ngx_postgres_timeout;
        ngx_add_timer(&ps->timeout, common->server->timeout);
    }
    u_char *listen = ngx_postgres_listen(pd);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "listen = %s", listen);
    if (!PQsendQuery(common->conn, (const char *)listen)) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsendQuery and %s", PQerrorMessageMy(common->conn)); }
    else common->state = state_db_listen;
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    if (state & NGX_PEER_FAILED) pd->failed = 1;
    if (pd->common.server->max_save) ngx_postgres_free_peer(pd);
    if (pc->connection) ngx_postgres_free_connection(&pd->common, 1);
}


typedef struct {
    ngx_uint_t index;
    ngx_uint_t oid;
} ngx_postgres_param_t;


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = ngx_pcalloc(r->pool, sizeof(ngx_postgres_data_t));
    if (!pd) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    pd->common.server = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    pd->request = r;
    r->upstream->peer.data = pd;
    r->upstream->peer.get = ngx_postgres_peer_get;
    r->upstream->peer.free = ngx_postgres_peer_free;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location->query;
    if (query->params->nelts) {
        ngx_postgres_param_t *param = query->params->elts;
        pd->nParams = query->params->nelts;
        if (!(pd->paramTypes = ngx_pnalloc(r->pool, query->params->nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (!(pd->paramValues = ngx_pnalloc(r->pool, query->params->nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->params->nelts; i++) {
            pd->paramTypes[i] = param[i].oid;
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[i].index);
            if (!value || !value->data || !value->len) pd->paramValues[i] = NULL; else {
                if (!(pd->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                (void) ngx_cpystrn(pd->paramValues[i], value->data, value->len + 1);
            }
        }
    }
    pd->resultFormat = location->output.binary;
    if (location->variables) {
        if (!(pd->variables = ngx_array_create(r->pool, location->variables->nelts, sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NGX_ERROR; }
        pd->variables->nelts = location->variables->nelts;
        ngx_memzero(pd->variables->elts, pd->variables->nelts * pd->variables->size); /* fake ngx_array_push'ing */
    }
    return NGX_OK;
}


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *pc) {
    return (pc->get == ngx_postgres_peer_get);
}


void ngx_postgres_free_connection(ngx_postgres_common_t *common, ngx_flag_t delete) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "%s", __func__);
    common->server->save--; /* free spot in keepalive connection pool */
    if (!common->connection) {
        if (common->conn) {
            PQfinish(common->conn);
            common->conn = NULL;
        }
        return;
    }
    if (common->conn) {
        if (/*delete && */!common->connection->close && common->listen) {
            ngx_str_t *elts = common->listen->elts;
            for (ngx_uint_t i = 0; i < common->listen->nelts; i++) {
                ngx_log_error(NGX_LOG_INFO, common->connection->log, 0, "delete channel = %V", &elts[i]);
                ngx_http_push_stream_delete_channel_my(common->connection->log, &elts[i], (u_char *)"channel unlisten", sizeof("channel unlisten") - 1, common->connection->pool);
            }
        }
        PQfinish(common->conn);
        common->conn = NULL;
    }
    if (common->connection->read->timer_set) ngx_del_timer(common->connection->read);
    if (common->connection->write->timer_set) ngx_del_timer(common->connection->write);
    if (ngx_del_conn) ngx_del_conn(common->connection, NGX_CLOSE_EVENT); else {
        if (common->connection->read->active || common->connection->read->disabled) ngx_del_event(common->connection->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        if (common->connection->write->active || common->connection->write->disabled) ngx_del_event(common->connection->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
    }
    if (common->connection->read->posted) { ngx_delete_posted_event(common->connection->read); }
    if (common->connection->write->posted) { ngx_delete_posted_event(common->connection->write); }
    common->connection->read->closed = 1;
    common->connection->write->closed = 1;
    if (common->connection->pool && !common->connection->close) {
        ngx_destroy_pool(common->connection->pool);
        common->connection->pool = NULL;
    }
    ngx_free_connection(common->connection);
    common->connection->fd = (ngx_socket_t) -1;
    common->connection = NULL;
}


static ngx_flag_t is_variable_character(u_char p) {
    return ((p >= '0' && p <= '9') || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || p == '_');
}


#define IDOID 9999


ngx_conf_enum_t ngx_postgres_oids[] = {
    { ngx_string("IDOID"), IDOID },
    { ngx_string("BOOLOID"), BOOLOID },
    { ngx_string("BYTEAOID"), BYTEAOID },
    { ngx_string("CHAROID"), CHAROID },
    { ngx_string("NAMEOID"), NAMEOID },
    { ngx_string("INT8OID"), INT8OID },
    { ngx_string("INT2OID"), INT2OID },
    { ngx_string("INT2VECTOROID"), INT2VECTOROID },
    { ngx_string("INT4OID"), INT4OID },
    { ngx_string("REGPROCOID"), REGPROCOID },
    { ngx_string("TEXTOID"), TEXTOID },
    { ngx_string("OIDOID"), OIDOID },
    { ngx_string("TIDOID"), TIDOID },
    { ngx_string("XIDOID"), XIDOID },
    { ngx_string("CIDOID"), CIDOID },
    { ngx_string("OIDVECTOROID"), OIDVECTOROID },
    { ngx_string("JSONOID"), JSONOID },
    { ngx_string("XMLOID"), XMLOID },
    { ngx_string("PGNODETREEOID"), PGNODETREEOID },
    { ngx_string("PGNDISTINCTOID"), PGNDISTINCTOID },
    { ngx_string("PGDEPENDENCIESOID"), PGDEPENDENCIESOID },
    { ngx_string("PGMCVLISTOID"), PGMCVLISTOID },
    { ngx_string("PGDDLCOMMANDOID"), PGDDLCOMMANDOID },
    { ngx_string("POINTOID"), POINTOID },
    { ngx_string("LSEGOID"), LSEGOID },
    { ngx_string("PATHOID"), PATHOID },
    { ngx_string("BOXOID"), BOXOID },
    { ngx_string("POLYGONOID"), POLYGONOID },
    { ngx_string("LINEOID"), LINEOID },
    { ngx_string("FLOAT4OID"), FLOAT4OID },
    { ngx_string("FLOAT8OID"), FLOAT8OID },
    { ngx_string("UNKNOWNOID"), UNKNOWNOID },
    { ngx_string("CIRCLEOID"), CIRCLEOID },
    { ngx_string("CASHOID"), CASHOID },
    { ngx_string("MACADDROID"), MACADDROID },
    { ngx_string("INETOID"), INETOID },
    { ngx_string("CIDROID"), CIDROID },
    { ngx_string("MACADDR8OID"), MACADDR8OID },
    { ngx_string("ACLITEMOID"), ACLITEMOID },
    { ngx_string("BPCHAROID"), BPCHAROID },
    { ngx_string("VARCHAROID"), VARCHAROID },
    { ngx_string("DATEOID"), DATEOID },
    { ngx_string("TIMEOID"), TIMEOID },
    { ngx_string("TIMESTAMPOID"), TIMESTAMPOID },
    { ngx_string("TIMESTAMPTZOID"), TIMESTAMPTZOID },
    { ngx_string("INTERVALOID"), INTERVALOID },
    { ngx_string("TIMETZOID"), TIMETZOID },
    { ngx_string("BITOID"), BITOID },
    { ngx_string("VARBITOID"), VARBITOID },
    { ngx_string("NUMERICOID"), NUMERICOID },
    { ngx_string("REFCURSOROID"), REFCURSOROID },
    { ngx_string("REGPROCEDUREOID"), REGPROCEDUREOID },
    { ngx_string("REGOPEROID"), REGOPEROID },
    { ngx_string("REGOPERATOROID"), REGOPERATOROID },
    { ngx_string("REGCLASSOID"), REGCLASSOID },
    { ngx_string("REGTYPEOID"), REGTYPEOID },
    { ngx_string("REGROLEOID"), REGROLEOID },
    { ngx_string("REGNAMESPACEOID"), REGNAMESPACEOID },
    { ngx_string("UUIDOID"), UUIDOID },
    { ngx_string("LSNOID"), LSNOID },
    { ngx_string("TSVECTOROID"), TSVECTOROID },
    { ngx_string("GTSVECTOROID"), GTSVECTOROID },
    { ngx_string("TSQUERYOID"), TSQUERYOID },
    { ngx_string("REGCONFIGOID"), REGCONFIGOID },
    { ngx_string("REGDICTIONARYOID"), REGDICTIONARYOID },
    { ngx_string("JSONBOID"), JSONBOID },
    { ngx_string("JSONPATHOID"), JSONPATHOID },
    { ngx_string("TXID_SNAPSHOTOID"), TXID_SNAPSHOTOID },
    { ngx_string("INT4RANGEOID"), INT4RANGEOID },
    { ngx_string("NUMRANGEOID"), NUMRANGEOID },
    { ngx_string("TSRANGEOID"), TSRANGEOID },
    { ngx_string("TSTZRANGEOID"), TSTZRANGEOID },
    { ngx_string("DATERANGEOID"), DATERANGEOID },
    { ngx_string("INT8RANGEOID"), INT8RANGEOID },
    { ngx_string("RECORDOID"), RECORDOID },
    { ngx_string("RECORDARRAYOID"), RECORDARRAYOID },
    { ngx_string("CSTRINGOID"), CSTRINGOID },
    { ngx_string("ANYOID"), ANYOID },
    { ngx_string("ANYARRAYOID"), ANYARRAYOID },
    { ngx_string("VOIDOID"), VOIDOID },
    { ngx_string("TRIGGEROID"), TRIGGEROID },
    { ngx_string("EVTTRIGGEROID"), EVTTRIGGEROID },
    { ngx_string("LANGUAGE_HANDLEROID"), LANGUAGE_HANDLEROID },
    { ngx_string("INTERNALOID"), INTERNALOID },
    { ngx_string("OPAQUEOID"), OPAQUEOID },
    { ngx_string("ANYELEMENTOID"), ANYELEMENTOID },
    { ngx_string("ANYNONARRAYOID"), ANYNONARRAYOID },
    { ngx_string("ANYENUMOID"), ANYENUMOID },
    { ngx_string("FDW_HANDLEROID"), FDW_HANDLEROID },
    { ngx_string("INDEX_AM_HANDLEROID"), INDEX_AM_HANDLEROID },
    { ngx_string("TSM_HANDLEROID"), TSM_HANDLEROID },
    { ngx_string("TABLE_AM_HANDLEROID"), TABLE_AM_HANDLEROID },
    { ngx_string("ANYRANGEOID"), ANYRANGEOID },
    { ngx_string("BOOLARRAYOID"), BOOLARRAYOID },
    { ngx_string("BYTEAARRAYOID"), BYTEAARRAYOID },
    { ngx_string("CHARARRAYOID"), CHARARRAYOID },
    { ngx_string("NAMEARRAYOID"), NAMEARRAYOID },
    { ngx_string("INT8ARRAYOID"), INT8ARRAYOID },
    { ngx_string("INT2ARRAYOID"), INT2ARRAYOID },
    { ngx_string("INT2VECTORARRAYOID"), INT2VECTORARRAYOID },
    { ngx_string("INT4ARRAYOID"), INT4ARRAYOID },
    { ngx_string("REGPROCARRAYOID"), REGPROCARRAYOID },
    { ngx_string("TEXTARRAYOID"), TEXTARRAYOID },
    { ngx_string("OIDARRAYOID"), OIDARRAYOID },
    { ngx_string("TIDARRAYOID"), TIDARRAYOID },
    { ngx_string("XIDARRAYOID"), XIDARRAYOID },
    { ngx_string("CIDARRAYOID"), CIDARRAYOID },
    { ngx_string("OIDVECTORARRAYOID"), OIDVECTORARRAYOID },
    { ngx_string("JSONARRAYOID"), JSONARRAYOID },
    { ngx_string("XMLARRAYOID"), XMLARRAYOID },
    { ngx_string("POINTARRAYOID"), POINTARRAYOID },
    { ngx_string("LSEGARRAYOID"), LSEGARRAYOID },
    { ngx_string("PATHARRAYOID"), PATHARRAYOID },
    { ngx_string("BOXARRAYOID"), BOXARRAYOID },
    { ngx_string("POLYGONARRAYOID"), POLYGONARRAYOID },
    { ngx_string("LINEARRAYOID"), LINEARRAYOID },
    { ngx_string("FLOAT4ARRAYOID"), FLOAT4ARRAYOID },
    { ngx_string("FLOAT8ARRAYOID"), FLOAT8ARRAYOID },
    { ngx_string("CIRCLEARRAYOID"), CIRCLEARRAYOID },
    { ngx_string("MONEYARRAYOID"), MONEYARRAYOID },
    { ngx_string("MACADDRARRAYOID"), MACADDRARRAYOID },
    { ngx_string("INETARRAYOID"), INETARRAYOID },
    { ngx_string("CIDRARRAYOID"), CIDRARRAYOID },
    { ngx_string("MACADDR8ARRAYOID"), MACADDR8ARRAYOID },
    { ngx_string("ACLITEMARRAYOID"), ACLITEMARRAYOID },
    { ngx_string("BPCHARARRAYOID"), BPCHARARRAYOID },
    { ngx_string("VARCHARARRAYOID"), VARCHARARRAYOID },
    { ngx_string("DATEARRAYOID"), DATEARRAYOID },
    { ngx_string("TIMEARRAYOID"), TIMEARRAYOID },
    { ngx_string("TIMESTAMPARRAYOID"), TIMESTAMPARRAYOID },
    { ngx_string("TIMESTAMPTZARRAYOID"), TIMESTAMPTZARRAYOID },
    { ngx_string("INTERVALARRAYOID"), INTERVALARRAYOID },
    { ngx_string("TIMETZARRAYOID"), TIMETZARRAYOID },
    { ngx_string("BITARRAYOID"), BITARRAYOID },
    { ngx_string("VARBITARRAYOID"), VARBITARRAYOID },
    { ngx_string("NUMERICARRAYOID"), NUMERICARRAYOID },
    { ngx_string("REFCURSORARRAYOID"), REFCURSORARRAYOID },
    { ngx_string("REGPROCEDUREARRAYOID"), REGPROCEDUREARRAYOID },
    { ngx_string("REGOPERARRAYOID"), REGOPERARRAYOID },
    { ngx_string("REGOPERATORARRAYOID"), REGOPERATORARRAYOID },
    { ngx_string("REGCLASSARRAYOID"), REGCLASSARRAYOID },
    { ngx_string("REGTYPEARRAYOID"), REGTYPEARRAYOID },
    { ngx_string("REGROLEARRAYOID"), REGROLEARRAYOID },
    { ngx_string("REGNAMESPACEARRAYOID"), REGNAMESPACEARRAYOID },
    { ngx_string("UUIDARRAYOID"), UUIDARRAYOID },
    { ngx_string("PG_LSNARRAYOID"), PG_LSNARRAYOID },
    { ngx_string("TSVECTORARRAYOID"), TSVECTORARRAYOID },
    { ngx_string("GTSVECTORARRAYOID"), GTSVECTORARRAYOID },
    { ngx_string("TSQUERYARRAYOID"), TSQUERYARRAYOID },
    { ngx_string("REGCONFIGARRAYOID"), REGCONFIGARRAYOID },
    { ngx_string("REGDICTIONARYARRAYOID"), REGDICTIONARYARRAYOID },
    { ngx_string("JSONBARRAYOID"), JSONBARRAYOID },
    { ngx_string("JSONPATHARRAYOID"), JSONPATHARRAYOID },
    { ngx_string("TXID_SNAPSHOTARRAYOID"), TXID_SNAPSHOTARRAYOID },
    { ngx_string("INT4RANGEARRAYOID"), INT4RANGEARRAYOID },
    { ngx_string("NUMRANGEARRAYOID"), NUMRANGEARRAYOID },
    { ngx_string("TSRANGEARRAYOID"), TSRANGEARRAYOID },
    { ngx_string("TSTZRANGEARRAYOID"), TSTZRANGEARRAYOID },
    { ngx_string("DATERANGEARRAYOID"), DATERANGEARRAYOID },
    { ngx_string("INT8RANGEARRAYOID"), INT8RANGEARRAYOID },
    { ngx_string("CSTRINGARRAYOID"), CSTRINGARRAYOID },
    { ngx_null_string, 0 }
};


static ngx_uint_t type2oid(ngx_str_t *type) {
    ngx_conf_enum_t *e = ngx_postgres_oids;
    for (ngx_uint_t i = 0; e[i].name.len; i++) if (e[i].name.len - 3 == type->len && !ngx_strncasecmp(e[i].name.data, type->data, type->len)) return e[i].value;
    return 0;
}


char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    ngx_str_t sql = elts[cf->args->nelts - 1];
    if (!sql.len) return "empty query";
    ngx_postgres_location_t *location = conf;
    if (location->query) return "is duplicate";
    if (!(location->query = ngx_palloc(cf->pool, sizeof(ngx_postgres_query_t)))) return "!ngx_palloc";
    if (sql.len > sizeof("file://") - 1 && !ngx_strncasecmp(sql.data, (u_char *)"file://", sizeof("file://") - 1)) {
        sql.data += sizeof("file://") - 1;
        sql.len -= sizeof("file://") - 1;
        if (ngx_conf_full_name(cf->cycle, &sql, 0) != NGX_OK) return "ngx_conf_full_name != NGX_OK";
        ngx_fd_t fd = ngx_open_file(sql.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) return "ngx_open_file == NGX_INVALID_FILE";
        ngx_file_info_t fi;
        if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_fd_info == NGX_FILE_ERROR"; }
        size_t len = ngx_file_size(&fi);
        u_char *data = ngx_pnalloc(cf->pool, len);
        if (!data) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "!ngx_pnalloc"; }
        ssize_t n = ngx_read_fd(fd, data, len);
        if (n == -1) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_read_fd == -1"; }
        if ((size_t) n != len) { if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR"; return "ngx_read_fd != len"; }
        if (ngx_close_file(fd) == NGX_FILE_ERROR) return "ngx_close_file == NGX_FILE_ERROR";
        sql.data = data;
        sql.len = len;
    }
    ngx_postgres_query_t *query = location->query;
    if (!(query->sql.data = ngx_palloc(cf->pool, sql.len))) return "!ngx_palloc";
    if (!(query->params = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_param_t)))) return "!ngx_array_create";
    if (!(query->ids = ngx_array_create(cf->pool, 1, sizeof(ngx_uint_t)))) return "!ngx_array_create";
    u_char *p = query->sql.data, *s = sql.data, *e = sql.data + sql.len;
    query->percent = 0;
    for (ngx_uint_t k = 0; s < e; *p++ = *s++) {
        if (*s == '%') {
            *p++ = '%';
            query->percent++;
        } else if (*s == '$') {
            ngx_str_t name;
            for (name.data = ++s, name.len = 0; s < e && is_variable_character(*s); s++, name.len++);
            if (!name.len) { *p++ = '$'; continue; }
            ngx_str_t type = {0, NULL};
            if (s[0] == ':' && s[1] == ':') for (s += 2, type.data = s, type.len = 0; s < e && is_variable_character(*s); s++, type.len++);
            if (!type.len) { *p++ = '$'; p = ngx_copy(p, name.data, name.len); continue; }
            ngx_int_t index = ngx_http_get_variable_index(cf, &name);
            if (index == NGX_ERROR) return "ngx_http_get_variable_index == NGX_ERROR";
            ngx_uint_t oid = type2oid(&type);
            if (!oid) return "!type2oid";
            if (oid == IDOID) {
                ngx_uint_t *id = ngx_array_push(query->ids);
                if (!id) return "!ngx_array_push";
                *id = (ngx_uint_t) index;
                *p++ = '%';
                *p++ = 'V';
            } else {
                ngx_postgres_param_t *param = ngx_array_push(query->params);
                if (!param) return "!ngx_array_push";
                param->index = (ngx_uint_t) index;
                param->oid = oid;
                p += ngx_sprintf(p, "$%i", ++k) - p;
            }
            if (s >= e) break;
        }
    }
    query->sql.len = p - query->sql.data;
    query->listen = query->sql.len > sizeof("LISTEN ") - 1 && !ngx_strncasecmp(query->sql.data, (u_char *)"LISTEN ", sizeof("LISTEN ") - 1);
//    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "sql = `%V`", &query->sql);
    return NGX_CONF_OK;
}


char *PQerrorMessageMy(const PGconn *conn) {
    char *err = PQerrorMessage(conn);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    err[len - 1] = '\0';
    return err;
}

char *PQresultErrorMessageMy(const PGresult *res) {
    char *err = PQresultErrorMessage(res);
    if (!err) return err;
    int len = strlen(err);
    if (!len) return err;
    err[len - 1] = '\0';
    return err;
}
