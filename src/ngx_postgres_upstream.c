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

#include <avcall.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static ngx_int_t ngx_postgres_peer_single(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    if (ngx_queue_empty(&peer_data->common.server_conf->busy)) return NGX_DECLINED;
    ngx_queue_t *queue = ngx_queue_head(&peer_data->common.server_conf->busy);
    ngx_postgres_save_t *save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    ngx_queue_remove(queue);
    ngx_queue_insert_head(&peer_data->common.server_conf->free, queue);
    if (!save->connection) return NGX_DECLINED;
    save->connection->idle = 0;
    save->connection->log = pc->log;
    save->connection->read->log = pc->log;
    save->connection->write->log = pc->log;
    pc->cached = 1;
    pc->connection = save->connection;
    pc->name = save->common.name;
    pc->sockaddr = save->common.sockaddr;
    pc->socklen = save->common.socklen;
    peer_data->common.charset = save->common.charset;
    peer_data->common.conn = save->common.conn;
    peer_data->common.name = save->common.name;
    peer_data->common.prepare = save->common.prepare;
    peer_data->common.requests = save->common.requests;
    peer_data->common.sockaddr = save->common.sockaddr;
    peer_data->common.socklen = save->common.socklen;
    peer_data->common.timeout = save->common.timeout;
    if (peer_data->common.timeout.timer_set) ngx_del_timer(&peer_data->common.timeout);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    for (ngx_queue_t *queue = ngx_queue_head(&peer_data->common.server_conf->busy); queue != ngx_queue_sentinel(&peer_data->common.server_conf->busy); queue = ngx_queue_next(queue)) {
        ngx_postgres_save_t *save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ngx_memn2cmp((u_char *) save->common.sockaddr, (u_char *) pc->sockaddr, save->common.socklen, pc->socklen)) continue;
        ngx_queue_remove(queue);
        ngx_queue_insert_head(&peer_data->common.server_conf->free, queue);
        if (!save->connection) continue;
        save->connection->idle = 0;
        save->connection->log = pc->log;
        save->connection->read->log = pc->log;
        save->connection->write->log = pc->log;
        pc->cached = 1;
        pc->connection = save->connection;
        /* we do not need to resume the peer name, because we already take the right value outside */
        peer_data->common.charset = save->common.charset;
        peer_data->common.conn = save->common.conn;
        peer_data->common.prepare = save->common.prepare;
        peer_data->common.requests = save->common.requests;
        peer_data->common.timeout = save->common.timeout;
        if (peer_data->common.timeout.timer_set) ngx_del_timer(&peer_data->common.timeout);
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


static ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_peer_data_t *peer_data = data;
    peer_data->failed = 0;
    if (peer_data->common.server_conf->max_save && peer_data->common.server_conf->single && ngx_postgres_peer_single(pc, peer_data) != NGX_DECLINED) { /* re-use keepalive peer */
        peer_data->state = peer_data->common.server_conf->prepare ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(peer_data->request);
        return NGX_AGAIN;
    }
    if (peer_data->common.server_conf->peer >= peer_data->common.server_conf->max_peer) peer_data->common.server_conf->peer = 0;
    ngx_postgres_peer_t *peer = &peer_data->common.server_conf->peers->peer[peer_data->common.server_conf->peer++];
    peer_data->common.name = peer->name;
    peer_data->common.sockaddr = peer->sockaddr;
    peer_data->common.socklen = peer->socklen;
    pc->cached = 0;
    pc->name = peer->name;
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    if (peer_data->common.server_conf->max_save && !peer_data->common.server_conf->single && ngx_postgres_peer_multi(pc, peer_data) != NGX_DECLINED) { /* re-use keepalive peer */
        peer_data->state = peer_data->common.server_conf->prepare ? state_db_send_prepare : state_db_send_query;
        ngx_postgres_process_events(peer_data->request);
        return NGX_AGAIN;
    }
    if (peer_data->common.server_conf->reject && peer_data->common.server_conf->save >= peer_data->common.server_conf->max_save) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0, "keepalive connection pool is full, rejecting request to upstream \"%V\"", peer->name);
        pc->connection = ngx_get_connection(0, pc->log); /* a bit hack-ish way to return error response (setup part) */
        return NGX_AGAIN;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "connstring: %s", peer->connstring);
    /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    peer_data->common.conn = PQconnectStart((const char *)peer->connstring);
    if (PQstatus(peer_data->common.conn) == CONNECTION_BAD || PQsetnonblocking(peer_data->common.conn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connection failed: %s in upstream \"%V\"", PQerrorMessage(peer_data->common.conn), peer->name);
        PQfinish(peer_data->common.conn);
        peer_data->common.conn = NULL;
        return NGX_DECLINED;
    }
//    PQtrace(peer_data->common.conn, stderr);
    peer_data->common.server_conf->save++; /* take spot in keepalive connection pool */
    int fd = PQsocket(peer_data->common.conn); /* add the file descriptor (fd) into an nginx connection structure */
    if (fd == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to get connection fd"); goto invalid; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "connection fd:%d", fd);
    if (!(pc->connection = ngx_get_connection(fd, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to get a free nginx connection"); goto invalid; }
    pc->connection->log = pc->log;
    pc->connection->log_error = pc->log_error;
    pc->connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    pc->connection->read->log = pc->log;
    pc->connection->write->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(pc->connection) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (ngx_add_event(pc->connection->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(pc->connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (ngx_add_event(pc->connection->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(pc->connection->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
    } else goto bad_add;
    peer_data->state = state_db_connect;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to add nginx connection");
invalid:
    ngx_postgres_free_connection(pc->connection, &peer_data->common, NULL, 0);
    return NGX_ERROR;
}


static void ngx_postgres_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
}


static ngx_str_t PQescapeInternal(ngx_pool_t *pool, const u_char *str, size_t len, ngx_flag_t as_ident) {
    ngx_str_t result = ngx_null_string;
    u_char quote_char = as_ident ? '"' : '\'';
    ngx_uint_t num_backslashes = 0;
    ngx_uint_t num_quotes = 0;
    const u_char *s;
    for (s = str; (size_t)(s - str) < len && *s != '\0'; ++s) if (*s == quote_char) ++num_quotes; else if (*s == '\\') ++num_backslashes;
    size_t input_len = s - str;
    size_t result_size = input_len + num_quotes + 3;
    if (!as_ident && num_backslashes > 0) result_size += num_backslashes + 2;
    u_char *rp = ngx_pnalloc(pool, result_size);
    if (!rp) return result;
    result.data = rp;
    if (!as_ident && num_backslashes > 0) { *rp++ = ' '; *rp++ = 'E'; }
    *rp++ = quote_char;
    if (!num_quotes && (!num_backslashes || as_ident)) rp = ngx_copy(rp, str, input_len);
    else for (s = str; (size_t)(s - str) < input_len; ++s) if (*s == quote_char || (!as_ident && *s == '\\')) { *rp++ = *s; *rp++ = *s; } else *rp++ = *s;
    *rp++ = quote_char;
    *rp = '\0';
    result.len = rp - result.data;
    return result;
}


void ngx_postgres_process_notify(ngx_connection_t *c, ngx_postgres_common_t *common) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    for (PGnotify *notify; (notify = PQnotifies(common->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "notify: relname=\"%s\", extra=\"%s\", be_pid=%d.", notify->relname, notify->extra, notify->be_pid);
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(4096, c->log);
        if (!temp_pool) continue;
        switch (ngx_http_push_stream_add_msg_to_channel_my(c->log, &id, &text, NULL, NULL, 0, temp_pool)) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "notify error"); break;
            case NGX_DECLINED: {
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "notify declined");
                ngx_str_t channel = PQescapeInternal(temp_pool, id.data, id.len, 1);
                if (!channel.len) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to escape %V", id); break; }
                u_char *command = ngx_pnalloc(temp_pool, sizeof("UNLISTEN ") - 1 + channel.len + 1);
                if (!command) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); break; }
                u_char *last = ngx_snprintf(command, sizeof("UNLISTEN ") - 1 + channel.len, "UNLISTEN %V", &channel);
                if (last != command + sizeof("UNLISTEN ") - 1 + channel.len) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_snprintf"); break; }
                *last = '\0';
                if (!PQsendQuery(common->conn, (const char *)command)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to send unlisten: %s", PQerrorMessage(common->conn)); break; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "unlisten %s sent successfully", command);
                ngx_destroy_pool(temp_pool);
                return;
            };
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "notify ok"); break;
            default: ngx_log_error(NGX_LOG_ERR, c->log, 0, "notify unknown"); break;
        }
        ngx_destroy_pool(temp_pool);
    }
}


static void ngx_postgres_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *save = c->data;
    if (c->close) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "c->close"); goto close; }
    if (!PQconsumeInput(save->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "failed to consume input: %s", PQerrorMessage(save->common.conn)); goto close; }
    if (PQisBusy(save->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "busy while keepalive"); goto close; }
    for (PGresult *res; (res = PQgetResult(save->common.conn)); PQclear(res)) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0, "received result on idle keepalive connection: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res));
    ngx_postgres_process_notify(c, &save->common);
    return;
close:
    ngx_postgres_free_connection(c, &save->common, NULL, 0);
    ngx_queue_remove(&save->queue);
    ngx_queue_insert_head(&save->common.server_conf->free, &save->queue);
}


static void ngx_postgres_timeout(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_postgres_save_t *save = ev->data;
    ngx_postgres_free_connection(save->connection, &save->common, NULL, 1);
    ngx_queue_remove(&save->queue);
    ngx_queue_insert_head(&save->common.server_conf->free, &save->queue);
}


static void ngx_postgres_free_peer(ngx_peer_connection_t *pc, ngx_postgres_peer_data_t *peer_data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    if (state & NGX_PEER_FAILED) peer_data->failed = 1;
    if (peer_data->failed || !pc->connection || peer_data->request->upstream->headers_in.status_n != NGX_HTTP_OK) return;
    ngx_postgres_save_t *save;
    ngx_queue_t *queue;
    if (ngx_queue_empty(&peer_data->common.server_conf->free)) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connection pool is already full");
        queue = ngx_queue_last(&peer_data->common.server_conf->busy);
        save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_queue_remove(queue);
        ngx_postgres_free_connection(save->connection, &save->common, &peer_data->common, 1);
    } else {
        queue = ngx_queue_head(&peer_data->common.server_conf->free);
        save = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_queue_remove(queue);
    }
    if (pc->connection->read->timer_set) ngx_del_timer(pc->connection->read);
    if (pc->connection->write->timer_set) ngx_del_timer(pc->connection->write);
    if (pc->connection->write->active && ngx_event_flags & NGX_USE_LEVEL_EVENT && ngx_del_event(pc->connection->write, NGX_WRITE_EVENT, 0) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_del_event != NGX_OK"); return; }
    if (peer_data->common.server_conf->max_requests && peer_data->common.requests >= peer_data->common.server_conf->max_requests - 1) return;
    save->connection = pc->connection;
    pc->connection = NULL;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "free keepalive peer: saving connection %p", save->connection);
    ngx_queue_insert_head(&peer_data->common.server_conf->busy, queue);
    save->connection->data = save;
    save->connection->idle = 1;
    save->connection->log = ngx_cycle->log;
    save->connection->read->handler = ngx_postgres_read_handler;
    save->connection->read->log = ngx_cycle->log;
    save->connection->write->handler = ngx_postgres_write_handler;
    save->connection->write->log = ngx_cycle->log;
    save->common.charset = peer_data->common.charset;
    save->common.conn = peer_data->common.conn;
    save->common.name = peer_data->common.name;
    save->common.prepare = peer_data->common.prepare;
    save->common.requests = peer_data->common.requests;
    save->common.sockaddr = pc->sockaddr;
    save->common.socklen = pc->socklen;
    save->common.timeout = peer_data->common.timeout;
    if (save->common.server_conf->max_requests) save->common.requests++;
    if (save->common.server_conf->timeout && !save->common.timeout.timer_set) {
        save->common.timeout.log = ngx_cycle->log;
        save->common.timeout.data = save;
        save->common.timeout.handler = ngx_postgres_timeout;
        ngx_add_timer(&save->common.timeout, save->common.server_conf->timeout);
    }
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_peer_data_t *peer_data = data;
    if (peer_data->common.server_conf->max_save) ngx_postgres_free_peer(pc, peer_data, state);
    if (pc->connection) {
        ngx_postgres_free_connection(pc->connection, &peer_data->common, NULL, 1);
        peer_data->common.conn = NULL;
        pc->connection = NULL;
    }
}


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_peer_data_t *peer_data = ngx_pcalloc(r->pool, sizeof(ngx_postgres_peer_data_t));
    if (!peer_data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    peer_data->common.server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    peer_data->request = r;
    r->upstream->peer.data = peer_data;
    r->upstream->peer.get = ngx_postgres_peer_get;
    r->upstream->peer.free = ngx_postgres_peer_free;
    ngx_postgres_query_t *query;
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location_conf->methods_set & r->method) {
        query = location_conf->methods->elts;
        ngx_uint_t i;
        for (i = 0; i < location_conf->methods->nelts; i++) if (query[i].methods & r->method) { query = &query[i]; break; }
        if (i == location_conf->methods->nelts) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "i == location_conf->methods->nelts"); return NGX_ERROR; }
    } else query = location_conf->query;
    if (query->params->nelts) {
        ngx_postgres_param_t *param = query->params->elts;
        peer_data->send.nParams = query->params->nelts;
        if (!(peer_data->send.paramTypes = ngx_pnalloc(r->pool, query->params->nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        if (!(peer_data->send.paramValues = ngx_pnalloc(r->pool, query->params->nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->params->nelts; i++) {
            peer_data->send.paramTypes[i] = param[i].oid;
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[i].index);
            if (!value || !value->data || !value->len) peer_data->send.paramValues[i] = NULL; else {
                if (!(peer_data->send.paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                (void) ngx_cpystrn(peer_data->send.paramValues[i], value->data, value->len + 1);
            }
        }
    }
    ngx_str_t sql;
    sql.len = query->sql.len - 2 * query->ids->nelts - query->percent;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &query->sql);
    ngx_str_t *ids = NULL;
    if (query->ids->nelts) {
        ngx_uint_t *id = query->ids->elts;
        if (!(ids = ngx_pnalloc(r->pool, query->ids->nelts * sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
        for (ngx_uint_t i = 0; i < query->ids->nelts; i++) {
            ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, id[i]);
            if (!value || !value->data || !value->len) { ngx_str_set(&ids[i], "NULL"); } else {
                ids[i] = PQescapeInternal(r->pool, value->data, value->len, 1);
                if (!ids[i].len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to escape %*.*s", value->len, value->len, value->data); return NGX_ERROR; }
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
    for (ngx_uint_t i = 0; i < query->ids->nelts; i++) if (av_ptr(alist, ngx_str_t *, &ids[i])) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_ptr"); return NGX_ERROR; }
    if (av_call(alist)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "av_call"); return NGX_ERROR; }
    if (last != sql.data + sql.len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf"); return NGX_ERROR; }
    *last = '\0';
    peer_data->send.command = sql.data;
    peer_data->send.resultFormat = location_conf->output.binary;
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sql = `%V`", &sql);
    ngx_postgres_context_t *context = ngx_http_get_module_ctx(r, ngx_postgres_module);
    context->sql = sql; /* set $postgres_query */
    if (peer_data->common.server_conf->prepare && !query->listen) {
        if (!(peer_data->send.stmtName = ngx_pnalloc(r->pool, 32))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_pnalloc"); return NGX_ERROR; }
        u_char *last = ngx_snprintf(peer_data->send.stmtName, 31, "ngx_%ul", (unsigned long)(peer_data->send.hash = ngx_hash_key(sql.data, sql.len)));
        *last = '\0';
    }
    return NGX_OK;
}


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *peer) {
    return (peer->get == ngx_postgres_peer_get);
}


void ngx_postgres_free_connection(ngx_connection_t *c, ngx_postgres_common_t *common, ngx_postgres_common_t *listen, ngx_flag_t delete) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    if (common->timeout.timer_set) ngx_del_timer(&common->timeout);
    if (listen) {
        PGresult *res = PQexec(common->conn, "with s as (select pg_listening_channels()) select array_to_string(array_agg(format($$listen %I$$, s.pg_listening_channels)), ';') from s");
        if (res) {
            if (PQresultStatus(res) == PGRES_TUPLES_OK) {
                if (!PQsendQuery(listen->conn, PQgetvalue(res, 0, 0))) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0, "failed to send relisten: %s", PQerrorMessage(listen->conn));
                } else {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "relisten %s sent successfully", PQgetvalue(res, 0, 0));
                }
            }
            PQclear(res);
        }
    } else if (delete) {
        PGresult *res = PQexec(common->conn, "select pg_listening_channels()");
        if (res) {
            if (PQresultStatus(res) == PGRES_TUPLES_OK) for (int row = 0; row < PQntuples(res); row++) {
                ngx_str_t id = { PQgetlength(res, row, 0), (u_char *)PQgetvalue(res, row, 0) };
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "delete channel = %V", &id);
                ngx_pool_t *temp_pool = ngx_create_pool(4096, c->log);
                if (temp_pool) {
                    ngx_http_push_stream_delete_channel_my(c->log, &id, (u_char *)"channel unlisten", sizeof("channel unlisten") - 1, temp_pool);
                    ngx_destroy_pool(temp_pool);
                }
            }
            PQclear(res);
        }
    }
    PQfinish(common->conn);
    if (c) {
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
        if (ngx_del_conn) ngx_del_conn(c, NGX_CLOSE_EVENT); else {
            if (c->read->active || c->read->disabled) ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
            if (c->write->active || c->write->disabled) ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
        if (c->read->posted) { ngx_delete_posted_event(c->read); }
        if (c->write->posted) { ngx_delete_posted_event(c->write); }
        c->read->closed = 1;
        c->write->closed = 1;
        if (c->pool) ngx_destroy_pool(c->pool);
        ngx_free_connection(c);
        c->fd = (ngx_socket_t) -1;
    }
    common->server_conf->save--; /* free spot in keepalive connection pool */
}
