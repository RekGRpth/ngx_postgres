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


#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static void ngx_postgres_busy_to_free(ngx_peer_connection_t *pc, ngx_postgres_data_t *pd, ngx_postgres_save_t *ps) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    pd->common = ps->common;
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_head(&ps->common.server_conf->free, &ps->queue);
    pc->cached = 1;
    pc->connection = pd->common.connection;
    pc->connection->idle = 0;
    pc->connection->log = pc->log;
    pc->connection->read->log = pc->log;
    pc->connection->write->log = pc->log;
    pc->name = pd->common.name;
    pc->sockaddr = pd->common.sockaddr;
    pc->socklen = pd->common.socklen;
}


static ngx_int_t ngx_postgres_peer_single(ngx_peer_connection_t *pc, ngx_postgres_data_t *pd) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    if (ngx_queue_empty(&pd->common.server_conf->busy)) return NGX_DECLINED;
    ngx_queue_t *queue = ngx_queue_head(&pd->common.server_conf->busy);
    ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    ngx_postgres_busy_to_free(pc, pd, ps);
    return NGX_DONE;
}


static ngx_int_t ngx_postgres_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_data_t *pd) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    for (ngx_queue_t *queue = ngx_queue_head(&pd->common.server_conf->busy); queue != ngx_queue_sentinel(&pd->common.server_conf->busy); queue = ngx_queue_next(queue)) {
        ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ngx_memn2cmp((u_char *)pd->common.sockaddr, (u_char *)ps->common.sockaddr, pd->common.socklen, ps->common.socklen)) continue;
        ngx_postgres_busy_to_free(pc, pd, ps);
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


static ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    pd->failed = 0;
    if (pd->common.server_conf->max_save && pd->common.server_conf->single && ngx_postgres_peer_single(pc, pd) != NGX_DECLINED) { ngx_postgres_process_events(pd->request); return NGX_AGAIN; }
    if (pd->common.server_conf->peer >= pd->common.server_conf->max_peer) pd->common.server_conf->peer = 0;
    ngx_postgres_peer_t *peer = &pd->common.server_conf->peers[pd->common.server_conf->peer++];
    pd->common.name = peer->name;
    pd->common.sockaddr = peer->sockaddr;
    pd->common.socklen = peer->socklen;
    pc->cached = 0;
    pc->name = pd->common.name;
    pc->sockaddr = pd->common.sockaddr;
    pc->socklen = pd->common.socklen;
    if (pd->common.server_conf->max_save && !pd->common.server_conf->single && ngx_postgres_peer_multi(pc, pd) != NGX_DECLINED) { ngx_postgres_process_events(pd->request); return NGX_AGAIN; }
    if (pd->common.server_conf->reject && pd->common.server_conf->save >= pd->common.server_conf->max_save) {
        ngx_log_error(NGX_LOG_INFO, pc->log, 0, "keepalive connection pool is full, rejecting request to upstream \"%V\"", peer->name);
        pd->common.connection = ngx_get_connection(0, pc->log); /* a bit hack-ish way to return error response (setup part) */
        pc->connection = pd->common.connection;
        return NGX_AGAIN;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "connstring: %s", peer->connstring);
    pd->common.conn = PQconnectStart((const char *)peer->connstring); /* internal checks in PQsetnonblocking are taking care of any PQconnectStart failures, so we don't need to check them here. */
    if (PQstatus(pd->common.conn) == CONNECTION_BAD || PQsetnonblocking(pd->common.conn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connection failed: %s in upstream \"%V\"", PQerrorMessage(pd->common.conn), peer->name);
        PQfinish(pd->common.conn);
        pd->common.conn = NULL;
        return NGX_DECLINED;
    }
//    PQtrace(pd->common.conn, stderr);
    pd->common.server_conf->save++; /* take spot in keepalive connection pool */
    int fd = PQsocket(pd->common.conn); /* add the file descriptor (fd) into an nginx connection structure */
    if (fd == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to get connection fd"); goto invalid; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "connection fd:%d", fd);
    if (!(pd->common.connection = ngx_get_connection(fd, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to get a free nginx connection"); goto invalid; }
    pd->common.connection->log = pc->log;
    pd->common.connection->log_error = pc->log_error;
    pd->common.connection->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    pd->common.connection->read->log = pc->log;
    pd->common.connection->write->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(pd->common.connection) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (ngx_add_event(pd->common.connection->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(pd->common.connection->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) goto bad_add;
    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (ngx_add_event(pd->common.connection->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
        if (ngx_add_event(pd->common.connection->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) goto bad_add;
    } else goto bad_add;
    pd->state = state_db_connect;
    pc->connection = pd->common.connection;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, pc->log, 0, "failed to add nginx connection");
invalid:
    ngx_postgres_free_connection(&pd->common, NULL, 0);
    return NGX_ERROR;
}


static void ngx_postgres_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
}


static void ngx_postgres_process_notify(ngx_postgres_common_t *common) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "%s", __func__);
    for (PGnotify *notify; (notify = PQnotifies(common->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "notify: relname=\"%s\", extra=\"%s\", be_pid=%d.", notify->relname, notify->extra, notify->be_pid);
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(8192, common->connection->log);
        if (!temp_pool) continue;
        switch (ngx_http_push_stream_add_msg_to_channel_my(common->connection->log, &id, &text, NULL, NULL, 0, temp_pool)) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "notify error"); break;
            case NGX_DECLINED: {
                ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "notify declined");
                char *str = PQescapeIdentifier(common->conn, (const char *)id.data, id.len);
                if (!str) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "failed to escape %V: %s", id, PQerrorMessage(common->conn)); break; }
                ngx_str_t channel = {ngx_strlen(str), (u_char *)str};
                if (!channel.len) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "failed to escape %V", id); PQfreemem(str); break; }
                u_char *command = ngx_pnalloc(temp_pool, sizeof("UNLISTEN ") - 1 + channel.len + 1);
                if (!command) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "!ngx_pnalloc"); PQfreemem(str); break; }
                u_char *last = ngx_snprintf(command, sizeof("UNLISTEN ") - 1 + channel.len, "UNLISTEN %V", &channel);
                PQfreemem(str);
                if (last != command + sizeof("UNLISTEN ") - 1 + channel.len) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "ngx_snprintf"); break; }
                *last = '\0';
                if (!PQsendQuery(common->conn, (const char *)command)) { ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "failed to send unlisten: %s", PQerrorMessage(common->conn)); break; }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "unlisten %s sent successfully", command);
                ngx_destroy_pool(temp_pool);
                return;
            };
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "notify ok"); break;
            default: ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "notify unknown"); break;
        }
        ngx_destroy_pool(temp_pool);
    }
}


static void ngx_postgres_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    if (c->close) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "c->close"); goto close; }
    if (!PQconsumeInput(ps->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "failed to consume input: %s", PQerrorMessage(ps->common.conn)); goto close; }
    if (PQisBusy(ps->common.conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "busy while keepalive"); goto close; }
    for (PGresult *res; (res = PQgetResult(ps->common.conn)); PQclear(res)) ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0, "received result on idle keepalive connection: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res));
    ngx_postgres_process_notify(&ps->common);
    return;
close:
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    ngx_postgres_free_connection(&ps->common, NULL, 0);
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_head(&ps->common.server_conf->free, &ps->queue);
}


static void ngx_postgres_timeout(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
    ngx_postgres_free_connection(&ps->common, NULL, 1);
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_head(&ps->common.server_conf->free, &ps->queue);
}


static void ngx_postgres_free_peer(ngx_postgres_data_t *pd) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pd->request->connection->log, 0, "%s", __func__);
    if (pd->failed || !pd->common.connection || pd->request->upstream->headers_in.status_n != NGX_HTTP_OK) return;
    ngx_postgres_save_t *ps;
    if (ngx_queue_empty(&pd->common.server_conf->free)) {
        ngx_log_error(NGX_LOG_ERR, pd->request->connection->log, 0, "connection pool is already full");
        ngx_queue_t *queue = ngx_queue_last(&pd->common.server_conf->busy);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
        ngx_postgres_free_connection(&ps->common, &pd->common, 1);
    } else {
        ngx_queue_t *queue = ngx_queue_head(&pd->common.server_conf->free);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    }
    if (pd->common.connection->read->timer_set) ngx_del_timer(pd->common.connection->read);
    if (pd->common.connection->write->timer_set) ngx_del_timer(pd->common.connection->write);
    if (pd->common.connection->write->active && ngx_event_flags & NGX_USE_LEVEL_EVENT && ngx_del_event(pd->common.connection->write, NGX_WRITE_EVENT, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, pd->request->connection->log, 0, "ngx_del_event != NGX_OK");
        return;
    }
    if (pd->common.server_conf->max_requests && ++pd->common.requests > pd->common.server_conf->max_requests) {
        ngx_log_error(NGX_LOG_WARN, pd->request->connection->log, 0, "max_requests");
        return;
    }
    ngx_queue_remove(&ps->queue);
    ngx_queue_insert_head(&pd->common.server_conf->busy, &ps->queue);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pd->request->connection->log, 0, "free keepalive peer: saving connection %p", pd->common.connection);
    ps->common = pd->common;
    pd->common.connection = NULL;
    ps->common.connection->data = ps;
    ps->common.connection->idle = 1;
    ps->common.connection->log = ngx_cycle->log;
    ps->common.connection->read->handler = ngx_postgres_read_handler;
    ps->common.connection->read->log = ngx_cycle->log;
    ps->common.connection->write->handler = ngx_postgres_write_handler;
    ps->common.connection->write->log = ngx_cycle->log;
    if (ps->common.server_conf->timeout) {
        ps->timeout.log = ngx_cycle->log;
        ps->timeout.data = ps->common.connection;
        ps->timeout.handler = ngx_postgres_timeout;
        ngx_add_timer(&ps->timeout, ps->common.server_conf->timeout);
    }
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    if (state & NGX_PEER_FAILED) pd->failed = 1;
    if (pd->common.server_conf->max_save) ngx_postgres_free_peer(pd);
    if (pd->common.connection) ngx_postgres_free_connection(&pd->common, NULL, 1);
    pc->connection = NULL;
}


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = ngx_pcalloc(r->pool, sizeof(ngx_postgres_data_t));
    if (!pd) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    pd->common.server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    pd->request = r;
    r->upstream->peer.data = pd;
    r->upstream->peer.get = ngx_postgres_peer_get;
    r->upstream->peer.free = ngx_postgres_peer_free;
    ngx_postgres_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *query = location_conf->query;
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
    pd->resultFormat = location_conf->output.binary;
    if (location_conf->variables) {
        if (!(pd->variables = ngx_array_create(r->pool, location_conf->variables->nelts, sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NGX_ERROR; }
        /* fake ngx_array_push'ing */
        pd->variables->nelts = location_conf->variables->nelts;
        ngx_memzero(pd->variables->elts, pd->variables->nelts * pd->variables->size);
    }
    return NGX_OK;
}


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *peer) {
    return (peer->get == ngx_postgres_peer_get);
}


void ngx_postgres_free_connection(ngx_postgres_common_t *common, ngx_postgres_common_t *listen, ngx_flag_t delete) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "%s", __func__);
    if (listen) {
        PGresult *res = PQexec(common->conn, "with s as (select pg_listening_channels()) select array_to_string(array_agg(format($$listen %I$$, s.pg_listening_channels)), ';') from s");
        if (res) {
            if (PQresultStatus(res) == PGRES_TUPLES_OK) {
                if (!PQsendQuery(listen->conn, PQgetvalue(res, 0, 0))) {
                    ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "failed to send relisten: %s", PQerrorMessage(listen->conn));
                } else {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, common->connection->log, 0, "relisten %s sent successfully", PQgetvalue(res, 0, 0));
                }
            }
            PQclear(res);
        }
    }
    if (delete) {
        PGresult *res = PQexec(common->conn, "select pg_listening_channels()");
        if (res) {
            if (PQresultStatus(res) == PGRES_TUPLES_OK) for (int row = 0; row < PQntuples(res); row++) {
                ngx_str_t id = { PQgetlength(res, row, 0), (u_char *)PQgetvalue(res, row, 0) };
                ngx_log_error(NGX_LOG_ERR, common->connection->log, 0, "delete channel = %V", &id);
                ngx_pool_t *temp_pool = ngx_create_pool(8192, common->connection->log);
                if (temp_pool) {
                    ngx_http_push_stream_delete_channel_my(common->connection->log, &id, (u_char *)"channel unlisten", sizeof("channel unlisten") - 1, temp_pool);
                    ngx_destroy_pool(temp_pool);
                }
            }
            PQclear(res);
        }
    }
    PQfinish(common->conn);
    common->conn = NULL;
    if (common->connection) {
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
        if (common->connection->pool) ngx_destroy_pool(common->connection->pool);
        ngx_free_connection(common->connection);
        common->connection->fd = (ngx_socket_t) -1;
        common->connection = NULL;
    }
    common->server_conf->save--; /* free spot in keepalive connection pool */
}
