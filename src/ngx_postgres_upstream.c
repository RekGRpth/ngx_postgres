#include <postgresql/server/catalog/pg_type_d.h>

#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_upstream.h"


static void ngx_postgres_save_to_free(ngx_postgres_data_t *pd, ngx_postgres_save_t *ps) {
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_queue_remove(&ps->queue);
    ngx_postgres_common_t *psc = &ps->common;
    ngx_postgres_server_t *server = psc->server;
    ngx_queue_insert_tail(&server->free.queue, &ps->queue);
    ngx_http_upstream_t *u = r->upstream;
    ngx_peer_connection_t *pc = &u->peer;
    ngx_postgres_common_t *pdc = &pd->common;
    *pdc = *psc;
    ngx_connection_t *c = pc->connection = pdc->connection;
    c->data = r;
    c->idle = 0;
    c->log_error = pc->log_error;
    c->log = pc->log;
    if (c->pool) c->pool->log = pc->log;
    c->read->log = pc->log;
    if (c->read->timer_set) ngx_del_timer(c->read);
    c->sent = 0;
    c->write->log = pc->log;
    if (c->write->timer_set) ngx_del_timer(c->write);
    pc->cached = 1;
    pc->name = &pdc->name;
    pc->sockaddr = pdc->sockaddr;
    pc->socklen = pdc->socklen;
}


static ngx_int_t ngx_postgres_peer_multi(ngx_http_request_t *r) {
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_server_t *server = pdc->server;
    for (ngx_queue_t *queue = ngx_queue_head(&server->ps.queue); queue != ngx_queue_sentinel(&server->ps.queue); queue = ngx_queue_next(queue)) {
        ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_postgres_common_t *psc = &ps->common;
        if (ngx_memn2cmp((u_char *)pdc->sockaddr, (u_char *)psc->sockaddr, pdc->socklen, psc->socklen)) continue;
        ngx_postgres_save_to_free(pd, ps);
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


static void ngx_postgres_data_timeout(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_http_request_t *r = c->data;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_queue_remove(&pd->queue);
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_server_t *server = pdc->server;
    server->pd.size--;
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
}


static ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_postgres_data_t *pd = pc->data;
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_server_t *server = pdc->server;
    ngx_queue_t *queue = ngx_queue_head(&server->peer);
    ngx_postgres_peer_t *peer = ngx_queue_data(queue, ngx_postgres_peer_t, queue);
    ngx_queue_remove(&peer->queue);
    ngx_queue_insert_tail(&server->peer, &peer->queue);
//    pc->cached = 0;
    ngx_http_upstream_t *u = r->upstream;
    u->conf->connect_timeout = peer->connect;
    pdc->name = peer->name;
    pdc->sockaddr = peer->sockaddr;
    pdc->socklen = peer->socklen;
    if (server->ps.max) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ps.max");
        if (ngx_postgres_peer_multi(r) != NGX_DECLINED) {
            ngx_postgres_process_events(r);
            return NGX_AGAIN;
        }
        if (server->ps.size < server->ps.max) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ps.size = %i", server->ps.size);
        } else if (server->pd.max) {
            if (server->pd.size < server->pd.max) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pd.size = %i", server->pd.size);
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "pd = %p", pd);
                ngx_queue_insert_tail(&server->pd.queue, &pd->queue);
                pd->timeout.handler = ngx_postgres_data_timeout;
                pd->timeout.log = r->connection->log;
                pd->timeout.data = r->connection;
                ngx_add_timer(&pd->timeout, server->pd.timeout);
                server->pd.size++;
                return NGX_YIELD;
            } else if (server->pd.reject) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "pd.size = %i", server->pd.size);
                return NGX_DECLINED;
            }
        } else if (server->ps.reject) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ps.size = %i", server->ps.size);
            return NGX_DECLINED;
        }
    }
    const char *host = peer->values[0];
    peer->values[0] = (const char *)peer->value;
    const char *options = peer->values[2];
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (location->append) {
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
    pdc->conn = PQconnectStartParams(peer->keywords, peer->values, 0);
    peer->values[0] = host;
    peer->values[2] = options;
    if (PQstatus(pdc->conn) == CONNECTION_BAD || PQsetnonblocking(pdc->conn, 1) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQstatus == CONNECTION_BAD or PQsetnonblocking == -1 and %s in upstream \"%V\"", PQerrorMessageMy(pdc->conn), peer->name);
        PQfinish(pdc->conn);
        pdc->conn = NULL;
        return NGX_DECLINED;
    }
    if (server->trace.log) PQtrace(pdc->conn, fdopen(server->trace.log->file->fd, "a+"));
    int fd;
    if ((fd = PQsocket(pdc->conn)) == -1) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "PQsocket == -1"); goto invalid; }
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!(pdc->connection = c)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_get_connection"); goto invalid; }
    c->log_error = pc->log_error;
    c->log = pc->log;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    if (c->pool) c->pool->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    /* register the connection with postgres connection fd into the nginx event model */
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_conn != NGX_OK"); goto invalid; }
    } else if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_CLEAR_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {
        if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_add_event != NGX_OK"); goto invalid; }
    } else goto bad_add;
    pdc->state = state_db_connect;
    pc->connection = c;
    pc->name = &pdc->name;
    pc->sockaddr = pdc->sockaddr;
    pc->socklen = pdc->socklen;
    server->ps.size++;
    return NGX_AGAIN;
bad_add:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_event_flags not NGX_USE_RTSIG_EVENT or NGX_USE_CLEAR_EVENT or NGX_USE_LEVEL_EVENT");
invalid:
    ngx_postgres_free_connection(pdc);
    return NGX_ERROR;
}


static void ngx_postgres_write_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    ngx_postgres_common_t *psc = &ps->common;
    if (c->close) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "close"); goto close; }
    if (c->write->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "timedout"); goto close; }
    return;
close:
    ngx_postgres_free_connection(psc);
    ngx_queue_remove(&ps->queue);
    ngx_postgres_server_t *server = psc->server;
    ngx_queue_insert_tail(&server->free.queue, &ps->queue);
}


static void ngx_postgres_process_notify(ngx_postgres_save_t *ps) {
    ngx_postgres_common_t *psc = &ps->common;
    ngx_connection_t *c = psc->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_array_t *array = NULL;
    size_t len = 0;
    for (PGnotify *notify; (notify = PQnotifies(psc->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "relname=%s, extra=%s, be_pid=%i", notify->relname, notify->extra, notify->be_pid);
        if (!ngx_http_push_stream_add_msg_to_channel_my) continue;
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(id.len + text.len, c->log);
        if (!temp_pool) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_create_pool"); continue; }
        switch (ngx_http_push_stream_add_msg_to_channel_my(c->log, &id, &text, NULL, NULL, 0, temp_pool)) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
            case NGX_DECLINED:
                ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED");
                if (psc->listen) for (ngx_queue_t *queue = ngx_queue_head(psc->listen); queue != ngx_queue_sentinel(psc->listen); queue = ngx_queue_next(queue)) {
                    ngx_postgres_listen_t *listen = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
                    if (id.len == listen->channel.len && !ngx_strncmp(id.data, listen->channel.data, id.len)) {
                        if (!array && !(array = ngx_array_create(c->pool, 1, sizeof(ngx_str_t)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_array_create"); break; }
                        ngx_str_t *unlisten = ngx_array_push(array);
                        if (!unlisten) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_array_push"); break; }
                        *unlisten = listen->command;
                        len += unlisten->len;
                        ngx_queue_remove(&listen->queue);
                        break;
                    }
                }
                break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); break;
            default: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == unknown"); break;
        }
        ngx_destroy_pool(temp_pool);
    }
    if (len && array && array->nelts) {
        u_char *unlisten = ngx_pnalloc(c->pool, len + 2 * array->nelts - 1);
        if (!unlisten) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); goto destroy; }
        ngx_str_t *elts = array->elts;
        u_char *p = unlisten;
        for (ngx_uint_t i = 0; i < array->nelts; i++) {
            if (i) { *p++ = ';'; *p++ = '\n'; }
            p = ngx_cpymem(p, elts[i].data, elts[i].len);
        }
        *p = '\0';
        if (!PQsendQuery(psc->conn, (const char *)unlisten)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(%s) and %s", unlisten, PQerrorMessageMy(psc->conn)); }
        else { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(%s)", unlisten); }
        ngx_pfree(c->pool, unlisten);
    }
destroy:
    if (array) ngx_array_destroy(array);
}


static void ngx_postgres_read_handler(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s", __func__);
    ngx_connection_t *c = ev->data;
    ngx_postgres_save_t *ps = c->data;
    ngx_postgres_common_t *psc = &ps->common;
    if (c->close) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "close"); goto close; }
    if (c->read->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "timedout"); goto close; }
    if (!PQconsumeInput(psc->conn)) { ngx_log_error(NGX_LOG_ERR, ev->log, 0, "!PQconsumeInput and %s", PQerrorMessageMy(psc->conn)); goto close; }
    if (PQisBusy(psc->conn)) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PQisBusy"); return; }
    for (PGresult *res; (res = PQgetResult(psc->conn)); PQclear(res)) switch(PQresultStatus(res)) {
        case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, ev->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
        default: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "PQresultStatus == %s", PQresStatus(PQresultStatus(res))); break;
    }
    ngx_postgres_process_notify(ps);
    return;
close:
    ngx_postgres_free_connection(psc);
    ngx_queue_remove(&ps->queue);
    ngx_postgres_server_t *server = psc->server;
    ngx_queue_insert_tail(&server->free.queue, &ps->queue);
}


static u_char *ngx_postgres_listen(ngx_postgres_data_t *pd, ngx_postgres_save_t *ps) {
    ngx_http_request_t *r = pd->request;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_connection_t *c = pdc->connection;
    u_char *listen = NULL;
    ngx_array_t *array = NULL;
    size_t len = 0;
    if (pdc->listen) while (!ngx_queue_empty(pdc->listen)) {
        ngx_queue_t *queue = ngx_queue_head(pdc->listen);
        ngx_postgres_listen_t *pdl = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
        ngx_postgres_common_t *psc = &ps->common;
        if (!psc->listen) {
            if (!(psc->listen = ngx_pcalloc(c->pool, sizeof(ngx_queue_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NULL; }
            ngx_queue_init(psc->listen);
        }
        for (ngx_queue_t *queue = ngx_queue_head(psc->listen); queue != ngx_queue_sentinel(psc->listen); queue = ngx_queue_next(queue)) {
            ngx_postgres_listen_t *psl = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
            if (psl->channel.len == pdl->channel.len && !ngx_strncmp(psl->channel.data, pdl->channel.data, pdl->channel.len)) goto cont;
        }
        if (!array && !(array = ngx_array_create(r->pool, 1, sizeof(ngx_postgres_listen_t)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_create"); return NULL; }
        ngx_postgres_listen_t *psl = ngx_array_push(array);
        if (!psl) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_array_push"); return NULL; }
        if (!(psl->channel.data = ngx_pstrdup(c->pool, &pdl->channel))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NULL; }
        psl->channel.len = pdl->channel.len;
        if (!(psl->command.data = ngx_pstrdup(c->pool, &pdl->command))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pstrdup"); return NULL; }
        psl->command.len = pdl->command.len;
        len += pdl->command.len - 2;
        ngx_queue_insert_tail(psc->listen, &psl->queue);
cont:
        ngx_queue_remove(&pdl->queue);
    }
    if (len && array && array->nelts) {
        listen = ngx_pnalloc(r->pool, len + 2 * array->nelts - 1);
        if (!listen) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NULL; }
        ngx_postgres_listen_t *elts = array->elts;
        u_char *p = listen;
        for (ngx_uint_t i = 0; i < array->nelts; i++) {
            if (i) { *p++ = ';'; *p++ = '\n'; }
            p = ngx_cpymem(p, elts[i].command.data + 2, elts[i].command.len - 2);
        }
        *p = '\0';
    }
    return listen;
}


static void ngx_postgres_free_to_save(ngx_postgres_data_t *pd, ngx_postgres_save_t *ps) {
    ngx_http_request_t *r = pd->request;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_queue_remove(&ps->queue);
    ngx_postgres_server_t *server = pdc->server;
    ngx_queue_insert_tail(&server->ps.queue, &ps->queue);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "connection = %p", pdc->connection);
    ngx_http_upstream_t *u = r->upstream;
    ngx_peer_connection_t *pc = &u->peer;
    pc->connection = NULL;
    ngx_postgres_common_t *psc = &ps->common;
    *psc = *pdc;
    ngx_connection_t *c = psc->connection;
    c->data = ps;
    c->idle = 1;
    c->log = server->ps.log ? server->ps.log : ngx_cycle->log;
    if (c->pool) c->pool->log = c->log;
    c->read->delayed = 0;
    c->read->handler = ngx_postgres_read_handler;
    c->read->log = c->log;
    ngx_add_timer(c->read, server->ps.timeout);
    c->read->timedout = 0;
    c->write->delayed = 0;
    c->write->handler = ngx_postgres_write_handler;
    c->write->log = c->log;
    ngx_add_timer(c->write, server->ps.timeout);
    c->write->timedout = 0;
}


static void ngx_postgres_free_peer(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_data_t *pd = u->peer.data;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_connection_t *c = pdc->connection;
    if (!c) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!connection"); return; }
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_postgres_server_t *server = pdc->server;
    if (c->requests >= server->ps.requests) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "requests = %i", c->requests); return; }
    if (ngx_terminate) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_terminate"); return; }
    if (ngx_exiting) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_exiting"); return; }
    u_char *listen = NULL;
    ngx_postgres_save_t *ps;
    if (ngx_queue_empty(&server->free.queue)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_queue_empty(free)");
        ngx_queue_t *queue = ngx_queue_last(&server->ps.queue);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ngx_http_push_stream_add_msg_to_channel_my && ngx_http_push_stream_delete_channel_my) listen = ngx_postgres_listen(pd, ps);
        ngx_postgres_common_t *psc = &ps->common;
        ngx_postgres_free_connection(psc);
    } else {
        ngx_queue_t *queue = ngx_queue_head(&server->free.queue);
        ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
    }
    ngx_postgres_free_to_save(pd, ps);
    ngx_postgres_common_t *psc = &ps->common;
    if (PQtransactionStatus(psc->conn) != PQTRANS_IDLE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
        PGcancel *cancel = PQgetCancel(psc->conn);
        if (!cancel) ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQgetCancel");
        char err[256];
        if (!PQcancel(cancel, err, 256)) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!PQcancel and %s", err); PQfreeCancel(cancel); }
        PQfreeCancel(cancel);
    }
    if (listen) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "listen = %s", listen);
        if (!PQsendQuery(pdc->conn, (const char *)listen)) { ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "!PQsendQuery(%s) and %s", listen, PQerrorMessageMy(pdc->conn)); }
    }
    if (!ngx_queue_empty(&server->pd.queue)) {
        ngx_queue_t *queue = ngx_queue_head(&server->pd.queue);
        ngx_postgres_data_t *pd = ngx_queue_data(queue, ngx_postgres_data_t, queue);
        ngx_http_request_t *r = pd->request;
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "pd = %p", pd);
        ngx_queue_remove(&pd->queue);
        server->pd.size--;
        if (pd->timeout.timer_set) ngx_del_timer(&pd->timeout);
        ngx_http_upstream_connect(r, r->upstream);
    }
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_connection_t *c = pc->connection;
    ngx_postgres_data_t *pd = pc->data;
    ngx_postgres_common_t *pdc = &pd->common;
    ngx_postgres_server_t *server = pdc->server;
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "state = %i", state);
    if (!c || c->read->error || c->write->error || (state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout)); else
    if (server->ps.max) ngx_postgres_free_peer(r);
    if (pc->connection) ngx_postgres_free_connection(pdc);
    pc->connection = NULL;
}


typedef struct {
    ngx_uint_t index;
    ngx_uint_t oid;
} ngx_postgres_param_t;


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = ngx_pcalloc(r->pool, sizeof(*pd));
    if (!pd) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_postgres_common_t *pdc = &pd->common;
    pdc->server = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    pd->request = r;
    ngx_http_upstream_t *u = r->upstream;
    u->peer.data = pd;
    u->peer.get = ngx_postgres_peer_get;
    u->peer.free = ngx_postgres_peer_free;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_query_t *elts = location->queries.elts;
    ngx_uint_t nelts = 0;
    for (ngx_uint_t i = 0; i < location->queries.nelts; i++) {
        ngx_postgres_query_t *query = &elts[i];
        if (query->params.nelts) {
            ngx_postgres_param_t *param = query->params.elts;
            pd->nParams = query->params.nelts;
            if (!(pd->paramTypes = ngx_pnalloc(r->pool, query->params.nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(pd->paramValues = ngx_pnalloc(r->pool, query->params.nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            for (ngx_uint_t i = 0; i < query->params.nelts; i++) {
                pd->paramTypes[i] = param[i].oid;
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[i].index);
                if (!value || !value->data || !value->len) pd->paramValues[i] = NULL; else {
                    if (!(pd->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                    (void)ngx_cpystrn(pd->paramValues[i], value->data, value->len + 1);
                }
            }
        }
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "query = %i", i);
        ngx_array_t *variables = &query->variables;
        nelts += variables->nelts;
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nelts = %i", variables->nelts);
    }
    if (nelts) {
        if (ngx_array_init(&pd->variables, r->pool, pd->variables.nelts, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_memzero(&pd->variables.elts, pd->variables.nelts * pd->variables.size);
        pd->variables.nelts = nelts;
    }
//    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nelts = %i", pd->variables.nelts);
    return NGX_OK;
}


ngx_flag_t ngx_postgres_is_my_peer(const ngx_peer_connection_t *pc) {
    return (pc->get == ngx_postgres_peer_get);
}


void ngx_postgres_free_connection(ngx_postgres_common_t *common) {
    ngx_connection_t *c = common->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_server_t *server = common->server;
    server->ps.size--;
    if (!c) {
        if (common->conn) {
            PQfinish(common->conn);
            common->conn = NULL;
        }
        return;
    }
    if (common->conn) {
        if (!c->close && common->listen && ngx_http_push_stream_delete_channel_my) {
            while (!ngx_queue_empty(common->listen)) {
                ngx_queue_t *queue = ngx_queue_head(common->listen);
                ngx_postgres_listen_t *listen = ngx_queue_data(queue, ngx_postgres_listen_t, queue);
                ngx_log_error(NGX_LOG_INFO, c->log, 0, "delete channel = %V", &listen->channel);
                ngx_http_push_stream_delete_channel_my(c->log, &listen->channel, (u_char *)"channel unlisten", sizeof("channel unlisten") - 1, c->pool);
                ngx_queue_remove(&listen->queue);
            }
        }
        PQfinish(common->conn);
        common->conn = NULL;
    }
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
    if (c->pool && !c->close) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }
    ngx_free_connection(c);
    c->fd = (ngx_socket_t) -1;
}


static ngx_flag_t is_variable_character(u_char p) {
    return ((p >= '0' && p <= '9') || (p >= 'a' && p <= 'z') || (p >= 'A' && p <= 'Z') || p == '_');
}


#define IDOID 9999




static ngx_uint_t type2oid(ngx_str_t *type) {
    static const ngx_conf_enum_t e[] = {
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
    for (ngx_uint_t i = 0; e[i].name.len; i++) if (e[i].name.len - 3 == type->len && !ngx_strncasecmp(e[i].name.data, type->data, type->len)) return e[i].value;
    return 0;
}


char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    ngx_postgres_location_t *location = conf;
    if (!location->queries.elts && ngx_array_init(&location->queries, cf->pool, 1, sizeof(ngx_postgres_query_t)) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_query_t *query = location->query = ngx_array_push(&location->queries);
    if (!query) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(query, sizeof(*query));
    ngx_uint_t j = 1;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (i == 1 && elts[i].len == sizeof("prepare") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"prepare", sizeof("prepare") - 1)) {
            query->prepare = 1;
            j = i + 1;
        } else if (elts[i].len > sizeof("timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            j = i + 1;
            elts[i].len = elts[i].len - (sizeof("timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 0);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be time", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be positive", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            query->timeout = (ngx_msec_t)n;
        }
    }
    ngx_str_t sql = ngx_null_string;
    for (ngx_uint_t i = j; i < cf->args->nelts; i++) {
        if (i > j) sql.len++;
        sql.len += elts[i].len;
    }
    if (!sql.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty query", &cmd->name); return NGX_CONF_ERROR; }
    if (!(sql.data = ngx_pnalloc(cf->pool, sql.len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    u_char *q = sql.data;
    for (ngx_uint_t i = j; i < cf->args->nelts; i++) {
        if (i > j) *q++ = ' ';
        q = ngx_cpymem(q, elts[i].data, elts[i].len);
    }
    if (!(query->sql.data = ngx_pnalloc(cf->pool, sql.len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    if (ngx_array_init(&query->params, cf->pool, 1, sizeof(ngx_postgres_param_t)) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    if (ngx_array_init(&query->ids, cf->pool, 1, sizeof(ngx_uint_t)) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
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
            if (index == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_http_get_variable_index == NGX_ERROR", &cmd->name); return NGX_CONF_ERROR; }
            ngx_uint_t oid = type2oid(&type);
            if (!oid) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !type2oid", &cmd->name); return NGX_CONF_ERROR; }
            if (oid == IDOID) {
                ngx_uint_t *id = ngx_array_push(&query->ids);
                if (!id) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
                *id = (ngx_uint_t) index;
                *p++ = '%';
                *p++ = 'V';
            } else {
                ngx_postgres_param_t *param = ngx_array_push(&query->params);
                if (!param) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
                param->index = (ngx_uint_t) index;
                param->oid = oid;
                p += ngx_sprintf(p, "$%i", ++k) - p;
            }
            if (s >= e) break;
        }
    }
    ngx_pfree(cf->pool, sql.data);
    query->sql.len = p - query->sql.data;
    query->listen = query->sql.len > sizeof("LISTEN ") - 1 && !ngx_strncasecmp(query->sql.data, (u_char *)"LISTEN ", sizeof("LISTEN ") - 1);
    if (query->listen && !ngx_http_push_stream_add_msg_to_channel_my && !ngx_http_push_stream_delete_channel_my) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: LISTEN requires ngx_http_push_stream_module!", &cmd->name); return NGX_CONF_ERROR; }
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
