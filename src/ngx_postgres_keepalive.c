/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * Copyright (C) 2008, Maxim Dounin
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <libpq-fe.h>

#include "ngx_postgres_keepalive.h"
#include "ngx_postgres_processor.h"


typedef struct {
    ngx_queue_t                        queue;
    ngx_postgres_srv_conf_t           *srv_conf;
    ngx_connection_t                  *connection;
    PGconn                            *pgconn;
    struct sockaddr                    sockaddr;
    socklen_t                          socklen;
    ngx_str_t                          name;
    ngx_postgres_statement_t          *statements;
} ngx_postgres_cached_t;


static void ngx_postgres_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_postgres_keepalive_close_handler(ngx_event_t *ev);


ngx_int_t ngx_postgres_keepalive_init(ngx_pool_t *pool, ngx_postgres_srv_conf_t *srv_conf) {
    ngx_postgres_cached_t *cached = ngx_pcalloc(pool, sizeof(ngx_postgres_cached_t) * srv_conf->max_cached);
    if (!cached) { ngx_log_error(NGX_LOG_ERR, pool->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_queue_init(&srv_conf->cache);
    ngx_queue_init(&srv_conf->free);
    for (ngx_uint_t i = 0; i < srv_conf->max_cached; i++) {
        ngx_queue_insert_head(&srv_conf->free, &cached[i].queue);
        cached[i].srv_conf = srv_conf;
        if (srv_conf->max_statements && !(cached[i].statements = ngx_pcalloc(pool, srv_conf->max_statements * sizeof(ngx_postgres_statement_t)))) { ngx_log_error(NGX_LOG_ERR, pool->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    if (ngx_queue_empty(&pgdt->srv_conf->cache)) return NGX_DECLINED;
    ngx_queue_t *q = ngx_queue_head(&pgdt->srv_conf->cache);
    ngx_queue_remove(q);
    ngx_postgres_cached_t *cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
    ngx_queue_insert_head(&pgdt->srv_conf->free, q);
    cached->connection->idle = 0;
    cached->connection->log = pc->log;
    cached->connection->pool->log = pc->log;
    cached->connection->read->log = pc->log;
    cached->connection->write->log = pc->log;
    pgdt->name = cached->name;
    pgdt->sockaddr = cached->sockaddr;
    pgdt->pgconn = cached->pgconn;
    pc->connection = cached->connection;
    pc->cached = 1;
    pc->name = &pgdt->name;
    pc->sockaddr = &pgdt->sockaddr;
    pc->socklen = cached->socklen;
    for (ngx_uint_t j = 0; j < pgdt->srv_conf->max_statements; j++) pgdt->statements[j] = cached->statements[j]; /* Inherit list of prepared statements */
    return NGX_DONE;
}


ngx_int_t ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    ngx_queue_t *cache = &pgdt->srv_conf->cache;
    for (ngx_queue_t *q = ngx_queue_head(cache); q != ngx_queue_sentinel(cache); q = ngx_queue_next(q)) {
        ngx_postgres_cached_t *cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
        if (ngx_memn2cmp((u_char *) &cached->sockaddr, (u_char *) pc->sockaddr, cached->socklen, pc->socklen)) continue;
        ngx_queue_remove(q);
        ngx_queue_insert_head(&pgdt->srv_conf->free, q);
        cached->connection->idle = 0;
        cached->connection->log = pc->log;
        cached->connection->pool->log = pc->log;
        cached->connection->read->log = pc->log;
        cached->connection->write->log = pc->log;
        pc->connection = cached->connection;
        pc->cached = 1;
        /* we do not need to resume the peer name, because we already take the right value outside */
        pgdt->pgconn = cached->pgconn;
        for (ngx_uint_t j = 0; j < pgdt->srv_conf->max_statements; j++) pgdt->statements[j] = cached->statements[j]; /* Inherit list of prepared statements */
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


void ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt, ngx_uint_t state) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: free keepalive peer");
    if (state & NGX_PEER_FAILED) pgdt->failed = 1;
    if (!pgdt->failed && pc->connection && pgdt->upstream->headers_in.status_n == NGX_HTTP_OK) {
        ngx_connection_t *c = pc->connection;
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
        if (c->write->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT) && ngx_del_event(c->write, NGX_WRITE_EVENT, 0) != NGX_OK) return;
        pc->connection = NULL;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "postgres: free keepalive peer: saving connection %p", c);
        ngx_queue_t *q;
        ngx_postgres_cached_t *cached;
        if (ngx_queue_empty(&pgdt->srv_conf->free)) { /* connection pool is already full */
            q = ngx_queue_last(&pgdt->srv_conf->cache);
            ngx_queue_remove(q);
            cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
            ngx_postgres_upstream_free_connection(cached->connection, cached->pgconn, pgdt->srv_conf);
        } else {
            q = ngx_queue_head(&pgdt->srv_conf->free);
            ngx_queue_remove(q);
            cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
        }
        for (ngx_uint_t j = 0; j < pgdt->srv_conf->max_statements; j++) cached->statements[j] = pgdt->statements[j];
        cached->connection = c;
        ngx_queue_insert_head(&pgdt->srv_conf->cache, q);
        c->write->handler = ngx_postgres_keepalive_dummy_handler;
        c->read->handler = ngx_postgres_keepalive_close_handler;
        c->data = cached;
        c->idle = 1;
        c->log = ngx_cycle->log;
        c->pool->log = ngx_cycle->log;
        c->read->log = ngx_cycle->log;
        c->write->log = ngx_cycle->log;
        cached->socklen = pc->socklen;
        ngx_memcpy(&cached->sockaddr, pc->sockaddr, pc->socklen);
        cached->pgconn = pgdt->pgconn;
        cached->name = pgdt->name;
    }
}


static void ngx_postgres_keepalive_dummy_handler(ngx_event_t *ev) { }


static void ngx_postgres_keepalive_close_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    ngx_postgres_cached_t *cached = c->data;
    if (c->close) goto close;
    if (!PQconsumeInput(cached->pgconn)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "postgres: failed to consume input: %s", PQerrorMessage(cached->pgconn)); goto close; }
    if (PQisBusy(cached->pgconn)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "postgres: busy while keepalive"); goto close; }
    for (PGresult *res; (res = PQgetResult(cached->pgconn)); PQclear(res)) { ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "postgres: received result on idle keepalive connection: %s: %s", PQresStatus(PQresultStatus(res)), PQresultErrorMessage(res)); }
    ngx_postgres_process_notify(c->log, c->pool, cached->pgconn);
    return;
close:
    ngx_postgres_upstream_free_connection(c, cached->pgconn, cached->srv_conf);
    ngx_queue_remove(&cached->queue);
    ngx_queue_insert_head(&cached->srv_conf->free, &cached->queue);
}


void ngx_postgres_keepalive_cleanup(void *data) {
    ngx_postgres_srv_conf_t *srv_conf = data;
    /* ngx_queue_empty is broken when used on unitialized queue */
    if (!srv_conf->cache.prev) return;
    /* just to be on the safe-side */
    srv_conf->max_cached = 0;
    while (!ngx_queue_empty(&srv_conf->cache)) {
        ngx_queue_t *q = ngx_queue_head(&srv_conf->cache);
        ngx_queue_remove(q);
        ngx_postgres_cached_t *cached = ngx_queue_data(q, ngx_postgres_cached_t, queue);
        ngx_postgres_upstream_free_connection(cached->connection, cached->pgconn, srv_conf);
    }
}
