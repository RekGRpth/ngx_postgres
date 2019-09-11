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

#include "ngx_postgres_keepalive.h"


static void ngx_postgres_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_postgres_keepalive_close_handler(ngx_event_t *ev);


ngx_int_t ngx_postgres_keepalive_init(ngx_pool_t *pool, ngx_postgres_upstream_srv_conf_t *pgscf) {
    ngx_postgres_keepalive_cache_t *cached = ngx_pcalloc(pool, sizeof(ngx_postgres_keepalive_cache_t) * pgscf->max_cached);
    if (!cached) { ngx_log_error(NGX_LOG_ERR, pool->log, 0, "%s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    ngx_queue_init(&pgscf->cache);
    ngx_queue_init(&pgscf->free);
    for (ngx_uint_t i = 0; i < pgscf->max_cached; i++) {
        ngx_queue_insert_head(&pgscf->free, &cached[i].queue);
        cached[i].pgscf = pgscf;
    }
    return NGX_OK;
}


ngx_int_t ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    if (ngx_queue_empty(&pgdt->pgscf->cache)) return NGX_DECLINED;
    ngx_queue_t *q = ngx_queue_head(&pgdt->pgscf->cache);
    ngx_queue_remove(q);
    ngx_postgres_keepalive_cache_t *cached = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
    ngx_queue_insert_head(&pgdt->pgscf->free, q);
    cached->connection->idle = 0;
    cached->connection->log = pc->log;
    cached->connection->pool->log = pc->log;
    cached->connection->read->log = pc->log;
    cached->connection->write->log = pc->log;
    pgdt->name.data = cached->name.data;
    pgdt->name.len = cached->name.len;
    pgdt->sockaddr = cached->sockaddr;
    pgdt->pgconn = cached->pgconn;
    pc->connection = cached->connection;
    pc->cached = 1;
    pc->name = &pgdt->name;
    pc->sockaddr = &pgdt->sockaddr;
    pc->socklen = cached->socklen;
    return NGX_DONE;
}


ngx_int_t ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    ngx_queue_t *cache = &pgdt->pgscf->cache;
    for (ngx_queue_t *q = ngx_queue_head(cache); q != ngx_queue_sentinel(cache); q = ngx_queue_next(q)) {
        ngx_postgres_keepalive_cache_t *cached = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
        if (ngx_memn2cmp((u_char *) &cached->sockaddr, (u_char *) pc->sockaddr, cached->socklen, pc->socklen)) continue;
        ngx_queue_remove(q);
        ngx_queue_insert_head(&pgdt->pgscf->free, q);
        cached->connection->idle = 0;
        cached->connection->log = pc->log;
        cached->connection->pool->log = pc->log;
        cached->connection->read->log = pc->log;
        cached->connection->write->log = pc->log;
        pc->connection = cached->connection;
        pc->cached = 1;
        /* we do not need to resume the peer name, because we already take the right value outside */
        pgdt->pgconn = cached->pgconn;
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


void ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt, ngx_uint_t  state) {
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->pgscf;
    ngx_postgres_keepalive_cache_t  *cached;
    ngx_queue_t                     *q;
    ngx_connection_t                *c;
    ngx_http_upstream_t             *u;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s entering", __func__);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "postgres: free keepalive peer");

    if (state & NGX_PEER_FAILED) {
        pgdt->failed = 1;
    }

    u = pgdt->upstream;

    if ((!pgdt->failed) && (pc->connection != NULL)
        && (u->headers_in.status_n == NGX_HTTP_OK))
    {
        c = pc->connection;

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        if (c->write->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
            if (ngx_del_event(c->write, NGX_WRITE_EVENT, 0) != NGX_OK) {
                return;
            }
        }

        pc->connection = NULL;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "postgres: free keepalive peer: saving connection %p",
                       c);

        if (ngx_queue_empty(&pgscf->free)) {
            /* connection pool is already full */

            q = ngx_queue_last(&pgscf->cache);
            ngx_queue_remove(q);

            cached = ngx_queue_data(q, ngx_postgres_keepalive_cache_t,
                                  queue);

            ngx_postgres_upstream_free_connection(cached->connection, cached->pgconn, pgscf);

        } else {
            q = ngx_queue_head(&pgscf->free);
            ngx_queue_remove(q);

            cached = ngx_queue_data(q, ngx_postgres_keepalive_cache_t,
                                  queue);
        }

        cached->connection = c;

        ngx_queue_insert_head(&pgscf->cache, q);

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

        cached->name.data = pgdt->name.data;
        cached->name.len = pgdt->name.len;

    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s returning", __func__);
}

static void
ngx_postgres_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s entering & returning (dummy handler)", __func__);
}

static void
ngx_postgres_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_postgres_upstream_srv_conf_t  *pgscf;
    ngx_postgres_keepalive_cache_t    *cached;
    ngx_connection_t                  *c;
    PGresult                          *res;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s entering", __func__);

    c = ev->data;
    cached = c->data;

    if (c->close) {
        goto close;
    }

    if (PQconsumeInput(cached->pgconn) && !PQisBusy(cached->pgconn)) {
        res = PQgetResult(cached->pgconn);
        if (res == NULL) {
            for (PGnotify *notify; (notify = PQnotifies(cached->pgconn)); PQfreemem(notify)) {
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ev->log, 0, "postgres notify: relname=\"%s\", extra=\"%s\", be_pid=%d.", notify->relname, notify->extra, notify->be_pid);
                ngx_str_t id = { strlen(notify->relname), (u_char *) notify->relname };
                ngx_str_t text = { strlen(notify->extra), (u_char *) notify->extra };
                ngx_http_push_stream_add_msg_to_channel_my(c->log, &id, &text, NULL, NULL, 0, c->pool);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s returning", __func__);
            return;
        }

        PQclear(res);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s received result on idle keepalive connection", __func__);
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "postgres: received result on idle keepalive connection");
    }

close:

    pgscf = cached->pgscf;

    ngx_postgres_upstream_free_connection(c, cached->pgconn, pgscf);

    ngx_queue_remove(&cached->queue);
    ngx_queue_insert_head(&pgscf->free, &cached->queue);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s returning", __func__);
}


void ngx_postgres_keepalive_cleanup(void *data) {
    ngx_postgres_upstream_srv_conf_t *pgscf = data;
    /* ngx_queue_empty is broken when used on unitialized queue */
    if (!pgscf->cache.prev) return;
    /* just to be on the safe-side */
    pgscf->max_cached = 0;
    while (!ngx_queue_empty(&pgscf->cache)) {
        ngx_queue_t *q = ngx_queue_head(&pgscf->cache);
        ngx_queue_remove(q);
        ngx_postgres_keepalive_cache_t *cached = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pgscf->pool->log, 0, "%s postgres: disconnecting %p", __func__, cached->connection);
        ngx_postgres_upstream_free_connection(cached->connection, cached->pgconn, pgscf);
    }
}
