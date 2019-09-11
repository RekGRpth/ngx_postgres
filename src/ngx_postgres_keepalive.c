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


static void
ngx_postgres_keepalive_dummy_handler(ngx_event_t *ev);
static void
ngx_postgres_keepalive_close_handler(ngx_event_t *ev);


ngx_int_t
ngx_postgres_keepalive_init(ngx_pool_t *pool,
    ngx_postgres_upstream_srv_conf_t *pgscf)
{
    ngx_postgres_keepalive_cache_t  *cached;
    ngx_uint_t                       i;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "%s entering", __func__);

    cached = ngx_pcalloc(pool,
                 sizeof(ngx_postgres_keepalive_cache_t) * pgscf->max_cached);
    if (cached == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "%s returning NGX_ERROR", __func__);
        return NGX_ERROR;
    }

    ngx_queue_init(&pgscf->cache);
    ngx_queue_init(&pgscf->free);

    for (i = 0; i < pgscf->max_cached; i++) {
        ngx_queue_insert_head(&pgscf->free, &cached[i].queue);
        cached[i].srv_conf = pgscf;
        if (pgscf->max_statements && !(cached[i].statements = ngx_pcalloc(pool, pgscf->max_statements * sizeof(ngx_uint_t)))) return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "%s returning NGX_OK", __func__);
    return NGX_OK;
}

ngx_int_t ngx_postgres_keepalive_get_peer_single(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->srv_conf;
    ngx_postgres_keepalive_cache_t  *item;
    ngx_queue_t                     *q;
    ngx_connection_t                *c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s entering", __func__);

    if (!ngx_queue_empty(&pgscf->cache)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s non-empty queue", __func__);

        q = ngx_queue_head(&pgscf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
        c = item->connection;

        ngx_queue_insert_head(&pgscf->free, q);

        c->idle = 0;
        c->log = pc->log;
        c->pool->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;

        pgdt->name.data = item->name.data;
        pgdt->name.len = item->name.len;

        pgdt->sockaddr = item->sockaddr;

        pgdt->pgconn = item->pgconn;

        pc->connection = c;
        pc->cached = 1;

        pc->name = &pgdt->name;

        pc->sockaddr = &pgdt->sockaddr;
        pc->socklen = item->socklen;

        /* Inherit list of prepared statements */
        ngx_uint_t j;
        for (j = 0; j < pgscf->max_statements; j++)
            pgdt->statements[j] = item->statements[j];

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s returning NGX_DONE", __func__);

        return NGX_DONE;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s returning NGX_DECLINED", __func__);
    return NGX_DECLINED;
}

ngx_int_t ngx_postgres_keepalive_get_peer_multi(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt) {
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->srv_conf;
    ngx_postgres_keepalive_cache_t  *item;
    ngx_queue_t                     *q, *cache;
    ngx_connection_t                *c;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s entering", __func__);

    cache = &pgscf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
        c = item->connection;

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                item->socklen, pc->socklen) == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&pgscf->free, q);

            c->idle = 0;
            c->log = pc->log;
            c->pool->log = pc->log;
            c->read->log = pc->log;
            c->write->log = pc->log;

            pc->connection = c;
            pc->cached = 1;

            /* we do not need to resume the peer name
             * because we already take the right value outside */

            pgdt->pgconn = item->pgconn;

            /* Inherit list of prepared statements */
            ngx_uint_t j;
            for (j = 0; j < pgscf->max_statements; j++)
                pgdt->statements[j] = item->statements[j];

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s returning NGX_DONE", __func__);
            return NGX_DONE;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s returning NGX_DECLINED", __func__);
    return NGX_DECLINED;
}

void ngx_postgres_keepalive_free_peer(ngx_peer_connection_t *pc, ngx_postgres_upstream_peer_data_t *pgdt, ngx_uint_t  state) {
    ngx_postgres_upstream_srv_conf_t *pgscf = pgdt->srv_conf;
    ngx_postgres_keepalive_cache_t  *item;
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

            item = ngx_queue_data(q, ngx_postgres_keepalive_cache_t,
                                  queue);

            ngx_postgres_upstream_free_connection(item->connection, item->pgconn, pgscf);

        } else {
            q = ngx_queue_head(&pgscf->free);
            ngx_queue_remove(q);

            item = ngx_queue_data(q, ngx_postgres_keepalive_cache_t,
                                  queue);
        }

        ngx_uint_t j;
        for (j = 0; j < pgscf->max_statements; j++)
            item->statements[j] = pgdt->statements[j];
        item->connection = c;

        ngx_queue_insert_head(&pgscf->cache, q);

        c->write->handler = ngx_postgres_keepalive_dummy_handler;
        c->read->handler = ngx_postgres_keepalive_close_handler;

        c->data = item;
        c->idle = 1;
        c->log = ngx_cycle->log;
        c->pool->log = ngx_cycle->log;
        c->read->log = ngx_cycle->log;
        c->write->log = ngx_cycle->log;

        item->socklen = pc->socklen;
        ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

        item->pgconn = pgdt->pgconn;

        item->name.data = pgdt->name.data;
        item->name.len = pgdt->name.len;

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
    ngx_postgres_keepalive_cache_t    *item;
    ngx_connection_t                  *c;
    PGresult                          *res;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "%s entering", __func__);

    c = ev->data;
    item = c->data;

    if (c->close) {
        goto close;
    }

    if (PQconsumeInput(item->pgconn) && !PQisBusy(item->pgconn)) {
        res = PQgetResult(item->pgconn);
        if (res == NULL) {
            for (PGnotify *notify; (notify = PQnotifies(item->pgconn)); PQfreemem(notify)) {
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

    pgscf = item->srv_conf;

    ngx_postgres_upstream_free_connection(c, item->pgconn, pgscf);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&pgscf->free, &item->queue);

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
        ngx_postgres_keepalive_cache_t *item = ngx_queue_data(q, ngx_postgres_keepalive_cache_t, queue);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pgscf->pool->log, 0, "%s postgres: disconnecting %p", __func__, item->connection);
        ngx_postgres_upstream_free_connection(item->connection, item->pgconn, pgscf);
    }
}
