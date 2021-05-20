#include <pg_config.h>
#include <postgresql/server/catalog/pg_type_d.h>
#include "ngx_postgres_include.h"


ngx_int_t ngx_postgres_notify(ngx_connection_t *c, PGconn *conn) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_array_t listen;
    if (ngx_array_init(&listen, c->pool, 1, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
    char *escape;
    ngx_str_t str = ngx_null_string;
    PGnotify *notify;
    for (; PQstatus(conn) == CONNECTION_OK && (notify = PQnotifies(conn)); ) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "relname=%s, extra=%s, be_pid=%i", notify->relname, notify->extra, notify->be_pid);
        if (!ngx_http_push_stream_add_msg_to_channel_my) { PQfreemem(notify); continue; }
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *) notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *) notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(4096 + id.len + text.len, c->log);
        if (!temp_pool) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_create_pool"); goto notify; }
        ngx_int_t rc = ngx_http_push_stream_add_msg_to_channel_my(c->log, &id, &text, NULL, NULL, 1, temp_pool);
        ngx_destroy_pool(temp_pool);
        switch (rc) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); goto notify;
            case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
                ngx_str_t *command = ngx_array_push(&listen);
                if (!command) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_array_push"); goto notify; }
                if (!(escape = PQescapeIdentifier(conn, (const char *)id.data, id.len))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQescapeIdentifier(%V) and %s", &id, PQerrorMessageMy(conn)); goto notify; }
                if (!(command->data = ngx_pnalloc(c->pool, command->len = sizeof("UNLISTEN ;") - 1 + ngx_strlen(escape)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); goto escape; }
                command->len = ngx_snprintf(command->data, command->len, "UNLISTEN %s;", escape) - command->data;
                str.len += command->len;
                PQfreemem(escape);
            } break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); c->requests++; break;
            default: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == %i", rc); goto notify;
        }
        PQfreemem(notify);
        switch (ngx_postgres_consume_flush_busy(c, conn)) {
            case NGX_AGAIN: goto again;
            case NGX_ERROR: goto error;
            default: break;
        }
    }
    if (!str.len) goto ok;
    if (!(str.data = ngx_pnalloc(c->pool, str.len + 1))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); goto error; }
    ngx_str_t *command = listen.elts;
    for (ngx_uint_t i = 0; i < listen.nelts; i++) {
        ngx_memcpy(str.data, command[i].data, command[i].len);
        ngx_pfree(c->pool, command[i].data);
    }
    str.data[str.len] = '\0';
    if (!PQsendQuery(conn, (const char *)str.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%V\") and %s", &str, PQerrorMessageMy(conn)); goto error; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(\"%V\")", &str);
ok:
    ngx_array_destroy(&listen);
    return NGX_OK;
again:
    ngx_array_destroy(&listen);
    return NGX_AGAIN;
escape:
    PQfreemem(escape);
notify:
    PQfreemem(notify);
error:
    ngx_array_destroy(&listen);
    return NGX_ERROR;
}


static ngx_int_t ngx_postgres_idle(ngx_postgres_save_t *ps) {
    ngx_connection_t *c = ps->connection;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    for (PGresult *res; PQstatus(ps->conn) == CONNECTION_OK && (res = PQgetResult(ps->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
            default: ngx_log_error(NGX_LOG_WARN, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(c, ps->conn)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_result(ngx_postgres_save_t *ps, PGresult *res) {
    ngx_connection_t *c = ps->connection;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    if (!PQntuples(res)) return NGX_OK;
    for (ngx_uint_t row = 0; row < PQntuples(res); row++) {
        const char *schannel = PQgetvalue(res, row, PQfnumber(res, "channel"));
        const char *sunlisten = PQgetvalue(res, row, PQfnumber(res, "unlisten"));
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "row = %i, channel = %s, unlisten = %s", row, schannel, sunlisten);
        ngx_str_t channel = {ngx_strlen(schannel), (u_char *)schannel};
        ngx_str_t unlisten = {ngx_strlen(sunlisten), (u_char *)sunlisten};
        ngx_http_push_stream_delete_channel_my(c->log, &channel, unlisten.data, unlisten.len, c->pool);
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_listen_result(ngx_postgres_save_t *ps) {
    ngx_connection_t *c = ps->connection;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ps->handler = ngx_postgres_listen_result;
    ngx_int_t rc = NGX_OK;
    for (PGresult *res; PQstatus(ps->conn) == CONNECTION_OK && (res = PQgetResult(ps->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_TUPLES_OK: rc = ngx_postgres_result(ps, res); break;
            default: ngx_log_error(NGX_LOG_WARN, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); rc = NGX_ERROR; break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(c, ps->conn)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    ngx_postgres_close(c, ps->conn, ps->usc);
    return rc;
}


static ngx_int_t ngx_postgres_listen(ngx_postgres_save_t *ps) {
    ngx_connection_t *c = ps->connection;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ps->handler = ngx_postgres_listen;
    for (PGresult *res; PQstatus(ps->conn) == CONNECTION_OK && (res = PQgetResult(ps->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
            default: ngx_log_error(NGX_LOG_WARN, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(c, ps->conn)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    static const char *command = "SELECT channel, concat_ws(' ', 'UNLISTEN', quote_ident(channel)) AS unlisten FROM pg_listening_channels() AS channel";
    if (!PQsendQuery(ps->conn, command)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%s\") and %s", command, PQerrorMessageMy(ps->conn)); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(\"%s\")", command);
    ps->handler = ngx_postgres_listen_result;
    return NGX_OK;
}


static void ngx_postgres_save_close(ngx_postgres_save_t *ps) {
    ngx_connection_t *c = ps->connection;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    if (!ngx_terminate && !ngx_exiting && ngx_http_push_stream_delete_channel_my && ngx_postgres_listen(ps) != NGX_ERROR) return;
    ngx_postgres_close(c, ps->conn, ps->usc);
}


static void ngx_postgres_save_handler(ngx_event_t *ev) {
    ngx_connection_t *c = ev->data;
    c->log->connection = c->number;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "write = %s", ev->write ? "true" : "false");
    ngx_postgres_save_t *ps = c->data;
    if (c->close) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "close"); goto close; }
    if (c->read->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "timedout"); goto close; }
    if (c->write->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "timedout"); goto close; }
    switch (ngx_postgres_consume_flush_busy(c, ps->conn)) {
        case NGX_AGAIN: return;
        case NGX_ERROR: goto close;
        default: break;
    }
    switch (ngx_postgres_notify(c, ps->conn)) {
        case NGX_AGAIN: return;
        case NGX_ERROR: goto close;
        default: break;
    }
    if (ps->handler(ps) != NGX_ERROR) return;
close:
    ngx_postgres_save_close(ps);
    ngx_queue_remove(&ps->item);
    ngx_postgres_upstream_srv_conf_t *usc = ps->usc;
    ngx_queue_insert_tail(&usc->ps.data.head, &ps->item);
}


#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
static ngx_int_t ngx_postgres_next(ngx_connection_t *c, ngx_postgres_upstream_srv_conf_t *usc) {
    ngx_queue_each(&usc->pd.head, item) {
        ngx_queue_remove(item);
        ngx_postgres_data_t *pd = ngx_queue_data(item, ngx_postgres_data_t, item);
        if (usc->pd.size) usc->pd.size--;
        if (pd->timeout.timer_set) ngx_del_timer(&pd->timeout);
        ngx_http_request_t *r = pd->request;
        if (!r->connection || r->connection->error) continue;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "pd = %p", pd);
        c->data = pd;
        c->idle = 0;
        c->log = r->connection->log;
        c->pool->log = r->connection->log;
        c->read->handler = ngx_postgres_data_handler;
        c->read->log = r->connection->log;
        c->read->timedout = 0;
        c->sent = 0;
        c->write->handler = ngx_postgres_data_handler;
        c->write->log = r->connection->log;
        c->write->timedout = 0;
        r->state = 0;
        ngx_queue_init(item);
        return ngx_postgres_prepare_or_query(pd);
    }
    return NGX_OK;
}
#endif


static void ngx_postgres_free_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    ngx_connection_t *c = pd->connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_postgres_upstream_srv_conf_t *usc = pd->usc;
    if (c->requests >= usc->ps.save.requests) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "requests = %i", c->requests); return; }
    switch (PQtransactionStatus(pd->conn)) {
        case PQTRANS_UNKNOWN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus == PQTRANS_UNKNOWN"); return;
        case PQTRANS_IDLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus == PQTRANS_IDLE"); break;
        default: ngx_log_error(NGX_LOG_WARN, pc->log, 0, "PQtransactionStatus != PQTRANS_IDLE"); if (!PQrequestCancel(pd->conn)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!PQrequestCancel and %s", PQerrorMessageMy(pd->conn)); return; } break;
    }
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    switch (ngx_postgres_next(c, usc)) {
        case NGX_ERROR: return;
        case NGX_OK: break;
        default: pc->connection = NULL; return;
    }
#endif
    ngx_queue_t *item;
    if (!ngx_queue_empty(&usc->ps.data.head)) item = ngx_queue_head(&usc->ps.data.head); else {
        ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ngx_queue_empty(data)");
        item = ngx_queue_last(&usc->ps.save.head);
        ngx_postgres_save_t *ps = ngx_queue_data(item, ngx_postgres_save_t, item);
        ngx_postgres_save_close(ps);
    }
    ngx_queue_remove(item);
    ngx_queue_insert_tail(&usc->ps.save.head, item);
    ngx_postgres_save_t *ps = ngx_queue_data(item, ngx_postgres_save_t, item);
    ngx_log_t *log = usc->ps.save.log ? usc->ps.save.log : ngx_cycle->log;
    c->data = ps;
    c->idle = 1;
    c->log = log;
    c->pool->log = log;
    c->read->handler = ngx_postgres_save_handler;
    c->read->log = log;
    c->read->timedout = 0;
    c->sent = 0;
    c->write->handler = ngx_postgres_save_handler;
    c->write->log = log;
    c->write->timedout = 0;
    log->connection = c->number;
    pc->connection = NULL;
    ps->connection = c;
    ps->conn = pd->conn;
    ps->handler = ngx_postgres_idle;
    ps->prepare = pd->prepare;
    ps->usc = usc;
    ps->sockaddr = pc->sockaddr;
    ps->socklen = pc->socklen;
    ngx_add_timer(c->read, usc->ps.save.timeout);
    ngx_add_timer(c->write, usc->ps.save.timeout);
}


static ngx_postgres_save_t *ngx_postgres_save_create(ngx_connection_t *c, ngx_log_t *log) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_postgres_save_t *ps = ngx_pcalloc(c->pool, sizeof(*ps));
    if (!ps) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); return NULL; }
    c->data = ps;
    c->idle = 1;
    c->log = log;
    c->pool->log = log;
    c->read->handler = ngx_postgres_save_handler;
    c->read->log = log;
    c->read->timedout = 0;
    c->sent = 0;
    c->write->handler = ngx_postgres_save_handler;
    c->write->log = log;
    c->write->timedout = 0;
    log->connection = c->number;
    ps->connection = c;
    return ps;
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    ngx_postgres_data_t *pd = data;
    ngx_postgres_upstream_srv_conf_t *usc = pd->usc;
    ngx_connection_t *c = pc->connection;
    if (ngx_terminate || ngx_exiting || !c || c->error || c->read->error || c->write->error || (state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout));
    else if (usc->ps.save.max) ngx_postgres_free_peer(pc, data);
    if (pc->connection) {
        ngx_postgres_save_t *ps = ngx_postgres_save_create(c, usc->ps.save.log ? usc->ps.save.log : ngx_cycle->log);
        if (!ps) ngx_postgres_close(c, pd->conn, usc); else {
            ps->conn = pd->conn;
            ps->usc = usc;
            ngx_postgres_save_close(ps);
        }
    }
    pc->connection = NULL;
    pd->peer.free(pc, pd->peer.data, state);
}


#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
static void ngx_postgres_data_cleanup(void *data) {
    ngx_postgres_data_t *pd = data;
    ngx_http_request_t *r = pd->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!ngx_queue_empty(&pd->item)) ngx_queue_remove(&pd->item);
    ngx_postgres_upstream_srv_conf_t *usc = pd->usc;
    if (usc->pd.size) usc->pd.size--;
    if (pd->timeout.timer_set) ngx_del_timer(&pd->timeout);
}


static void ngx_postgres_data_timeout(ngx_event_t *ev) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0, "write = %s", ev->write ? "true" : "false");
    ngx_http_request_t *r = ev->data;
    if (!r->connection || r->connection->error) return;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
}
#endif


ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    ngx_int_t rc = pd->peer.get(pc, pd->peer.data);
    if (rc != NGX_OK) return rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "rc = %i", rc);
    ngx_postgres_upstream_srv_conf_t *usc = pd->usc;
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_postgres_connect_t *connect = pc->peer_data;
#else
    ngx_array_t *array = usc->connect;
    ngx_postgres_connect_t *connect = array->elts;
    ngx_uint_t i;
    for (i = 0; i < array->nelts; i++) for (ngx_uint_t j = 0; j < connect[i].naddrs; j++) {
        if (ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)connect[i].addrs[j].sockaddr, pc->socklen, connect[i].addrs[j].socklen)) continue;
        connect = &connect[i];
        goto exit;
    }
exit:
    if (i == array->nelts) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connect not found"); return NGX_BUSY; } // and ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE) and return
#endif
    ngx_http_request_t *r = pd->request;
    ngx_http_upstream_t *u = r->upstream;
#if (HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS)
    u->connect_timeout = connect->timeout;
#else
    u->conf->connect_timeout = connect->timeout;
#endif
    if (usc->ps.save.max) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ps.max");
        ngx_queue_each(&usc->ps.save.head, item) {
            ngx_postgres_save_t *ps = ngx_queue_data(item, ngx_postgres_save_t, item);
            if (ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)ps->sockaddr, pc->socklen, ps->socklen)) continue;
            ngx_queue_remove(item);
            ngx_queue_insert_tail(&usc->ps.data.head, item);
            ngx_connection_t *c = ps->connection;
            c->idle = 0;
            c->log_error = pc->log_error;
            c->log = pc->log;
            c->pool->log = pc->log;
            c->read->log = pc->log;
            c->read->timedout = 0;
            c->sent = 0;
            c->write->log = pc->log;
            c->write->timedout = 0;
            pc->cached = 1;
            pc->connection = c;
            pd->connection = c;
            pd->conn = ps->conn;
            pd->prepare = ps->prepare;
            if (c->read->timer_set) ngx_del_timer(c->read);
            if (c->write->timer_set) ngx_del_timer(c->write);
            return ngx_postgres_prepare_or_query(pd);
        }
        if (usc->ps.save.size < usc->ps.save.max) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ps.size = %i", usc->ps.save.size);
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
        } else if (usc->pd.max) {
            if (usc->pd.size < usc->pd.max) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pd = %p", pd);
                ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
                if (!cln) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
                cln->handler = ngx_postgres_data_cleanup;
                cln->data = pd;
                ngx_queue_insert_tail(&usc->pd.head, &pd->item);
                usc->pd.size++;
                pd->timeout.handler = ngx_postgres_data_timeout;
                pd->timeout.log = pc->log;
                pd->timeout.data = r;
                ngx_add_timer(&pd->timeout, usc->pd.timeout);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "pd.size = %i", usc->pd.size);
                return NGX_YIELD; // and return
            } else if (usc->pd.reject) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0, "pd.size = %i", usc->pd.size);
                return NGX_BUSY; // and ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE) and return
            }
#endif
        } else if (usc->ps.save.reject) {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ps.size = %i", usc->ps.save.size);
            return NGX_BUSY; // and ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE) and return
        }
    }
    ngx_str_t addr;
    if (!(addr.data = ngx_pcalloc(r->pool, NGX_SOCKADDR_STRLEN + 1))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pnalloc"); goto error; }
    if (!(addr.len = ngx_sock_ntop(pc->sockaddr, pc->socklen, addr.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_sock_ntop"); goto error; }
    const char *host = connect->values[0];
    if (host) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "host = %s", host);
    connect->values[0] = (const char *)addr.data + (pc->sockaddr->sa_family == AF_UNIX ? 5 : 0);
    for (int i = 0; connect->keywords[i]; i++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i: %s = %s", i, connect->keywords[i], connect->values[i]);
    pd->conn = PQconnectStartParams(connect->keywords, connect->values, 0);
    connect->values[0] = host;
    if (PQstatus(pd->conn) == CONNECTION_BAD) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQstatus == CONNECTION_BAD %s in upstream \"%V\"", PQerrorMessageMy(pd->conn), pc->name); goto declined; }
    if (PQsetnonblocking(pd->conn, 1) == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsetnonblocking == -1 and %s in upstream \"%V\"", PQerrorMessageMy(pd->conn), pc->name); goto declined; }
    usc->ps.save.size++;
    if (usc->trace.log) PQtrace(pd->conn, fdopen(usc->trace.log->file->fd, "a+"));
    pgsocket fd;
    if ((fd = PQsocket(pd->conn)) == PGINVALID_SOCKET) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsocket == PGINVALID_SOCKET"); goto declined; }
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!(pd->connection = c)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); goto finish; }
    c->log_error = pc->log_error;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->read->log = pc->log;
    c->shared = 1;
    c->start_time = ngx_current_msec;
    c->type = pc->type ? pc->type : SOCK_STREAM;
    c->write->log = pc->log;
    if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); goto close; }
    if (!(pd->prepare = ngx_pcalloc(c->pool, sizeof(*pd->prepare)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_conn != NGX_OK"); goto destroy; }
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
    }
    c->read->ready = 1;
    c->write->ready = 1;
    pc->connection = c;
    ngx_queue_init(&pd->prepare->head);
    pd->handler = ngx_postgres_connect;
    ngx_log_error(NGX_LOG_WARN, pc->log, 0, "PQconnectStartParams");
    return NGX_AGAIN; // and ngx_add_timer(c->write, u->conf->connect_timeout) and return
declined:
    PQfinish(pd->conn);
    pd->conn = NULL;
    return NGX_DECLINED; // and ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR) and return
destroy:
    ngx_destroy_pool(c->pool);
    c->pool = NULL;
close:
    ngx_close_connection(c);
    pd->connection = NULL;
finish:
    PQfinish(pd->conn);
    pd->conn = NULL;
error:
    return NGX_ERROR; // ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR) and return
}


typedef struct {
    ngx_uint_t index;
    ngx_uint_t oid;
} ngx_postgres_param_t;


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_postgres_set_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    return pd->peer.set_session(pc, pd->peer.data);
}


static void ngx_postgres_save_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = data;
    pd->peer.save_session(pc, pd->peer.data);
}
#endif


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *usc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_data_t *pd = ngx_pcalloc(r->pool, sizeof(*pd));
    if (!pd) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    pd->usc = ngx_http_conf_upstream_srv_conf(usc, ngx_postgres_module);
    if (pd->usc->peer_init(r, usc) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer_init != NGX_OK"); return NGX_ERROR; }
    pd->request = r;
    ngx_http_upstream_t *u = r->upstream;
    pd->peer = u->peer;
    u->peer.data = pd;
    u->peer.get = ngx_postgres_peer_get;
    u->peer.free = ngx_postgres_peer_free;
#if (NGX_HTTP_SSL)
    u->peer.save_session = ngx_postgres_save_session;
    u->peer.set_session = ngx_postgres_set_session;
#endif
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (ngx_array_init(&pd->send, r->pool, location->query.nelts, sizeof(ngx_postgres_send_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
    ngx_memzero(pd->send.elts, location->query.nelts * pd->send.size);
    pd->send.nelts = location->query.nelts;
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_send_t *sendelts = pd->send.elts;
    ngx_uint_t nelts = 0;
    for (ngx_uint_t i = 0; i < location->query.nelts; i++) {
        ngx_postgres_query_t *query = &queryelts[i];
        ngx_postgres_send_t *send = &sendelts[i];
        send->binary = query->output.binary;
        if (!query->method || query->method & r->method); else continue;
        if (query->params.nelts) {
            ngx_postgres_param_t *param = query->params.elts;
            send->nParams = query->params.nelts;
            if (!(send->paramTypes = ngx_pnalloc(r->pool, query->params.nelts * sizeof(Oid)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(send->paramValues = ngx_pnalloc(r->pool, query->params.nelts * sizeof(char *)))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            for (ngx_uint_t i = 0; i < query->params.nelts; i++) {
                send->paramTypes[i] = param[i].oid;
                ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, param[i].index);
                if (!value || !value->data || !value->len) send->paramValues[i] = NULL; else {
                    if (!(send->paramValues[i] = ngx_pnalloc(r->pool, value->len + 1))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                    (void)ngx_cpystrn(send->paramValues[i], value->data, value->len + 1);
                }
            }
        }
        ngx_array_t *variable = &query->variable;
        nelts += variable->nelts;
    }
    if (nelts) {
        if (ngx_array_init(&pd->variable, r->pool, nelts, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_memzero(pd->variable.elts, nelts * pd->variable.size);
        pd->variable.nelts = nelts;
    }
    return NGX_OK;
}


void ngx_postgres_close(ngx_connection_t *c, PGconn *conn, ngx_postgres_upstream_srv_conf_t *usc) {
    if (usc->ps.save.size) usc->ps.save.size--;
    PQfinish(conn);
    if (c) {
        c->log->connection = c->number;
//        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "%s", __func__);
        if (ngx_del_conn) {
            ngx_del_conn(c, NGX_CLOSE_EVENT);
        } else {
            if (c->read->active || c->read->disabled) { ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT); }
            if (c->write->active || c->write->disabled) { ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT); }
        }
        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
    }
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
#if (PG_VERSION_NUM >= 130000)
#else
        { ngx_string("OPAQUEOID"), OPAQUEOID },
#endif
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
    ngx_str_t *args = cf->args->elts;
    ngx_postgres_location_t *location = conf;
    if (!location->query.elts && ngx_array_init(&location->query, cf->pool, 1, sizeof(ngx_postgres_query_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_query_t *query = ngx_array_push(&location->query);
    if (!query) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(query, sizeof(*query));
    static const ngx_conf_bitmask_t b[] = {
        { ngx_string("UNKNOWN"), NGX_HTTP_UNKNOWN },
        { ngx_string("GET"), NGX_HTTP_GET },
        { ngx_string("HEAD"), NGX_HTTP_HEAD },
        { ngx_string("POST"), NGX_HTTP_POST },
        { ngx_string("PUT"), NGX_HTTP_PUT },
        { ngx_string("DELETE"), NGX_HTTP_DELETE },
        { ngx_string("MKCOL"), NGX_HTTP_MKCOL },
        { ngx_string("COPY"), NGX_HTTP_COPY },
        { ngx_string("MOVE"), NGX_HTTP_MOVE },
        { ngx_string("OPTIONS"), NGX_HTTP_OPTIONS },
        { ngx_string("PROPFIND"), NGX_HTTP_PROPFIND },
        { ngx_string("PROPPATCH"), NGX_HTTP_PROPPATCH },
        { ngx_string("LOCK"), NGX_HTTP_LOCK },
        { ngx_string("UNLOCK"), NGX_HTTP_UNLOCK },
        { ngx_string("PATCH"), NGX_HTTP_PATCH },
        { ngx_string("TRACE"), NGX_HTTP_TRACE },
        { ngx_null_string, 0 }
    };
    ngx_uint_t i, j;
    for (j = 1; j < cf->args->nelts; j++) {
        for (i = 0; b[i].name.len; i++) if (b[i].name.len == args[j].len && !ngx_strncasecmp(b[i].name.data, args[j].data, b[i].name.len)) { query->method |= b[i].mask; break; }
        if (!b[i].name.len) break;
    }
//    if (query->method) j++;
    ngx_str_t sql = ngx_null_string;
    for (ngx_uint_t i = j; i < cf->args->nelts; i++) {
        if (i > j) sql.len++;
        sql.len += args[i].len;
    }
    if (!sql.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty query", &cmd->name); return NGX_CONF_ERROR; }
    if (!(sql.data = ngx_pnalloc(cf->pool, sql.len))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    u_char *q = sql.data;
    for (ngx_uint_t i = j; i < cf->args->nelts; i++) {
        if (i > j) *q++ = ' ';
        q = ngx_copy(q, args[i].data, args[i].len);
    }
    if (!(query->sql.data = ngx_pnalloc(cf->pool, sql.len))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    if (ngx_array_init(&query->params, cf->pool, 1, sizeof(ngx_postgres_param_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    if (ngx_array_init(&query->ids, cf->pool, 1, sizeof(ngx_uint_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
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
            ngx_str_t type = ngx_null_string;
            if (s[0] == ':' && s[1] == ':') for (s += 2, type.data = s, type.len = 0; s < e && is_variable_character(*s); s++, type.len++);
            if (!type.len) { *p++ = '$'; p = ngx_copy(p, name.data, name.len); continue; }
            ngx_int_t index = ngx_http_get_variable_index(cf, &name);
            if (index == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_http_get_variable_index == NGX_ERROR", &cmd->name); return NGX_CONF_ERROR; }
            ngx_uint_t oid = type2oid(&type);
            if (!oid) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !type2oid", &cmd->name); return NGX_CONF_ERROR; }
            if (oid == IDOID) {
                ngx_uint_t *id = ngx_array_push(&query->ids);
                if (!id) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
                *id = (ngx_uint_t) index;
                *p++ = '%';
                *p++ = 'V';
            } else {
                ngx_postgres_param_t *param = ngx_array_push(&query->params);
                if (!param) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
                param->index = (ngx_uint_t) index;
                param->oid = oid;
                p += ngx_sprintf(p, "$%i", ++k) - p;
            }
            if (s >= e) break;
        }
    }
    ngx_pfree(cf->pool, sql.data);
    query->sql.len = p - query->sql.data;
//    ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "sql = `%V`", &query->sql);
    return NGX_CONF_OK;
}
