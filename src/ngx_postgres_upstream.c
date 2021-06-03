#include <pg_config.h>
#include <postgresql/server/catalog/pg_type_d.h>
#include "ngx_postgres_include.h"


ngx_int_t ngx_postgres_notify(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_array_t listen;
    if (ngx_array_init(&listen, c->pool, 1, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
    char *escape;
    ngx_str_t str = ngx_null_string;
    PGnotify *notify;
    for (; PQstatus(s->conn) == CONNECTION_OK && (notify = PQnotifies(s->conn)); ) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "relname=%s, extra=%s, be_pid=%i", notify->relname, notify->extra, notify->be_pid);
        if (!ngx_http_push_stream_add_msg_to_channel_my) { PQfreemem(notify); continue; }
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *)notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *)notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(4096 + id.len + text.len, c->log);
        if (!temp_pool) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_create_pool"); goto notify; }
        ngx_int_t rc = ngx_http_push_stream_add_msg_to_channel_my(c->log, &id, &text, NULL, NULL, 1, temp_pool);
        ngx_destroy_pool(temp_pool);
        switch (rc) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); goto notify;
            case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
                ngx_str_t *command = ngx_array_push(&listen);
                if (!command) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_array_push"); goto notify; }
                if (!(escape = PQescapeIdentifier(s->conn, (const char *)id.data, id.len))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQescapeIdentifier(%V) and %s", &id, PQerrorMessageMy(s->conn)); goto notify; }
                if (!(command->data = ngx_pnalloc(c->pool, command->len = sizeof("UNLISTEN ;") - 1 + ngx_strlen(escape)))) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!ngx_pnalloc"); goto escape; }
                command->len = ngx_snprintf(command->data, command->len, "UNLISTEN %s;", escape) - command->data;
                str.len += command->len;
                PQfreemem(escape);
            } break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); s->connection->requests++; break;
            default: ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == %i", rc); goto notify;
        }
        PQfreemem(notify);
        switch (ngx_postgres_consume_flush_busy(s)) {
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
    if (!PQsendQuery(s->conn, (const char *)str.data)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%V\") and %s", &str, PQerrorMessageMy(s->conn)); goto error; }
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


static ngx_int_t ngx_postgres_idle(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    for (PGresult *res; PQstatus(s->conn) == CONNECTION_OK && (res = PQgetResult(s->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
            default: ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(s)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_result(ngx_postgres_save_t *s, PGresult *res) {
    ngx_connection_t *c = s->connection;
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


static ngx_int_t ngx_postgres_listen_result(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    s->handler = ngx_postgres_listen_result;
    ngx_int_t rc = NGX_OK;
    for (PGresult *res; PQstatus(s->conn) == CONNECTION_OK && (res = PQgetResult(s->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_TUPLES_OK: rc = ngx_postgres_result(s, res); break;
            default: ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); rc = NGX_ERROR; break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(s)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    ngx_postgres_close(s);
    return rc;
}


static ngx_int_t ngx_postgres_listen(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    s->handler = ngx_postgres_listen;
    for (PGresult *res; PQstatus(s->conn) == CONNECTION_OK && (res = PQgetResult(s->conn)); ) {
        switch(PQresultStatus(res)) {
            case PGRES_FATAL_ERROR: ngx_log_error(NGX_LOG_ERR, c->log, 0, "PQresultStatus == PGRES_FATAL_ERROR and %s", PQresultErrorMessageMy(res)); break;
            default: ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQresultStatus == %s and %s and %s", PQresStatus(PQresultStatus(res)), PQcmdStatus(res), PQresultErrorMessageMy(res)); break;
        }
        PQclear(res);
        switch (ngx_postgres_consume_flush_busy(s)) {
            case NGX_AGAIN: return NGX_AGAIN;
            case NGX_ERROR: return NGX_ERROR;
            default: break;
        }
    }
    static const char *command = "SELECT channel, concat_ws(' ', 'UNLISTEN', quote_ident(channel)) AS unlisten FROM pg_listening_channels() AS channel";
    if (!PQsendQuery(s->conn, command)) { ngx_log_error(NGX_LOG_ERR, c->log, 0, "!PQsendQuery(\"%s\") and %s", command, PQerrorMessageMy(s->conn)); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "PQsendQuery(\"%s\")", command);
    s->handler = ngx_postgres_listen_result;
    return NGX_OK;
}


static void ngx_postgres_log_to_save(ngx_log_t *log, ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
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
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (usc) {
        ngx_add_timer(c->read, usc->save.timeout);
        ngx_add_timer(c->write, usc->save.timeout);
        queue_remove(&s->queue);
        queue_insert_head(&usc->save.queue, &s->queue);
    }
}


static void ngx_postgres_save_close(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (!ngx_terminate && !ngx_exiting && ngx_http_push_stream_delete_channel_my && usc && usc->save.max && PQstatus(s->conn) == CONNECTION_OK && ngx_postgres_listen(s) != NGX_ERROR) return;
close:
    ngx_postgres_close(s);
}


void ngx_postgres_save_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_connection_t *c = e->data;
    c->log->connection = c->number;
    ngx_postgres_save_t *ps = c->data;
    if (c->close) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, "close"); goto close; }
    if (c->read->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, "read timedout"); c->read->timedout = 0; goto close; }
    if (c->write->timedout) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, "write timedout"); c->write->timedout = 0; goto close; }
    switch (ngx_postgres_consume_flush_busy(ps)) {
        case NGX_AGAIN: return;
        case NGX_ERROR: goto close;
        default: break;
    }
    switch (ngx_postgres_notify(ps)) {
        case NGX_AGAIN: return;
        case NGX_ERROR: goto close;
        default: break;
    }
    if (ps->handler(ps) != NGX_ERROR) return;
close:
    ngx_postgres_save_close(ps);
}


static void ngx_postgres_log_to_data(ngx_log_t *log, ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    c->idle = 0;
    c->log = log;
    c->pool->log = log;
    c->read->handler = ngx_postgres_data_handler;
    c->read->log = log;
    c->read->timedout = 0;
    c->sent = 0;
    c->write->handler = ngx_postgres_data_handler;
    c->write->log = log;
    c->write->timedout = 0;
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (usc) {
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
        queue_remove(&s->queue);
        queue_insert_head(&usc->data.queue, &s->queue);
    }
}


#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
static ngx_int_t ngx_postgres_next(ngx_postgres_save_t *s) {
    ngx_postgres_upstream_srv_conf_t *usc = s->usc;
    if (!usc) return NGX_OK;
    queue_each(&usc->request.queue, q) {
        queue_remove(q);
        ngx_postgres_data_t *d = queue_data(q, typeof(*d), queue);
        if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
        ngx_http_request_t *r = d->request;
        if (!r->connection || r->connection->error) continue;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "d = %p", d);
        d->save = s;
        ngx_postgres_log_to_data(r->connection->log, s);
        s->connection->data = d;
        r->state = 0;
        ngx_http_upstream_t *u = r->upstream;
        u->peer.connection = s->connection;
        queue_init(q);
        return ngx_postgres_prepare_or_query(s);
    }
    return NGX_OK;
}
#endif


static void ngx_postgres_free_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_connection_t *c = pc->connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_postgres_data_t *d = data;
    ngx_postgres_save_t *ds = d->save;
    ngx_postgres_upstream_srv_conf_t *usc = ds->usc;
    if (!usc || !usc->save.max) goto close;
    if (c->requests >= usc->save.requests) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "requests = %i", c->requests); goto close; }
    switch (PQtransactionStatus(ds->conn)) {
        case PQTRANS_UNKNOWN: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus == PQTRANS_UNKNOWN"); return;
        case PQTRANS_IDLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus == PQTRANS_IDLE"); break;
        default: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus != PQTRANS_IDLE"); if (!PQrequestCancel(ds->conn)) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!PQrequestCancel and %s", PQerrorMessageMy(ds->conn)); goto close; } break;
    }
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    switch (ngx_postgres_next(ds)) {
        case NGX_ERROR: goto close;
        case NGX_OK: break;
        default: goto null;
    }
#endif
    if (queue_size(&usc->save.queue) >= usc->save.max) {
        queue_t *q = queue_last(&usc->save.queue);
        ngx_postgres_save_t *s = queue_data(q, typeof(*s), queue);
        ngx_postgres_save_close(s);
    }
    ngx_postgres_log_to_save(usc->save.log ? usc->save.log : ngx_cycle->log, ds);
    ds->connection->data = ds;
    ds->handler = ngx_postgres_idle;
    goto null;
close:
    ngx_postgres_save_close(ds);
null:
    pc->connection = NULL;
}


static void ngx_postgres_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "state = %i", state);
    if (ngx_terminate) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ngx_terminate"); goto close; }
    if (ngx_exiting) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "ngx_exiting"); goto close; }
    ngx_connection_t *c = pc->connection;
    if (!c) { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "!c"); goto close; }
    if (c->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->error"); goto close; }
    if (c->read->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->read->error"); goto close; }
    if (c->write->error) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "c->write->error"); goto close; }
    if (state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout"); goto close; }
    ngx_postgres_free_peer(pc, data);
close:;
    ngx_postgres_data_t *d = data;
    if (pc->connection) { ngx_postgres_close(d->save); pc->connection = NULL; }
    if (d->peer.data) d->peer.free(pc, d->peer.data, state);
}


#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
static void ngx_postgres_data_cleanup(void *data) {
    ngx_postgres_data_t *d = data;
    ngx_http_request_t *r = d->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    if (!queue_empty(&d->queue)) queue_remove(&d->queue);
    if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
}


static void ngx_postgres_data_timeout(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_http_request_t *r = e->data;
    if (!r->connection || r->connection->error) return;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
}
#endif


static ngx_int_t ngx_postgres_open(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = data;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_srv_conf_t *usc = u->conf->upstream ? ngx_http_conf_upstream_srv_conf(u->conf->upstream, ngx_postgres_module) : NULL;
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
    ngx_postgres_connect_t *connect = location->connect ? location->connect : pc->peer_data;
#else
    ngx_postgres_connect_t *connect = location->connect ? location->connect : usc->connect.elts;
    if (!location->connect) {
        ngx_uint_t i;
        for (i = 0; i < connect->nelts; i++) for (ngx_uint_t j = 0; j < connect[i].naddrs; j++) { if (!ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)connect[i].addrs[j].sockaddr, pc->socklen, connect[i].addrs[j].socklen)) connect = &connect[i]; break; }
        if (i == connect->nelts) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connect not found"); return NGX_BUSY; }
    }
#endif
#if (HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS)
    u->connect_timeout = connect->timeout;
#else
    u->conf->connect_timeout = connect->timeout;
#endif
    const char *host = connect->values[0];
    if (host) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "host = %s", host);
    if (location->connect) {
        pc->sockaddr = connect->url.addrs[0].sockaddr;
        pc->socklen = connect->url.addrs[0].socklen;
    }
    ngx_str_t addr;
    if (!(addr.data = ngx_pcalloc(r->pool, NGX_SOCKADDR_STRLEN + 1))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto error; }
    if (!(addr.len = ngx_sock_ntop(pc->sockaddr, pc->socklen, addr.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_sock_ntop"); goto error; }
    connect->values[0] = (const char *)addr.data + (pc->sockaddr->sa_family == AF_UNIX ? 5 : 0);
    for (int i = 0; connect->keywords[i]; i++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i: %s = %s", i, connect->keywords[i], connect->values[i]);
    PGconn *conn = PQconnectStartParams(connect->keywords, connect->values, 0);
    connect->values[0] = host;
    if (PQstatus(conn) == CONNECTION_BAD) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQstatus == CONNECTION_BAD %s in upstream \"%V\"", PQerrorMessageMy(conn), pc->name); goto declined; }
    if (PQsetnonblocking(conn, 1) == -1) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsetnonblocking == -1 and %s in upstream \"%V\"", PQerrorMessageMy(conn), pc->name); goto declined; }
    if (usc && usc->trace.log) PQtrace(conn, fdopen(usc->trace.log->file->fd, "a+"));
    pgsocket fd;
    if ((fd = PQsocket(conn)) == PGINVALID_SOCKET) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PQsocket == PGINVALID_SOCKET"); goto declined; }
    ngx_connection_t *c = ngx_get_connection(fd, pc->log);
    if (!c) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); goto finish; }
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->read->log = pc->log;
    c->shared = 1;
    c->start_time = ngx_current_msec;
    c->type = pc->type ? pc->type : SOCK_STREAM;
    c->write->log = pc->log;
    if (!(c->pool = ngx_create_pool(128, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_create_pool"); goto close; }
    if (ngx_event_flags & NGX_USE_RTSIG_EVENT) {
        if (ngx_add_conn(c) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_conn != NGX_OK"); goto destroy; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_conn"); }
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(read)"); }
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        else { ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(write)"); }
    }
    ngx_postgres_save_t *ds;
    switch (PQconnectPoll(conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_ACTIVE and %s", ngx_postgres_status(conn)); break;
        case PGRES_POLLING_FAILED: ngx_log_error(NGX_LOG_ERR, pc->log, 0, "PGRES_POLLING_FAILED and %s and %s", ngx_postgres_status(conn), PQerrorMessageMy(conn)); goto destroy;
        case PGRES_POLLING_OK: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_OK and %s", ngx_postgres_status(conn)); goto connected;
        case PGRES_POLLING_READING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_READING and %s", ngx_postgres_status(conn)); break;
        case PGRES_POLLING_WRITING: ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_WRITING and %s", ngx_postgres_status(conn)); break;
    }
    if (!(d->save = ds = ngx_pcalloc(c->pool, sizeof(*ds)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    queue_init(&ds->prepare.queue);
    ds->conn = conn;
    ds->connection = c;
    ds->handler = ngx_postgres_connect;
    ds->peer.sockaddr = pc->sockaddr;
    ds->peer.socklen = pc->socklen;
    ds->usc = usc;
    pc->connection = c;
    if (usc) queue_insert_head(&usc->data.queue, &ds->queue);
    return NGX_AGAIN;
connected:
    if (!(d->save = ds = ngx_pcalloc(c->pool, sizeof(*ds)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    queue_init(&ds->prepare.queue);
    ds->conn = conn;
    ds->connection = c;
    ds->peer.sockaddr = pc->sockaddr;
    ds->peer.socklen = pc->socklen;
    ds->usc = usc;
    pc->connection = c;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    if (usc) queue_insert_head(&usc->data.queue, &ds->queue);
    return ngx_postgres_prepare_or_query(ds);
declined:
    PQfinish(conn);
    return NGX_DECLINED;
destroy:
    ngx_destroy_pool(c->pool);
    c->pool = NULL;
close:
    ngx_close_connection(c);
finish:
    PQfinish(conn);
error:
    return NGX_ERROR;
}


ngx_int_t ngx_postgres_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = data;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_postgres_upstream_srv_conf_t *usc = u->conf->upstream ? ngx_http_conf_upstream_srv_conf(u->conf->upstream, ngx_postgres_module) : NULL;
    if (!usc) goto ret;
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    if (rc != NGX_OK) return rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "rc = %i", rc);
    if (usc->save.max) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "save.max = %i, save.size = %i, data.size = %i", usc->save.max, queue_size(&usc->save.queue), queue_size(&usc->data.queue));
        queue_each(&usc->save.queue, q) {
            ngx_postgres_save_t *s = queue_data(q, typeof(*s), queue);
            if (ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)s->peer.sockaddr, pc->socklen, s->peer.socklen)) continue;
            d->save = s;
            ngx_postgres_log_to_data(pc->log, s);
            pc->cached = 1;
            pc->connection = s->connection;
            s->connection->data = d;
            return ngx_postgres_prepare_or_query(s);
        }
        if (queue_size(&usc->save.queue) + queue_size(&usc->data.queue) < usc->save.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "save.size = %i, data.size = %i", queue_size(&usc->save.queue), queue_size(&usc->data.queue));
#if (T_NGX_HTTP_DYNAMIC_RESOLVE)
        } else if (usc->request.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "request.max = %i, request.size = %i", usc->request.max, queue_size(&usc->request.queue));
            if (queue_size(&usc->request.queue) < usc->request.max) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "d = %p", d);
                ngx_http_request_t *r = d->request;
                ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
                if (!cln) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
                cln->handler = ngx_postgres_data_cleanup;
                cln->data = d;
                queue_insert_tail(&usc->request.queue, &d->queue);
                d->timeout.handler = ngx_postgres_data_timeout;
                d->timeout.log = pc->log;
                d->timeout.data = r;
                ngx_add_timer(&d->timeout, usc->request.timeout);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "request.size = %i", queue_size(&usc->request.queue));
                return NGX_YIELD;
            }
            if (usc->request.reject) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0, "request.size = %i", queue_size(&usc->request.queue));
                return NGX_BUSY;
            }
#endif
        } else if (usc->save.reject) {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "save.size = %i, data.size = %i", queue_size(&usc->save.queue), queue_size(&usc->data.queue));
            return NGX_BUSY;
        }
    }
ret:
    return ngx_postgres_open(pc, data);
}


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_postgres_set_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = data;
    return d->peer.set_session(pc, d->peer.data);
}


static void ngx_postgres_save_session(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = data;
    d->peer.save_session(pc, d->peer.data);
}
#endif


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *usc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_upstream_srv_conf_t *pusc = usc ? ngx_http_conf_upstream_srv_conf(usc, ngx_postgres_module) : NULL;
    ngx_http_upstream_t *u = r->upstream;
    if (pusc) {
        if (pusc->peer.init(r, usc) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
    } else {
        ngx_http_core_loc_conf_t *core = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        u->peer.name = &core->name;
    }
    ngx_postgres_data_t *d = ngx_pcalloc(r->pool, sizeof(*d));
    if (!d) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    d->request = r;
    d->peer.data = u->peer.data;
    u->peer.data = d;
    d->peer.get = u->peer.get;
    u->peer.get = ngx_postgres_peer_get;
    d->peer.free = u->peer.free;
    u->peer.free = ngx_postgres_peer_free;
#if (NGX_HTTP_SSL)
    d->peer.save_session = u->peer.save_session;
    u->peer.save_session = ngx_postgres_save_session;
    d->peer.set_session = u->peer.set_session;
    u->peer.set_session = ngx_postgres_set_session;
#endif
    ngx_postgres_location_t *location = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    if (ngx_array_init(&d->send, r->pool, location->query.nelts, sizeof(ngx_postgres_send_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
    ngx_memzero(d->send.elts, location->query.nelts * d->send.size);
    d->send.nelts = location->query.nelts;
    ngx_postgres_query_t *queryelts = location->query.elts;
    ngx_postgres_send_t *sendelts = d->send.elts;
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
        if (ngx_array_init(&d->variable, r->pool, nelts, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_array_init != NGX_OK"); return NGX_ERROR; }
        ngx_memzero(d->variable.elts, nelts * d->variable.size);
        d->variable.nelts = nelts;
    }
    return NGX_OK;
}


void ngx_postgres_close(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    if (s->usc) queue_remove(&s->queue);
    PQfinish(s->conn);
    if (ngx_del_conn) {
        ngx_del_conn(c, NGX_CLOSE_EVENT);
    } else {
        if (c->read->active || c->read->disabled) { ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT); }
        if (c->write->active || c->write->disabled) { ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT); }
    }
    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
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
    ngx_postgres_query_t *query = ngx_array_push(&location->query);
    if (!query) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(query, sizeof(*query));
    if (ngx_array_init(&query->rewrite, cf->pool, 1, sizeof(ngx_postgres_rewrite_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    if (ngx_array_init(&query->variable, cf->pool, 1, sizeof(ngx_postgres_variable_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
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
