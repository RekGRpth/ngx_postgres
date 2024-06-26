#include <catalog/pg_type_d.h>
#include "ngx_postgres_include.h"


ngx_int_t ngx_postgres_notify(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_array_t listen = {0};
    ngx_int_t rc = NGX_OK;
    ngx_str_t str = ngx_null_string;
    for (PGnotify *notify; PQstatus(s->conn) == CONNECTION_OK && (notify = PQnotifies(s->conn)); PQfreemem(notify)) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "relname=%s, extra=%s, be_pid=%i", notify->relname, notify->extra, notify->be_pid);
        if (!ngx_http_push_stream_add_msg_to_channel_my) continue;
        ngx_str_t id = { ngx_strlen(notify->relname), (u_char *)notify->relname };
        ngx_str_t text = { ngx_strlen(notify->extra), (u_char *)notify->extra };
        ngx_pool_t *temp_pool = ngx_create_pool(4096 + id.len + text.len, s->connection->log);
        if (!temp_pool) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_create_pool"); rc = NGX_ERROR; continue; }
        switch ((rc = ngx_http_push_stream_add_msg_to_channel_my(s->connection->log, &id, &text, NULL, NULL, 1, temp_pool))) {
            case NGX_ERROR: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_ERROR"); break;
            case NGX_DECLINED: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DECLINED"); {
                if (!listen.nelts && ngx_array_init(&listen, s->connection->pool, 1, sizeof(ngx_str_t)) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_array_init != NGX_OK"); break; }
                ngx_str_t *command = ngx_array_push(&listen);
                if (!command) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_array_push"); break; }
                char *escape = PQescapeIdentifier(s->conn, (const char *)id.data, id.len);
                if (!escape) { ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQescapeIdentifier(%V)", &id); break; }
                if (!(command->data = ngx_pnalloc(s->connection->pool, command->len = sizeof("UNLISTEN ;") - 1 + ngx_strlen(escape)))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); } else {
                    command->len = ngx_snprintf(command->data, command->len, "UNLISTEN %s;", escape) - command->data;
                    str.len += command->len;
                }
                PQfreemem(escape);
            } break;
            case NGX_DONE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_DONE"); break;
            case NGX_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == NGX_OK"); s->connection->requests++; break;
            default: ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "ngx_http_push_stream_add_msg_to_channel_my == %i", rc); break;
        }
        ngx_destroy_pool(temp_pool);
    }
    if (str.len) {
        if (!(str.data = ngx_pnalloc(s->connection->pool, str.len + 1))) { ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "!ngx_pnalloc"); rc = NGX_ERROR; } else {
            ngx_str_t *command = listen.elts;
            u_char *p = str.data;
            for (ngx_uint_t i = 0; i < listen.nelts; i++) {
                p = ngx_copy(p, command[i].data, command[i].len);
                ngx_pfree(s->connection->pool, command[i].data);
            }
            *p = '\0';
            if (!PQsendQuery(s->conn, (const char *)str.data)) { ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendQuery(\"%V\")", &str); rc = NGX_ERROR; } else {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendQuery(\"%V\")", &str);
            }
        }
    }
    if (listen.nelts) ngx_array_destroy(&listen);
    return rc;
}


static ngx_int_t ngx_postgres_result_idle_handler(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (s->res) switch (PQresultStatus(s->res)) {
        case PGRES_FATAL_ERROR: ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s", PQresStatus(PQresultStatus(s->res))); break;
        default: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQcmdStatus(s->res)); break;
    }
    return NGX_OK;
}


static ngx_int_t ngx_postgres_result_listen_handler(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (s->res) switch (PQresultStatus(s->res)) {
        case PGRES_TUPLES_OK: {
            for (int row = 0; row < PQntuples(s->res); row++) {
                const char *schannel = PQgetvalue(s->res, row, PQfnumber(s->res, "channel"));
                const char *sunlisten = PQgetvalue(s->res, row, PQfnumber(s->res, "unlisten"));
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "row = %i, channel = %s, unlisten = %s", row, schannel, sunlisten);
                ngx_str_t channel = {ngx_strlen(schannel), (u_char *)schannel};
                ngx_str_t unlisten = {ngx_strlen(sunlisten), (u_char *)sunlisten};
                ngx_http_push_stream_delete_channel_my(s->connection->log, &channel, unlisten.data, unlisten.len, s->connection->pool);
            }
        } break;
        case PGRES_FATAL_ERROR: ngx_postgres_log_error(NGX_LOG_WARN, s->connection->log, 0, PQresultErrorMessageMy(s->res), "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQcmdStatus(s->res)); return NGX_ERROR;
        default: ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "PQresultStatus == %s and %s", PQresStatus(PQresultStatus(s->res)), PQcmdStatus(s->res)); return NGX_ERROR;
    }
    ngx_postgres_close(s);
    return NGX_OK;
}


static ngx_int_t ngx_postgres_send_listen_handler(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    if (PQisBusy(s->conn)) { ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "PQisBusy"); goto ret; }
    static const char *command = "SELECT channel, concat_ws(' ', 'UNLISTEN', quote_ident(channel)) AS unlisten FROM pg_listening_channels() AS channel";
    if (!PQsendQuery(s->conn, command)) { ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQsendQuery(\"%s\")", command); return NGX_ERROR; }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQsendQuery(\"%s\")", command);
    s->read_handler = ngx_postgres_result_listen_handler;
    s->write_handler = NULL;
    ngx_connection_t *c = s->connection;
    c->read->active = 1;
    c->write->active = 0;
ret:
    return NGX_OK;
}


static void ngx_postgres_save_close(ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    s->read_handler = NULL;
    s->write_handler = ngx_postgres_send_listen_handler;
    c->read->active = 0;
    c->write->active = 1;
    ngx_postgres_upstream_srv_conf_t *pusc = s->conf;
    if (!ngx_terminate && !ngx_exiting && ngx_http_push_stream_delete_channel_my && pusc && pusc->keep.max && PQstatus(s->conn) == CONNECTION_OK && s->write_handler(s) != NGX_ERROR) return;
    ngx_postgres_close(s);
}


static void ngx_postgres_save_read_or_write_handler(ngx_event_t *e) {
    ngx_connection_t *c = e->data;
    ngx_postgres_save_t *s = c->data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", e->write ? "write" : "read");
    if (c->close) { ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "close"); goto close; }
    if (c->read->timedout) { ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "read timedout"); c->read->timedout = 0; goto close; }
    if (c->write->timedout) { ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "write timedout"); c->write->timedout = 0; goto close; }
    if (!e->write && PQstatus(s->conn) == CONNECTION_OK && !PQconsumeInput(s->conn)) { ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "!PQconsumeInput"); goto close; }
    ngx_int_t rc = NGX_OK;
    if (!e->write && PQstatus(s->conn) == CONNECTION_OK && rc == NGX_OK) rc = ngx_postgres_notify(s);
    while (PQstatus(s->conn) == CONNECTION_OK && (s->res = PQgetResult(s->conn))) {
        if (e->write) {
            if (rc == NGX_OK && s->write_handler) rc = s->write_handler(s);
        } else {
            if (rc == NGX_OK && s->read_handler) rc = s->read_handler(s);
        }
        PQclear(s->res);
    }
    s->res = NULL;
    if (e->write) {
        if (rc == NGX_OK && s->write_handler) rc = s->write_handler(s);
    } else {
        if (rc == NGX_OK && s->read_handler) rc = s->read_handler(s);
    }
    if (rc != NGX_ERROR) return;
close:
    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "close");
    ngx_postgres_save_close(s);
}


static void ngx_postgres_save_read_handler(ngx_event_t *e) {
    ngx_postgres_save_read_or_write_handler(e);
}


static void ngx_postgres_save_write_handler(ngx_event_t *e) {
    ngx_postgres_save_read_or_write_handler(e);
}


static void ngx_postgres_log_to_keep(ngx_log_t *log, ngx_postgres_save_t *s) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", __func__);
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", __func__);
    c->idle = 1;
    c->log = log;
    c->pool->log = log;
    c->read->handler = ngx_postgres_save_read_handler;
    c->read->log = log;
    c->read->timedout = 0;
    c->sent = 0;
    c->write->handler = ngx_postgres_save_write_handler;
    c->write->log = log;
    c->write->timedout = 0;
    ngx_postgres_upstream_srv_conf_t *pusc = s->conf;
    if (pusc) {
        if (pusc->keep.timeout) {
            ngx_add_timer(c->read, pusc->keep.timeout);
            ngx_add_timer(c->write, pusc->keep.timeout);
        }
        queue_remove(&s->queue);
        queue_insert_head(&pusc->keep.queue, &s->queue);
    }
}


static void ngx_postgres_log_to_work(ngx_log_t *log, ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "%s", __func__);
    c->idle = 0;
    c->log = log;
    c->pool->log = log;
    c->read->handler = ngx_postgres_data_read_handler;
    c->read->log = log;
    c->read->timedout = 0;
    c->sent = 0;
    c->write->handler = ngx_postgres_data_write_handler;
    c->write->log = log;
    c->write->timedout = 0;
    ngx_postgres_upstream_srv_conf_t *pusc = s->conf;
    if (pusc) {
        if (c->read->timer_set) ngx_del_timer(c->read);
        if (c->write->timer_set) ngx_del_timer(c->write);
        queue_remove(&s->queue);
        queue_insert_head(&pusc->work.queue, &s->queue);
    }
}


static ngx_int_t ngx_postgres_next(ngx_postgres_save_t *s) {
    ngx_postgres_upstream_srv_conf_t *pusc = s->conf;
    if (!pusc) return NGX_OK;
    queue_each(&pusc->data.queue, q) {
        queue_remove(q);
        ngx_postgres_data_t *d = queue_data(q, typeof(*d), queue);
        if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
        ngx_http_request_t *r = d->request;
        if (!r->connection || r->connection->error) continue;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "d = %p", d);
        d->save = s;
        ngx_postgres_log_to_work(r->connection->log, s);
        s->connection->data = d;
        r->state = 0;
        ngx_http_upstream_t *u = r->upstream;
        u->peer.connection = s->connection;
        queue_init(q);
        return ngx_postgres_send_query(s);
    }
    return NGX_OK;
}


static void ngx_postgres_free_peer(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_connection_t *c = pc->connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_postgres_data_t *d = data;
    ngx_postgres_save_t *s = d->save;
    ngx_postgres_upstream_srv_conf_t *pusc = s->conf;
    if (!pusc || !pusc->keep.max) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "!pusc || !pusc->keep.max"); goto close; }
    switch (PQtransactionStatus(s->conn)) {
        case PQTRANS_UNKNOWN: ngx_log_error(NGX_LOG_WARN, pc->log, 0, "PQtransactionStatus == PQTRANS_UNKNOWN"); return;
        case PQTRANS_IDLE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PQtransactionStatus == PQTRANS_IDLE"); break;
        default: {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "PQtransactionStatus != PQTRANS_IDLE");
            PGcancel *cancel = PQgetCancel(s->conn);
            if (!cancel) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(s->conn), "!PQgetCancel"); goto close; }
            char errbuf[256];
            if (!PQcancel(cancel, errbuf, sizeof(errbuf))) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, errbuf, "!PQcancel"); PQfreeCancel(cancel); goto close; }
            PQfreeCancel(cancel);
        } break;
    }
    if (pusc->keep.requests && c->requests >= pusc->keep.requests) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "requests = %i", c->requests); goto close; }
    switch (ngx_postgres_next(s)) {
        case NGX_ERROR: goto close;
        case NGX_OK: break;
        default: goto null;
    }
    if (queue_size(&pusc->keep.queue) >= pusc->keep.max) {
        queue_t *q = queue_last(&pusc->keep.queue);
        queue_remove(q);
        ngx_log_error(NGX_LOG_WARN, pc->log, 0, "close");
        ngx_postgres_save_t *s = queue_data(q, typeof(*s), queue);
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "close");
        ngx_postgres_save_close(s);
        queue_insert_head(&pusc->work.queue, q);
    }
    ngx_postgres_log_to_keep(pusc->keep.log ? pusc->keep.log : ngx_cycle->log, s);
    s->connection->data = s;
    s->read_handler = ngx_postgres_result_idle_handler;
    s->write_handler = NULL;
    c->read->active = 1;
    c->write->active = 0;
    goto null;
close:
    ngx_log_error(NGX_LOG_WARN, pc->log, 0, "close");
    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0, "close");
    ngx_postgres_save_close(s);
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
    if (state & NGX_PEER_FAILED && !c->read->timedout && !c->write->timedout) { ngx_log_error(NGX_LOG_WARN, pc->log, 0, "state & NGX_PEER_FAILED = %s, c->read->timedout = %s, c->write->timedout = %s", state & NGX_PEER_FAILED ? "true" : "false", c->read->timedout ? "true" : "false", c->write->timedout ? "true" : "false"); goto close; }
    ngx_postgres_free_peer(pc, data);
close:;
    ngx_postgres_data_t *d = data;
    if (pc->connection) { ngx_postgres_close(d->save); pc->connection = NULL; }
    d->peer.free(pc, d->peer.data, state);
    d->save = NULL;
}


static void ngx_postgres_data_cleanup_handler(void *data) {
    ngx_postgres_data_t *d = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    if (!queue_empty(&d->queue)) queue_remove(&d->queue);
    if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
}


static void ngx_postgres_data_timeout_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_http_request_t *r = e->data;
    if (!r->connection || r->connection->error) return;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
}


static ngx_int_t ngx_postgres_connect_handler(ngx_postgres_save_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "%s", __func__);
    switch (PQstatus(s->conn)) {
        case CONNECTION_BAD: ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "PQstatus == CONNECTION_BAD"); return NGX_ERROR;
        case CONNECTION_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PQstatus == CONNECTION_OK"); goto connected;
        default: break;
    }
    switch (PQconnectPoll(s->conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_postgres_log_error(NGX_LOG_ERR, s->connection->log, 0, PQerrorMessageMy(s->conn), "PGRES_POLLING_FAILED"); return NGX_ERROR;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_OK"); c->read->active = 0; c->write->active = 1; break;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
    return NGX_AGAIN;
connected:
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    return ngx_postgres_send_query(s);
}


static ngx_int_t ngx_postgres_open(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_postgres_data_t *d = data;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *husc = u->upstream;
    ngx_postgres_upstream_srv_conf_t *pusc = husc->srv_conf ? ngx_http_conf_upstream_srv_conf(husc, ngx_postgres_module) : NULL;
    ngx_postgres_loc_conf_t *plc = ngx_http_get_module_loc_conf(r, ngx_postgres_module);
    ngx_postgres_connect_t *connect = plc->connect ? plc->connect : pusc->connect.elts;
    if (!plc->connect) {
        ngx_uint_t i;
        for (i = 0; i < pusc->connect.nelts; i++) for (ngx_uint_t j = 0; j < connect[i].url.naddrs; j++) if (!ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)connect[i].url.addrs[j].sockaddr, pc->socklen, connect[i].url.addrs[j].socklen)) { connect = &connect[i]; goto found; }
found:
        if (i == pusc->connect.nelts) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "connect not found"); return NGX_BUSY; }
    }
    u->conf->connect_timeout = connect->timeout;
    const char *host = connect->values[0];
    if (host) { ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "host = %s", host); }
    ngx_str_t addr;
    if (!(addr.data = ngx_pcalloc(r->pool, NGX_SOCKADDR_STRLEN + 1))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto error; }
    if (!(addr.len = ngx_sock_ntop(pc->sockaddr, pc->socklen, addr.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_sock_ntop"); goto error; }
    connect->values[0] = (const char *)addr.data + (pc->sockaddr->sa_family == AF_UNIX ? 5 : 0);
    for (int i = 0; connect->keywords[i]; i++) ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%i: %s = %s", i, connect->keywords[i], connect->values[i]);
    PGconn *conn = PQconnectStartParams(connect->keywords, connect->values, 0);
    connect->values[0] = host;
    if (PQstatus(conn) == CONNECTION_BAD) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PQstatus == CONNECTION_BAD"); goto declined; }
    (void)PQsetErrorVerbosity(conn, connect->verbosity);
    if (PQsetnonblocking(conn, 1) == -1) { ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PQsetnonblocking == -1"); goto declined; }
    if (pusc && pusc->trace.log) PQtrace(conn, fdopen(pusc->trace.log->file->fd, "a+"));
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
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_conn");
    } else {
        if (ngx_add_event(c->read, NGX_READ_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(read)");
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, ngx_event_flags & NGX_USE_CLEAR_EVENT ? NGX_CLEAR_EVENT : NGX_LEVEL_EVENT) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "ngx_add_event != NGX_OK"); goto destroy; }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "ngx_add_event(write)");
    }
    ngx_postgres_save_t *s;
    switch (PQconnectPoll(conn)) {
        case PGRES_POLLING_ACTIVE: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_ACTIVE"); break;
        case PGRES_POLLING_FAILED: ngx_postgres_log_error(NGX_LOG_ERR, pc->log, 0, PQerrorMessageMy(conn), "PGRES_POLLING_FAILED"); goto destroy;
        case PGRES_POLLING_OK: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_OK"); c->read->active = 0; c->write->active = 1; break;
        case PGRES_POLLING_READING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_READING"); c->read->active = 1; c->write->active = 0; break;
        case PGRES_POLLING_WRITING: ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "PGRES_POLLING_WRITING"); c->read->active = 0; c->write->active = 1; break;
    }
    if (!(s = d->save = ngx_pcalloc(c->pool, sizeof(*s)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); goto destroy; }
    s->conn = conn;
    s->connect = connect;
    s->connection = c;
    s->peer.sockaddr = pc->sockaddr;
    s->peer.socklen = pc->socklen;
    s->read_handler = ngx_postgres_connect_handler;
    s->conf = pusc;
    s->write_handler = ngx_postgres_connect_handler;
    pc->connection = c;
    if (pusc) queue_insert_head(&pusc->work.queue, &s->queue);
    return NGX_AGAIN;
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
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    if (rc != NGX_OK) return rc;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "rc = %i", rc);
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *husc = u->upstream;
    ngx_postgres_upstream_srv_conf_t *pusc = husc->srv_conf ? ngx_http_conf_upstream_srv_conf(husc, ngx_postgres_module) : NULL;
    if (pusc && pusc->keep.max) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, "keep.max = %i, keep.size = %i, work.size = %i", pusc->keep.max, queue_size(&pusc->keep.queue), queue_size(&pusc->work.queue));
        queue_each(&pusc->keep.queue, q) {
            ngx_postgres_save_t *s = queue_data(q, typeof(*s), queue);
            if (ngx_memn2cmp((u_char *)pc->sockaddr, (u_char *)s->peer.sockaddr, pc->socklen, s->peer.socklen)) continue;
            d->save = s;
            ngx_postgres_log_to_work(pc->log, s);
            pc->cached = 1;
            pc->connection = s->connection;
            s->connection->data = d;
            return ngx_postgres_send_query(s);
        }
        if (queue_size(&pusc->keep.queue) + queue_size(&pusc->work.queue) < pusc->keep.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "keep.size = %i, work.size = %i", queue_size(&pusc->keep.queue), queue_size(&pusc->work.queue));
        } else if (pusc->data.max) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "data.max = %i, data.size = %i", pusc->data.max, queue_size(&pusc->data.queue));
            if (queue_size(&pusc->data.queue) < pusc->data.max) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "d = %p", d);
                ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(d->request->pool, 0);
                if (!cln) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
                cln->handler = ngx_postgres_data_cleanup_handler;
                cln->data = d;
                queue_insert_tail(&pusc->data.queue, &d->queue);
                if (pusc->data.timeout) {
                    d->timeout.handler = ngx_postgres_data_timeout_handler;
                    d->timeout.log = pc->log;
                    d->timeout.data = r;
                    ngx_add_timer(&d->timeout, pusc->data.timeout);
                }
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "data.size = %i", queue_size(&pusc->data.queue));
                return NGX_YIELD;
            }
            if (pusc->data.reject) {
                ngx_log_error(NGX_LOG_WARN, pc->log, 0, "data.size = %i", queue_size(&pusc->data.queue));
                return NGX_BUSY;
            }
        } else if (pusc->keep.reject) {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "keep.size = %i, work.size = %i", queue_size(&pusc->keep.queue), queue_size(&pusc->work.queue));
            return NGX_BUSY;
        }
    }
    return ngx_postgres_open(pc, data);
}


ngx_int_t ngx_postgres_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *husc) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_postgres_upstream_srv_conf_t *pusc = husc->srv_conf ? ngx_http_conf_upstream_srv_conf(husc, ngx_postgres_module) : NULL;
    ngx_http_upstream_t *u = r->upstream;
    if ((pusc && pusc->peer.init ? pusc->peer.init : ngx_http_upstream_init_round_robin_peer)(r, husc) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "peer.init != NGX_OK"); return NGX_ERROR; }
    ngx_postgres_data_t *d = ngx_pcalloc(r->pool, sizeof(*d));
    if (!d) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    d->request = r;
    d->peer.data = u->peer.data;
    u->peer.data = d;
    d->peer.get = u->peer.get;
    u->peer.get = ngx_postgres_peer_get;
    d->peer.free = u->peer.free;
    u->peer.free = ngx_postgres_peer_free;
    return NGX_OK;
}


void ngx_postgres_close(ngx_postgres_save_t *s) {
    s->read_handler = NULL;
    s->write_handler = NULL;
    ngx_connection_t *c = s->connection;
    s->connection = NULL;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "%s", __func__);
    c->read->active = 0;
    c->write->active = 0;
    if (s->conf) queue_remove(&s->queue);
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
    ngx_int_t n = ngx_atoi(type->data, type->len);
    if (n != NGX_ERROR) return n <= 0 ? 0 : n;
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
#ifdef PG_NODE_TREEOID
        { ngx_string("PG_NODE_TREEOID"), PG_NODE_TREEOID },
#endif
#ifdef PG_NDISTINCTOID
        { ngx_string("PG_NDISTINCTOID"), PG_NDISTINCTOID },
#endif
#ifdef PG_DEPENDENCIESOID
        { ngx_string("PG_DEPENDENCIESOID"), PG_DEPENDENCIESOID },
#endif
#ifdef PG_MCV_LISTOID
        { ngx_string("PG_MCV_LISTOID"), PG_MCV_LISTOID },
#endif
#ifdef PG_DDL_COMMANDOID
        { ngx_string("PG_DDL_COMMANDOID"), PG_DDL_COMMANDOID },
#endif
#ifdef PGNODETREEOID
        { ngx_string("PGNODETREEOID"), PGNODETREEOID },
#endif
#ifdef PGNDISTINCTOID
        { ngx_string("PGNDISTINCTOID"), PGNDISTINCTOID },
#endif
#ifdef PGDEPENDENCIESOID
        { ngx_string("PGDEPENDENCIESOID"), PGDEPENDENCIESOID },
#endif
#ifdef PGMCVLISTOID
        { ngx_string("PGMCVLISTOID"), PGMCVLISTOID },
#endif
#ifdef PGDDLCOMMANDOID
        { ngx_string("PGDDLCOMMANDOID"), PGDDLCOMMANDOID },
#endif
#ifdef XID8OID
        { ngx_string("XID8OID"), XID8OID },
#endif
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
#ifdef MONEYOID
        { ngx_string("MONEYOID"), MONEYOID },
#endif
#ifdef CASHOID
        { ngx_string("CASHOID"), CASHOID },
#endif
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
#ifdef REGCOLLATIONOID
        { ngx_string("REGCOLLATIONOID"), REGCOLLATIONOID },
#endif
        { ngx_string("REGTYPEOID"), REGTYPEOID },
        { ngx_string("REGROLEOID"), REGROLEOID },
        { ngx_string("REGNAMESPACEOID"), REGNAMESPACEOID },
        { ngx_string("UUIDOID"), UUIDOID },
#ifdef PG_LSNOID
        { ngx_string("PG_LSNOID"), PG_LSNOID },
#endif
#ifdef LSNOID
        { ngx_string("LSNOID"), LSNOID },
#endif
        { ngx_string("TSVECTOROID"), TSVECTOROID },
        { ngx_string("GTSVECTOROID"), GTSVECTOROID },
        { ngx_string("TSQUERYOID"), TSQUERYOID },
        { ngx_string("REGCONFIGOID"), REGCONFIGOID },
        { ngx_string("REGDICTIONARYOID"), REGDICTIONARYOID },
        { ngx_string("JSONBOID"), JSONBOID },
        { ngx_string("JSONPATHOID"), JSONPATHOID },
        { ngx_string("TXID_SNAPSHOTOID"), TXID_SNAPSHOTOID },
#ifdef PG_SNAPSHOTOID
        { ngx_string("PG_SNAPSHOTOID"), PG_SNAPSHOTOID },
#endif
        { ngx_string("INT4RANGEOID"), INT4RANGEOID },
        { ngx_string("NUMRANGEOID"), NUMRANGEOID },
        { ngx_string("TSRANGEOID"), TSRANGEOID },
        { ngx_string("TSTZRANGEOID"), TSTZRANGEOID },
        { ngx_string("DATERANGEOID"), DATERANGEOID },
        { ngx_string("INT8RANGEOID"), INT8RANGEOID },
#ifdef INT4MULTIRANGEOID
        { ngx_string("INT4MULTIRANGEOID"), INT4MULTIRANGEOID },
#endif
#ifdef NUMMULTIRANGEOID
        { ngx_string("NUMMULTIRANGEOID"), NUMMULTIRANGEOID },
#endif
#ifdef TSMULTIRANGEOID
        { ngx_string("TSMULTIRANGEOID"), TSMULTIRANGEOID },
#endif
#ifdef TSTZMULTIRANGEOID
        { ngx_string("TSTZMULTIRANGEOID"), TSTZMULTIRANGEOID },
#endif
#ifdef DATEMULTIRANGEOID
        { ngx_string("DATEMULTIRANGEOID"), DATEMULTIRANGEOID },
#endif
#ifdef INT8MULTIRANGEOID
        { ngx_string("INT8MULTIRANGEOID"), INT8MULTIRANGEOID },
#endif
        { ngx_string("RECORDOID"), RECORDOID },
        { ngx_string("RECORDARRAYOID"), RECORDARRAYOID },
        { ngx_string("CSTRINGOID"), CSTRINGOID },
        { ngx_string("ANYOID"), ANYOID },
        { ngx_string("ANYARRAYOID"), ANYARRAYOID },
        { ngx_string("VOIDOID"), VOIDOID },
        { ngx_string("TRIGGEROID"), TRIGGEROID },
#ifdef EVENT_TRIGGEROID
        { ngx_string("EVENT_TRIGGEROID"), EVENT_TRIGGEROID },
#endif
#ifdef EVTTRIGGEROID
        { ngx_string("EVTTRIGGEROID"), EVTTRIGGEROID },
#endif
        { ngx_string("LANGUAGE_HANDLEROID"), LANGUAGE_HANDLEROID },
        { ngx_string("INTERNALOID"), INTERNALOID },
#ifdef OPAQUEOID
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
#ifdef ANYCOMPATIBLEOID
        { ngx_string("ANYCOMPATIBLEOID"), ANYCOMPATIBLEOID },
#endif
#ifdef ANYCOMPATIBLEARRAYOID
        { ngx_string("ANYCOMPATIBLEARRAYOID"), ANYCOMPATIBLEARRAYOID },
#endif
#ifdef ANYCOMPATIBLENONARRAYOID
        { ngx_string("ANYCOMPATIBLENONARRAYOID"), ANYCOMPATIBLENONARRAYOID },
#endif
#ifdef ANYCOMPATIBLERANGEOID
        { ngx_string("ANYCOMPATIBLERANGEOID"), ANYCOMPATIBLERANGEOID },
#endif
#ifdef ANYMULTIRANGEOID
        { ngx_string("ANYMULTIRANGEOID"), ANYMULTIRANGEOID },
#endif
#ifdef ANYCOMPATIBLEMULTIRANGEOID
        { ngx_string("ANYCOMPATIBLEMULTIRANGEOID"), ANYCOMPATIBLEMULTIRANGEOID },
#endif
#ifdef PG_BRIN_BLOOM_SUMMARYOID
        { ngx_string("PG_BRIN_BLOOM_SUMMARYOID"), PG_BRIN_BLOOM_SUMMARYOID },
#endif
#ifdef PG_BRIN_MINMAX_MULTI_SUMMARYOID
        { ngx_string("PG_BRIN_MINMAX_MULTI_SUMMARYOID"), PG_BRIN_MINMAX_MULTI_SUMMARYOID },
#endif
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
#ifdef PG_TYPEARRAYOID
        { ngx_string("PG_TYPEARRAYOID"), PG_TYPEARRAYOID },
#endif
#ifdef PG_ATTRIBUTEARRAYOID
        { ngx_string("PG_ATTRIBUTEARRAYOID"), PG_ATTRIBUTEARRAYOID },
#endif
#ifdef PG_PROCARRAYOID
        { ngx_string("PG_PROCARRAYOID"), PG_PROCARRAYOID },
#endif
#ifdef PG_CLASSARRAYOID
        { ngx_string("PG_CLASSARRAYOID"), PG_CLASSARRAYOID },
#endif
        { ngx_string("JSONARRAYOID"), JSONARRAYOID },
        { ngx_string("XMLARRAYOID"), XMLARRAYOID },
#ifdef XID8ARRAYOID
        { ngx_string("XID8ARRAYOID"), XID8ARRAYOID },
#endif
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
#ifdef REGCOLLATIONARRAYOID
        { ngx_string("REGCOLLATIONARRAYOID"), REGCOLLATIONARRAYOID },
#endif
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
#ifdef PG_SNAPSHOTARRAYOID
        { ngx_string("PG_SNAPSHOTARRAYOID"), PG_SNAPSHOTARRAYOID },
#endif
        { ngx_string("INT4RANGEARRAYOID"), INT4RANGEARRAYOID },
        { ngx_string("NUMRANGEARRAYOID"), NUMRANGEARRAYOID },
        { ngx_string("TSRANGEARRAYOID"), TSRANGEARRAYOID },
        { ngx_string("TSTZRANGEARRAYOID"), TSTZRANGEARRAYOID },
        { ngx_string("DATERANGEARRAYOID"), DATERANGEARRAYOID },
        { ngx_string("INT8RANGEARRAYOID"), INT8RANGEARRAYOID },
#ifdef INT4MULTIRANGEARRAYOID
        { ngx_string("INT4MULTIRANGEARRAYOID"), INT4MULTIRANGEARRAYOID },
#endif
#ifdef NUMMULTIRANGEARRAYOID
        { ngx_string("NUMMULTIRANGEARRAYOID"), NUMMULTIRANGEARRAYOID },
#endif
#ifdef TSMULTIRANGEARRAYOID
        { ngx_string("TSMULTIRANGEARRAYOID"), TSMULTIRANGEARRAYOID },
#endif
#ifdef TSTZMULTIRANGEARRAYOID
        { ngx_string("TSTZMULTIRANGEARRAYOID"), TSTZMULTIRANGEARRAYOID },
#endif
#ifdef DATEMULTIRANGEARRAYOID
        { ngx_string("DATEMULTIRANGEARRAYOID"), DATEMULTIRANGEARRAYOID },
#endif
#ifdef INT8MULTIRANGEARRAYOID
        { ngx_string("INT8MULTIRANGEARRAYOID"), INT8MULTIRANGEARRAYOID },
#endif
        { ngx_string("CSTRINGARRAYOID"), CSTRINGARRAYOID },
        { ngx_null_string, 0 }
    };
    for (ngx_uint_t i = 0; e[i].name.len; i++) if (e[i].name.len - 3 == type->len && !ngx_strncasecmp(e[i].name.data, type->data, type->len)) return e[i].value;
    return 0;
}


char *ngx_postgres_query_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_loc_conf_t *plc = conf;
    if (!plc->query.nelts && ngx_array_init(&plc->query, cf->pool, 1, sizeof(ngx_postgres_query_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_array_init != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_query_t *query = ngx_array_push(&plc->query);
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
    ngx_str_t *args = cf->args->elts;
    ngx_uint_t i, j;
    for (j = 1; j < cf->args->nelts; j++) {
        for (i = 0; b[i].name.len; i++) if (b[i].name.len == args[j].len && !ngx_strncasecmp(b[i].name.data, args[j].data, b[i].name.len)) { query->method |= b[i].mask; break; }
        if (!b[i].name.len) break;
    }
    ngx_str_t sql = ngx_null_string;
    for (i = j; i < cf->args->nelts; i++) {
        if (i > j) sql.len++;
        sql.len += args[i].len;
    }
    if (!sql.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: empty query", &cmd->name); return NGX_CONF_ERROR; }
    if (!(sql.data = ngx_pnalloc(cf->pool, sql.len))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    u_char *q = sql.data;
    for (i = j; i < cf->args->nelts; i++) {
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
