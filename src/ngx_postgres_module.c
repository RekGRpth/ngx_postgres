#include <pg_config.h>

#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


static ngx_int_t ngx_postgres_preconfiguration(ngx_conf_t *cf) {
    return ngx_postgres_variable_add(cf);
}


static void ngx_postgres_server_cleanup(void *data) {
    ngx_postgres_server_t *server = data;
    while (!ngx_queue_empty(&server->ps.queue)) {
        ngx_queue_t *queue = ngx_queue_head(&server->ps.queue);
        ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        ngx_postgres_common_t *psc = &ps->common;
        ngx_postgres_free_connection(psc);
        ngx_queue_remove(&ps->queue);
    }
}


static void *ngx_postgres_create_srv_conf(ngx_conf_t *cf) {
    ngx_postgres_server_t *server = ngx_pcalloc(cf->pool, sizeof(*server));
    if (!server) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    server->ps.timeout = NGX_CONF_UNSET_MSEC;
    server->ps.requests = NGX_CONF_UNSET_UINT;
    server->pd.timeout = NGX_CONF_UNSET_MSEC;
    return server;
}


static void *ngx_postgres_create_loc_conf(ngx_conf_t *cf) {
    ngx_postgres_location_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    location->upstream.buffering = NGX_CONF_UNSET;
    location->upstream.buffer_size = NGX_CONF_UNSET_SIZE;
    location->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    location->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    location->upstream.ignore_client_abort = NGX_CONF_UNSET;
    location->upstream.intercept_errors = NGX_CONF_UNSET;
    location->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
    location->upstream.local = NGX_CONF_UNSET_PTR;
    location->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    location->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    location->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    location->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    location->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    location->upstream.request_buffering = NGX_CONF_UNSET;
    location->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    location->upstream.socket_keepalive = NGX_CONF_UNSET;
    location->upstream.store_access = NGX_CONF_UNSET_UINT;
    location->upstream.store = NGX_CONF_UNSET;
    location->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;
    ngx_str_set(&location->upstream.module, "postgres");
    return location;
}


static ngx_path_init_t ngx_postgres_temp_path = {
    ngx_string("/var/cache/nginx/postgres_temp"), { 1, 2, 0 }
};


static ngx_str_t ngx_postgres_hide_headers[] = {
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};


static char *ngx_postgres_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_postgres_location_t *prev = parent;
    ngx_postgres_location_t *conf = child;
    if (!conf->complex.value.data) conf->complex = prev->complex;
    if (!conf->queries.elts) conf->queries = prev->queries;
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    if (conf->upstream.store == NGX_CONF_UNSET) {
        ngx_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);
        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }
    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers, prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
    ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);
    ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t)ngx_pagesize);
    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_size_value(conf->upstream.limit_rate, prev->upstream.limit_rate, 0);
    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf, prev->upstream.max_temp_file_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf, prev->upstream.temp_file_write_size_conf, NGX_CONF_UNSET_SIZE);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_uint_value(conf->upstream.store_access, prev->upstream.store_access, 0600);
    ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 1);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.bufs.num < 2) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "there must be at least 2 \"postgres_buffers\""); return NGX_CONF_ERROR; }
    size_t size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) size = conf->upstream.bufs.size;
    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) conf->upstream.busy_buffers_size = 2 * size;
    else conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf;
    if (conf->upstream.busy_buffers_size < size) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"postgres_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"postgres_buffer_size\" and one of the \"postgres_buffers\""); return NGX_CONF_ERROR; }
    if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"postgres_busy_buffers_size\" must be less than the size of all \"postgres_buffers\" minus one buffer"); return NGX_CONF_ERROR; }
    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) conf->upstream.temp_file_write_size = 2 * size;
    else conf->upstream.temp_file_write_size = conf->upstream.temp_file_write_size_conf;
    if (conf->upstream.temp_file_write_size < size) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"postgres_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"postgres_buffer_size\" and one of the \"postgres_buffers\""); return NGX_CONF_ERROR; }
    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    else conf->upstream.max_temp_file_size = conf->upstream.max_temp_file_size_conf;
    if (conf->upstream.max_temp_file_size != 0 && conf->upstream.max_temp_file_size < size) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"postgres_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"postgres_buffer_size\" and one of the \"postgres_buffers\""); return NGX_CONF_ERROR; }
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_postgres_temp_path) != NGX_OK) return NGX_CONF_ERROR;
    ngx_hash_init_t hash;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "postgres_hide_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_postgres_hide_headers, &hash) != NGX_OK) return NGX_CONF_ERROR;
    return NGX_CONF_OK;
}


typedef struct {
    ngx_http_upstream_server_t u; // !!! always first !!!
    int family;
    ngx_postgres_connect_t connect;
} ngx_postgres_upstream_server_t;


static ngx_int_t ngx_postgres_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *usc) {
    if (!usc->servers || !usc->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &usc->host, usc->file_name, usc->line); return NGX_ERROR; }
    ngx_postgres_server_t *server = ngx_http_conf_upstream_srv_conf(usc, ngx_postgres_module);
    ngx_conf_init_msec_value(server->ps.timeout, 60 * 60 * 1000);
    ngx_conf_init_uint_value(server->ps.requests, 1000);
    usc->peer.init = ngx_postgres_peer_init;
    ngx_queue_init(&server->peer.queue);
    ngx_postgres_peers_t *peers = &server->peers;
    ngx_postgres_peers_t *backs = &server->backs;
    ngx_postgres_upstream_server_t *elts = usc->servers->elts;
    ngx_uint_t n = 0;
    ngx_uint_t  w = 0;
    for (ngx_uint_t i = 0; i < usc->servers->nelts; i++) if (!elts[i].u.backup) {
        n += elts[i].u.naddrs;
        w += elts[i].u.naddrs * elts[i].u.weight;
    }
    if (!n) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no \"postgres_server\" found in upstream \"%V\" in %s:%ui", &usc->host, usc->file_name, usc->line); return NGX_ERROR; }
    peers->single = n == 1;
    peers->number = n;
    peers->weighted = w != n;
    peers->total_weight = w;
    peers->name = usc->host;
    ngx_postgres_peer_t *peer = peers->peer = ngx_pcalloc(cf->pool, sizeof(*peer) * n);
    if (!peer) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    n = 0;
    for (ngx_uint_t i = 0; i < usc->servers->nelts; i++) {
        if (elts[i].u.backup) continue;
        for (ngx_uint_t j = 0; j < elts[i].u.naddrs; j++, n++) {
            if (n > 0) peer[n - 1].rr.next = &peer[n].rr;
            ngx_queue_insert_tail(&server->peer.queue, &peer[n].queue);
            peer[n].connect = elts[i].connect;
            peer[n].rr.down = elts[i].u.down;
            peer[n].rr.effective_weight = elts[i].u.weight;
            peer[n].rr.fail_timeout = elts[i].u.fail_timeout;
            peer[n].rr.max_conns = elts[i].u.max_conns;
            peer[n].rr.max_fails = elts[i].u.max_fails;
            peer[n].rr.name = elts[i].u.addrs[j].name;
            peer[n].rr.sockaddr = elts[i].u.addrs[j].sockaddr;
            peer[n].rr.socklen = elts[i].u.addrs[j].socklen;
            peer[n].rr.weight = elts[i].u.weight;
            if (!(peer[n].rr.host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(peer[n].rr.host.len = ngx_sock_ntop(peer[n].rr.sockaddr, peer[n].rr.socklen, peer[n].rr.host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_sock_ntop"); return NGX_ERROR; }
            if (!(peer[n].value = ngx_pnalloc(cf->pool, peer[n].rr.host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            (void)ngx_cpystrn(peer[n].value, peer[n].rr.host.data + (elts[i].family == AF_UNIX ? 5 : 0), peer[n].rr.host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0));
        }
    }
    n = 0;
    w = 0;
    for (ngx_uint_t i = 0; i < usc->servers->nelts; i++) if (elts[i].u.backup) {
        n += elts[i].u.naddrs;
        w += elts[i].u.naddrs * elts[i].u.weight;
    }
    if (n) {
        peers->single = 0;
        backs->single = 0;
        backs->number = n;
        backs->weighted = w != n;
        backs->total_weight = w;
        backs->name = usc->host;
        peers->next = backs;
        peer = backs->peer = ngx_pcalloc(cf->pool, sizeof(*peer) * n);
        if (!peer) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
        n = 0;
        for (ngx_uint_t i = 0; i < usc->servers->nelts; i++) {
            if (!elts[i].u.backup) continue;
            for (ngx_uint_t j = 0; j < elts[i].u.naddrs; j++, n++) {
                if (n > 0) peer[n - 1].rr.next = &peer[n].rr;
    //            ngx_queue_insert_tail(&server->peer.queue, &peer[n].queue);
                peer[n].connect = elts[i].connect;
                peer[n].rr.down = elts[i].u.down;
                peer[n].rr.effective_weight = elts[i].u.weight;
                peer[n].rr.fail_timeout = elts[i].u.fail_timeout;
                peer[n].rr.max_conns = elts[i].u.max_conns;
                peer[n].rr.max_fails = elts[i].u.max_fails;
                peer[n].rr.name = elts[i].u.addrs[j].name;
                peer[n].rr.sockaddr = elts[i].u.addrs[j].sockaddr;
                peer[n].rr.socklen = elts[i].u.addrs[j].socklen;
                peer[n].rr.weight = elts[i].u.weight;
                if (!(peer[n].rr.host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                if (!(peer[n].rr.host.len = ngx_sock_ntop(peer[n].rr.sockaddr, peer[n].rr.socklen, peer[n].rr.host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_sock_ntop"); return NGX_ERROR; }
                if (!(peer[n].value = ngx_pnalloc(cf->pool, peer[n].rr.host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
                (void)ngx_cpystrn(peer[n].value, peer[n].rr.host.data + (elts[i].family == AF_UNIX ? 5 : 0), peer[n].rr.host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0));
            }
        }
    }
    if (!server->ps.max) return NGX_OK;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = ngx_postgres_server_cleanup;
    cln->data = server;
    ngx_queue_init(&server->free.queue);
    ngx_conf_init_msec_value(server->pd.timeout, 60 * 1000);
    ngx_queue_init(&server->pd.queue);
    ngx_queue_init(&server->ps.queue);
    ngx_postgres_save_t *ps = ngx_pcalloc(cf->pool, sizeof(*ps) * server->ps.max);
    if (!ps) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    for (ngx_uint_t i = 0; i < server->ps.max; i++) {
        ngx_queue_insert_tail(&server->free.queue, &ps[i].queue);
    }
    return NGX_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { /* Based on: ngx_http_upstream.c/ngx_http_upstream_server Copyright (C) Igor Sysoev */
    ngx_http_upstream_srv_conf_t *usc = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (!usc->servers && !(usc->servers = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_upstream_server_t)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_create", &cmd->name); return NGX_CONF_ERROR; }
    ngx_postgres_upstream_server_t *pus = ngx_array_push(usc->servers);
    if (!pus) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(pus, sizeof(*pus));
    pus->u.fail_timeout = 10;
    pus->u.max_fails = 1;
    pus->u.weight = 1;
    ngx_str_t *elts = cf->args->elts;
    size_t len = 0;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("weight=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_WEIGHT)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            elts[i].len = elts[i].len - (sizeof("weight=") - 1);
            elts[i].data = &elts[i].data[sizeof("weight=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be number", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be positive", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            pus->u.weight = (ngx_uint_t)n;
        } else if (elts[i].len > sizeof("max_conns=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_MAX_CONNS)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_conns\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            elts[i].len = elts[i].len - (sizeof("max_conns=") - 1);
            elts[i].data = &elts[i].data[sizeof("max_conns=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_conns\" value \"%V\" must be number", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            pus->u.max_conns = (ngx_uint_t)n;
        } else if (elts[i].len > sizeof("max_fails=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_MAX_FAILS)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_fails\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            elts[i].len = elts[i].len - (sizeof("max_fails=") - 1);
            elts[i].data = &elts[i].data[sizeof("max_fails=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_fails\" value \"%V\" must be number", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            pus->u.max_fails = (ngx_uint_t)n;
        } else if (elts[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"fail_timeout\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            elts[i].len = elts[i].len - (sizeof("fail_timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("fail_timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 1);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"fail_timeout\" value \"%V\" must be time", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            pus->u.fail_timeout = (time_t)n;
        } else if (elts[i].len == sizeof("backup") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"backup", sizeof("backup") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_BACKUP)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"backup\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            pus->u.backup = 1;
        } else if (elts[i].len == sizeof("down") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"down", sizeof("down") - 1)) {
            if (!(usc->flags & NGX_HTTP_UPSTREAM_DOWN)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"down\" not supported", &cmd->name); return NGX_CONF_ERROR; }
            pus->u.down = 1;
        } else {
            if (i > 1) len++;
            len += elts[i].len;
        }
    }
    u_char *conninfo = ngx_pnalloc(cf->pool, len + 1);
    if (!conninfo) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    u_char *p = conninfo;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("weight=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"weight=", sizeof("weight=") - 1));
        else if (elts[i].len > sizeof("max_conns=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1));
        else if (elts[i].len > sizeof("max_fails=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1));
        else if (elts[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1));
        else if (elts[i].len == sizeof("backup") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"backup", sizeof("backup") - 1));
        else if (elts[i].len == sizeof("down") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"down", sizeof("down") - 1));
        else {
            if (i > 1) *p++ = ' ';
            p = ngx_cpymem(p, elts[i].data, elts[i].len);
        }
    }
    *p = '\0';
    char *err;
    PQconninfoOption *opts = PQconninfoParse((const char *)conninfo, &err);
    if (!opts) {
        if (err && (len = ngx_strlen(err))) {
            err[len - 1] = '\0';
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: %s", &cmd->name, err);
            PQfreemem(err);
            return NGX_CONF_ERROR;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !PQconninfoParse", &cmd->name); return NGX_CONF_ERROR;
    }
    u_char *host = NULL;
    u_char *hostaddr = NULL;
    u_char *options = NULL;
    u_char *connect = NULL;
    in_port_t port = DEF_PGPORT;
    int arg = 4;
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host")) { host = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) { hostaddr = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"options")) { options = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"connect_timeout")) connect = (u_char *)opt->val; else
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"port")) {
            ngx_int_t n = ngx_atoi((u_char *)opt->val, ngx_strlen(opt->val));
            if (n == NGX_ERROR) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_atoi == NGX_ERROR", &cmd->name); return NGX_CONF_ERROR; }
            port = (in_port_t)n;
        }
        arg++;
    }
    if (!connect) pus->connect.timeout = 60000; else {
        ngx_int_t n = ngx_parse_time(&(ngx_str_t){ngx_strlen(connect), connect}, 0);
        if (n == NGX_ERROR) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_parse_time == NGX_ERROR", &cmd->name); return NGX_CONF_ERROR; }
        pus->connect.timeout = (ngx_msec_t)n;
    }
    if (!host && !hostaddr) host = (u_char *)"unix:///run/postgresql";
    ngx_url_t url;
    ngx_memzero(&url, sizeof(url));
    url.url = hostaddr ? (ngx_str_t){ngx_strlen(hostaddr), hostaddr} : (ngx_str_t){ngx_strlen(host), host};
    url.default_port = port;
    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        if (url.err) ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_parse_url(%V:%i) != NGX_OK and %s", &cmd->name, &url.url, url.default_port, url.err);
        else ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_parse_url(%V:%i) != NGX_OK", &cmd->name, &url.url, url.default_port);
        PQconninfoFree(opts);
        return NGX_CONF_ERROR;
    }
    pus->u.addrs = url.addrs;
    pus->u.naddrs = url.naddrs;
    pus->family = url.family;
    if (host && pus->family != AF_UNIX) arg++;
    if (!(pus->connect.keywords = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    if (!(pus->connect.values = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    arg = 0;
    pus->connect.keywords[arg] = pus->family == AF_UNIX ? "host" : "hostaddr";
    arg++;
    pus->connect.keywords[arg] = "fallback_application_name";
    pus->connect.values[arg] = "nginx";
    arg++;
    pus->connect.keywords[arg] = "options";
    pus->connect.values[arg] = (const char *)options;
    if (host && pus->family != AF_UNIX) {
        arg++;
        pus->connect.keywords[arg] = "host";
        if (!(pus->connect.values[arg] = ngx_pnalloc(cf->pool, url.host.len + 1))) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)pus->connect.values[arg], url.host.data, url.host.len + 1);
    }
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"options")) continue;
        arg++;
        size_t keyword_len = ngx_strlen(opt->keyword);
        if (!(pus->connect.keywords[arg] = ngx_pnalloc(cf->pool, keyword_len + 1))) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)pus->connect.keywords[arg], (u_char *)opt->keyword, keyword_len + 1);
        size_t val_len = ngx_strlen(opt->val);
        if (!(pus->connect.values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) { PQconninfoFree(opts); ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)pus->connect.values[arg], (u_char *)opt->val, val_len + 1);
    }
    arg++;
    pus->connect.keywords[arg] = NULL;
    pus->connect.values[arg] = NULL;
    PQconninfoFree(opts);
    usc->peer.init_upstream = ngx_postgres_peer_init_upstream;
    usc->flags = NGX_HTTP_UPSTREAM_CREATE|NGX_HTTP_UPSTREAM_WEIGHT|NGX_HTTP_UPSTREAM_MAX_CONNS|NGX_HTTP_UPSTREAM_MAX_FAILS|NGX_HTTP_UPSTREAM_FAIL_TIMEOUT|NGX_HTTP_UPSTREAM_DOWN|NGX_HTTP_UPSTREAM_BACKUP;
    return NGX_CONF_OK;
}


static char *ngx_postgres_keepalive_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_t *server = conf;
    if (server->ps.max) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    ngx_int_t n = ngx_atoi(elts[1].data, elts[1].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be number", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    server->ps.max = (ngx_uint_t)n;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("overflow=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("overflow=") - 1);
            elts[i].data = &elts[i].data[sizeof("overflow=") - 1];
            static const ngx_conf_enum_t e[] = {
                { ngx_string("ignore"), 0 },
                { ngx_string("reject"), 1 },
                { ngx_null_string, 0 }
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server->ps.reject = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"overflow\" value \"%V\" must be \"ignore\" or \"reject\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else if (elts[i].len > sizeof("timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 0);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be time", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be positive", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            server->ps.timeout = (ngx_msec_t)n;
        } else if (elts[i].len > sizeof("requests=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"requests=", sizeof("requests=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("requests=") - 1);
            elts[i].data = &elts[i].data[sizeof("requests=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"requests\" value \"%V\" must be number", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"requests\" value \"%V\" must be positive", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            server->ps.requests = (ngx_uint_t)n;
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_prepare_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_t *server = conf;
    if (!server->ps.max) return "works only with \"postgres_keepalive\"";
    if (server->prepare.max) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    ngx_int_t n = ngx_atoi(elts[1].data, elts[1].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be number", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    server->prepare.max = (ngx_uint_t)n;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("overflow=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("overflow=") - 1);
            elts[i].data = &elts[i].data[sizeof("overflow=") - 1];
            static const ngx_conf_enum_t e[] = {
                { ngx_string("ignore"), 0 },
                { ngx_string("deallocate"), 1 },
                { ngx_null_string, 0 }
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server->prepare.deallocate = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"overflow\" value \"%V\" must be \"ignore\" or \"deallocate\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_queue_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_t *server = conf;
    if (!server->ps.max) return "works only with \"postgres_keepalive\"";
    if (server->pd.max) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    ngx_int_t n = ngx_atoi(elts[1].data, elts[1].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be number", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    server->pd.max = (ngx_uint_t)n;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("overflow=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("overflow=") - 1);
            elts[i].data = &elts[i].data[sizeof("overflow=") - 1];
            static const ngx_conf_enum_t e[] = {
                { ngx_string("ignore"), 0 },
                { ngx_string("reject"), 1 },
                { ngx_null_string, 0 }
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server->pd.reject = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"overflow\" value \"%V\" must be \"ignore\" or \"reject\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
        } else if (elts[i].len > sizeof("timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 0);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be time", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be positive", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
            server->pd.timeout = (ngx_msec_t)n;
        } else { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &elts[i]); return NGX_CONF_ERROR; }
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (location->upstream.upstream || location->complex.value.data) return "duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (!elts[1].len) return "error: empty upstream name";
    ngx_http_core_loc_conf_t *core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core->handler = ngx_postgres_handler;
    if (core->name.data[core->name.len - 1] == '/') core->auto_redirect = 1;
    if (ngx_http_script_variables_count(&elts[1])) { /* complex value */
        ngx_http_compile_complex_value_t ccv = {cf, &elts[1], &location->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_http_compile_complex_value != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    } else { /* simple value */
        ngx_url_t url;
        ngx_memzero(&url, sizeof(url));
        url.url = elts[1];
        url.no_resolve = 1;
        if (!(location->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: !ngx_http_upstream_add", &cmd->name); return NGX_CONF_ERROR; }
        return NGX_CONF_OK;
    }
}


static char *ngx_postgres_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_t *server = conf;
    return ngx_log_set_log(cf, &server->ps.log);
}


static char *ngx_postgres_trace_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_t *server = conf;
    return ngx_log_set_log(cf, &server->trace.log);
}


char *ngx_postgres_timeout_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    ngx_postgres_query_t *query = location->query;
    ngx_str_t *elts = cf->args->elts;
    ngx_int_t n = ngx_parse_time(&elts[1], 0);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be time", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (!query) location->timeout = (ngx_msec_t)n;
    else if (location->timeout) return "duplicate";
    else if (query->timeout) return "duplicate";
    else query->timeout = (ngx_msec_t)n;
    return NGX_CONF_OK;
}


char *ngx_postgres_prepare_conf_(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    ngx_postgres_query_t *query = location->query;
    ngx_str_t *elts = cf->args->elts;
    static const ngx_conf_enum_t e[] = {
        { ngx_string("off"), 0 },
        { ngx_string("no"), 0 },
        { ngx_string("false"), 0 },
        { ngx_string("on"), 1 },
        { ngx_string("yes"), 1 },
        { ngx_string("true"), 1 },
        { ngx_null_string, 0 }
    };
    ngx_flag_t prepare;
    ngx_uint_t j;
    for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[1].len && !ngx_strncasecmp(e[j].name.data, elts[1].data, elts[1].len)) { prepare = e[j].value; break; }
    if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"append\" value \"%V\" must be \"off\", \"no\", \"false\", \"on\", \"yes\" or \"true\"", &cmd->name, &elts[1]); return NGX_CONF_ERROR; }
    if (!query) location->prepare = prepare;
    else if (location->prepare) return "duplicate";
    else if (query->prepare) return "duplicate";
    else query->prepare = prepare;
    return NGX_CONF_OK;
}


static ngx_conf_bitmask_t ngx_postgres_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static char *ngx_postgres_store_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_t *location = conf;
    if (location->upstream.store != NGX_CONF_UNSET) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].len == sizeof("off") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"off", sizeof("off") - 1)) { location->upstream.store = 0; return NGX_CONF_OK; }
    location->upstream.store = 1;
    if (elts[1].len == sizeof("on") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"on", sizeof("on") - 1)) return NGX_CONF_OK;
    elts[1].len++;
    ngx_http_script_compile_t sc;
    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
    sc.cf = cf;
    sc.source = &elts[1];
    sc.lengths = &location->upstream.store_lengths;
    sc.values = &location->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&elts[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;
    if (ngx_http_script_compile(&sc) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: ngx_http_script_compile != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
    return NGX_CONF_OK;
}


static ngx_command_t ngx_postgres_commands[] = {
  { .name = ngx_string("postgres_log"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_log_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_keepalive"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
    .set = ngx_postgres_keepalive_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_prepare"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
    .set = ngx_postgres_prepare_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_queue"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12|NGX_CONF_TAKE3,
    .set = ngx_postgres_queue_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_server"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_server_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_trace"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_trace_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },

  { .name = ngx_string("postgres_output"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_output_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_pass"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_pass_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_prepare"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_prepare_conf_,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_query"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_query_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_set"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
    .set = ngx_postgres_set_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_store"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_store_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_timeout_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },

  { .name = ngx_string("postgres_bind"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    .set = ngx_http_upstream_bind_set_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.local),
    .post = NULL },
  { .name = ngx_string("postgres_buffering"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.buffering),
    .post = NULL },
  { .name = ngx_string("postgres_buffers"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    .set = ngx_conf_set_bufs_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.bufs),
    .post = NULL },
  { .name = ngx_string("postgres_buffer_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.buffer_size),
    .post = NULL },
  { .name = ngx_string("postgres_busy_buffers_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.busy_buffers_size_conf),
    .post = NULL },
  { .name = ngx_string("postgres_hide_header"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_array_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.hide_headers),
    .post = NULL },
  { .name = ngx_string("postgres_ignore_client_abort"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.ignore_client_abort),
    .post = NULL },
  { .name = ngx_string("postgres_ignore_headers"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_conf_set_bitmask_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.ignore_headers),
    .post = &ngx_http_upstream_ignore_headers_masks },
  { .name = ngx_string("postgres_intercept_errors"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.intercept_errors),
    .post = NULL },
  { .name = ngx_string("postgres_limit_rate"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.limit_rate),
    .post = NULL },
  { .name = ngx_string("postgres_max_temp_file_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.max_temp_file_size_conf),
    .post = NULL },
  { .name = ngx_string("postgres_next_upstream"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_conf_set_bitmask_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.next_upstream),
    .post = &ngx_postgres_next_upstream_masks },
  { .name = ngx_string("postgres_next_upstream_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.next_upstream_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_next_upstream_tries"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.next_upstream_tries),
    .post = NULL },
  { .name = ngx_string("postgres_pass_header"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_array_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.pass_headers),
    .post = NULL },
  { .name = ngx_string("postgres_read_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.read_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_request_buffering"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.request_buffering),
    .post = NULL },
  { .name = ngx_string("postgres_send_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.send_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_socket_keepalive"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.socket_keepalive),
    .post = NULL },
  { .name = ngx_string("postgres_store_access"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
    .set = ngx_conf_set_access_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.store_access),
    .post = NULL },
  { .name = ngx_string("postgres_temp_file_write_size"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.temp_file_write_size_conf),
    .post = NULL },
  { .name = ngx_string("postgres_temp_path"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
    .set = ngx_conf_set_path_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_t, upstream.temp_path),
    .post = NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_postgres_ctx = {
    .preconfiguration = ngx_postgres_preconfiguration,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_postgres_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_postgres_create_loc_conf,
    .merge_loc_conf = ngx_postgres_merge_loc_conf
};

ngx_module_t ngx_postgres_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_postgres_ctx,
    .commands = ngx_postgres_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
