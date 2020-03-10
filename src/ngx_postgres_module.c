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

#include "ngx_postgres_handler.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_output.h"
#include "ngx_postgres_upstream.h"
#include "ngx_postgres_variable.h"


#define NGX_CONF_TAKE34  (NGX_CONF_TAKE3|NGX_CONF_TAKE4)


ngx_conf_enum_t ngx_postgres_mode_options[] = {
    { ngx_string("multi"), 0 },
    { ngx_string("single"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_overflow_options[] = {
    { ngx_string("ignore"), 0 },
    { ngx_string("reject"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_prepare_options[] = {
    { ngx_string("off"), 0 },
    { ngx_string("no"), 0 },
    { ngx_string("false"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("yes"), 1 },
    { ngx_string("true"), 1 },
    { ngx_null_string, 0 }
};

ngx_conf_enum_t ngx_postgres_output_options[] = {
    { ngx_string("off"), 0 },
    { ngx_string("no"), 0 },
    { ngx_string("false"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("yes"), 1 },
    { ngx_string("true"), 1 },
    { ngx_null_string, 0 }
};

struct ngx_postgres_output_enum_t {
    ngx_str_t name;
    unsigned binary:1;
    ngx_postgres_output_handler_pt handler;
} ngx_postgres_output_handlers[] = {
    { ngx_string("none"), 0, NULL },
    { ngx_string("text"), 0, ngx_postgres_output_text },
    { ngx_string("csv"), 0, ngx_postgres_output_csv },
    { ngx_string("value"), 0, ngx_postgres_output_value },
    { ngx_string("binary"), 1, ngx_postgres_output_value },
    { ngx_string("json"), 0, ngx_postgres_output_json },
    { ngx_null_string, 0, NULL }
};


static ngx_int_t ngx_postgres_preconfiguration(ngx_conf_t *cf) {
    return ngx_postgres_variable_add(cf);
}


static void ngx_postgres_server_conf_cleanup(void *data) {
    ngx_postgres_server_conf_t *server_conf = data;
    server_conf->max_save = 0; /* just to be on the safe-side */
    while (!ngx_queue_empty(&server_conf->busy)) {
        ngx_queue_t *queue = ngx_queue_head(&server_conf->busy);
        ngx_postgres_save_t *ps = ngx_queue_data(queue, ngx_postgres_save_t, queue);
        if (ps->timeout.timer_set) ngx_del_timer(&ps->timeout);
        ngx_postgres_free_connection(&ps->common, NULL, 0);
        ngx_queue_remove(&ps->queue);
    }
}


static void *ngx_postgres_create_srv_conf(ngx_conf_t *cf) {
    ngx_postgres_server_conf_t *server_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_server_conf_t));
    if (!server_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    ngx_queue_init(&server_conf->busy);
    ngx_queue_init(&server_conf->free);
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pool_cleanup_add"); return NULL; }
    cln->handler = ngx_postgres_server_conf_cleanup;
    cln->data = server_conf;
    return server_conf;
}


static void *ngx_postgres_create_loc_conf(ngx_conf_t *cf) {
    ngx_postgres_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_location_conf_t));
    if (!location_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    location_conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    location_conf->output.header = 1;
    location_conf->output.string = 1;
    location_conf->variables = NGX_CONF_UNSET_PTR;
    /* the hardcoded values */
    location_conf->upstream.cyclic_temp_file = 0;
    location_conf->upstream.buffering = 1;
    location_conf->upstream.ignore_client_abort = 1;
    location_conf->upstream.send_lowat = 0;
    location_conf->upstream.bufs.num = 0;
    location_conf->upstream.busy_buffers_size = 0;
    location_conf->upstream.max_temp_file_size = 0;
    location_conf->upstream.temp_file_write_size = 0;
    location_conf->upstream.intercept_errors = 1;
    location_conf->upstream.intercept_404 = 1;
    location_conf->upstream.pass_request_headers = 0;
    location_conf->upstream.pass_request_body = 0;
    return location_conf;
}


static char *ngx_postgres_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_postgres_location_conf_t *prev = parent;
    ngx_postgres_location_conf_t *conf = child;
    ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    if (!conf->upstream.upstream && !conf->complex) {
        conf->upstream = prev->upstream;
        conf->complex = prev->complex;
    }
    if (!conf->query) conf->query = prev->query;
    if (!conf->output.handler && prev->output.handler) conf->output = prev->output;
    ngx_conf_merge_ptr_value(conf->variables, prev->variables, NULL);
    return NGX_CONF_OK;
}


typedef struct {
    in_port_t                           port;
    int                                 family;
    ngx_addr_t                         *addrs;
    ngx_str_t                           application_name;
    ngx_str_t                           dbname;
    ngx_str_t                           password;
    ngx_str_t                           user;
    ngx_uint_t                          naddrs;
} ngx_postgres_server_t;


static_assert(sizeof(ngx_postgres_server_t) <= sizeof(ngx_http_upstream_server_t), "sizeof(ngx_postgres_server_t) <= sizeof(ngx_http_upstream_server_t)");


static ngx_int_t ngx_postgres_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *upstream_srv_conf) {
    upstream_srv_conf->peer.init = ngx_postgres_peer_init;
    ngx_postgres_server_conf_t *server_conf = ngx_http_conf_upstream_srv_conf(upstream_srv_conf, ngx_postgres_module);
    if (!upstream_srv_conf->servers || !upstream_srv_conf->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no \"postgres_server\" defined in upstream \"%V\" in %s:%ui", &upstream_srv_conf->host, upstream_srv_conf->file_name, upstream_srv_conf->line); return NGX_ERROR; }
    ngx_postgres_server_t *elts = upstream_srv_conf->servers->elts;
    for (ngx_uint_t i = 0; i < upstream_srv_conf->servers->nelts; i++) server_conf->max_peer += elts[i].naddrs;
    if (!(server_conf->peers = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_peer_t) * server_conf->max_peer))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    for (ngx_uint_t i = 0, n = 0; i < upstream_srv_conf->servers->nelts; i++) {
        for (ngx_uint_t j = 0; j < elts[i].naddrs; j++) {
            ngx_postgres_peer_t *peer = &server_conf->peers[n];
            peer->sockaddr = elts[i].addrs[j].sockaddr;
            peer->socklen = elts[i].addrs[j].socklen;
            peer->name = &elts[i].addrs[j].name;
            if (!(peer->host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(peer->host.len = ngx_sock_ntop(peer->sockaddr, peer->socklen, peer->host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_sock_ntop"); return NGX_ERROR; }
            size_t len = elts[i].family == AF_UNIX ? sizeof("host=%s") - 1 - 1 + peer->host.len - 5 : sizeof("hostaddr=%V") - 1 - 1 + peer->host.len;
            len += sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1;
            if (elts[i].dbname.len) len += sizeof(" dbname=%V") - 1 - 1 + elts[i].dbname.len;
            if (elts[i].user.len) len += sizeof(" user=%V") - 1 - 1 + elts[i].user.len;
            if (elts[i].password.len) len += sizeof(" password=%V") - 1 - 1 + elts[i].password.len;
            if (elts[i].application_name.len) len += sizeof(" application_name=%V") - 1 - 1 + elts[i].application_name.len;
            if (!(peer->connstring = ngx_pnalloc(cf->pool, len))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            u_char *last = peer->connstring;
            last = elts[i].family == AF_UNIX ? ngx_snprintf(last, sizeof("host=%s") - 1 - 1 + peer->host.len - 5, "host=%s", &peer->host.data[5]) : ngx_snprintf(last, sizeof("hostaddr=%V") - 1 - 1 + peer->host.len, "hostaddr=%V", &peer->host);
            last = ngx_snprintf(last, sizeof(" port=%d") - 1 - 1 + sizeof("65535") - 1, " port=%d", elts[i].port);
            if (elts[i].dbname.len) last = ngx_snprintf(last, sizeof(" dbname=%V") - 1 - 1 + elts[i].dbname.len, " dbname=%V", &elts[i].dbname);
            if (elts[i].user.len) last = ngx_snprintf(last, sizeof(" user=%V") - 1 - 1 + elts[i].user.len, " user=%V", &elts[i].user);
            if (elts[i].password.len) last = ngx_snprintf(last, sizeof(" password=%V") - 1 - 1 + elts[i].password.len, " password=%V", &elts[i].password);
            if (elts[i].application_name.len) last = ngx_snprintf(last, sizeof(" application_name=%V") - 1 - 1 + elts[i].application_name.len, " application_name=%V", &elts[i].application_name);
            *last = '\0';
            n++;
        }
    }
    server_conf->save = 0;
    if (!server_conf->max_save) return NGX_OK;
    ngx_postgres_save_t *ps = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_save_t) * server_conf->max_save);
    if (!ps) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    for (ngx_uint_t i = 0; i < server_conf->max_save; i++) { ngx_queue_insert_head(&server_conf->free, &ps[i].queue); }
    return NGX_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { /* Based on: ngx_http_upstream.c/ngx_http_upstream_server Copyright (C) Igor Sysoev */
    ngx_http_upstream_srv_conf_t *upstream_srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (!upstream_srv_conf->servers && !(upstream_srv_conf->servers = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_server_t)))) return "!ngx_array_create";
    ngx_postgres_server_t *server = ngx_array_push(upstream_srv_conf->servers);
    if (!server) return "!ngx_array_push";
    ngx_memzero(server, sizeof(ngx_postgres_server_t));
    /* parse the first name:port argument */
    ngx_url_t url;
    ngx_memzero(&url, sizeof(ngx_url_t));
    ngx_str_t *elts = cf->args->elts;
    url.url = elts[1];
    url.default_port = 5432; /* PostgreSQL default */
    if (ngx_parse_url(cf->pool, &url) != NGX_OK) { if (url.err) return url.err; return "ngx_parse_url != NGX_OK"; }
    server->addrs = url.addrs;
    server->naddrs = url.naddrs;
    server->port = url.family == AF_UNIX ? url.default_port : url.port;
    server->family = url.family;
    /* parse various options */
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("port=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"port=", sizeof("port=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("port=") - 1);
            elts[i].data = &elts[i].data[sizeof("port=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server->port = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("dbname=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"dbname=", sizeof("dbname=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("dbname=") - 1);
            if (!(server->dbname.len = elts[i].len)) return "!server->dbname.len";
            elts[i].data = &elts[i].data[sizeof("dbname=") - 1];
            server->dbname.data = elts[i].data;
        } else if (elts[i].len > sizeof("user=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"user=", sizeof("user=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("user=") - 1);
            if (!(server->user.len = elts[i].len)) return "!server->user.len";
            elts[i].data = &elts[i].data[sizeof("user=") - 1];
            server->user.data = elts[i].data;
        } else if (elts[i].len > sizeof("password=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"password=", sizeof("password=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("password=") - 1);
            if (!(server->password.len = elts[i].len)) return "!server->password.len";
            elts[i].data = &elts[i].data[sizeof("password=") - 1];
            server->password.data = elts[i].data;
        } else if (elts[i].len > sizeof("application_name=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"application_name=", sizeof("application_name=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("application_name=") - 1);
            if (!(server->application_name.len = elts[i].len)) return "!server->application_name.len";
            elts[i].data = &elts[i].data[sizeof("application_name=") - 1];
            server->application_name.data = elts[i].data;
        } else return "invalid parameter";
    }
    upstream_srv_conf->peer.init_upstream = ngx_postgres_init_upstream;
    return NGX_CONF_OK;
}


static char *ngx_postgres_keepalive_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_server_conf_t *server_conf = conf;
    if (server_conf->max_save/* default */) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (cf->args->nelts == 2 && ((elts[1].len == sizeof("off") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"off", sizeof("off") - 1)) || (elts[1].len == sizeof("no") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"no", sizeof("no") - 1)) || (elts[1].len == sizeof("false") - 1 && !ngx_strncasecmp(elts[1].data, (u_char *)"false", sizeof("false") - 1)))) { server_conf->max_save = 0; server_conf->prepare = 0; return NGX_CONF_OK; }
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("requests=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"requests=", sizeof("requests=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("requests=") - 1);
            elts[i].data = &elts[i].data[sizeof("requests=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server_conf->max_requests = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("timeout=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("timeout=") - 1);
            elts[i].data = &elts[i].data[sizeof("timeout=") - 1];
            ngx_int_t n = ngx_parse_time(&elts[i], 0);
            if (n == NGX_ERROR) return "ngx_parse_time == NGX_ERROR";
            server_conf->timeout = (ngx_msec_t) n;
        } else if (elts[i].len > sizeof("save=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"save=", sizeof("save=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("save=") - 1);
            elts[i].data = &elts[i].data[sizeof("save=") - 1];
            ngx_int_t n = ngx_atoi(elts[i].data, elts[i].len);
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            server_conf->max_save = (ngx_uint_t) n;
        } else if (elts[i].len > sizeof("mode=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"mode=", sizeof("mode=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("mode=") - 1);
            elts[i].data = &elts[i].data[sizeof("mode=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_mode_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->single = e[j].value; break; }
            if (!e[j].name.len) return "invalid mode";
        } else if (elts[i].len > sizeof("overflow=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("overflow=") - 1);
            elts[i].data = &elts[i].data[sizeof("overflow=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_overflow_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->reject = e[j].value; break; }
            if (!e[j].name.len) return "invalid overflow";
        } else if (elts[i].len > sizeof("prepare=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"prepare=", sizeof("prepare=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("prepare=") - 1);
            elts[i].data = &elts[i].data[sizeof("prepare=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_prepare_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->prepare = e[j].value; break; }
            if (!e[j].name.len) return "invalid prepare";
        } else return "invalid parameter";
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->upstream.upstream || location_conf->complex) return "is duplicate";
    ngx_str_t *elts = cf->args->elts;
    if (!elts[1].len) return "empty upstream";
    ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_loc_conf->handler = ngx_postgres_handler;
    if (core_loc_conf->name.data[core_loc_conf->name.len - 1] == '/') core_loc_conf->auto_redirect = 1;
    if (ngx_http_script_variables_count(&elts[1])) { /* complex value */
        if (!(location_conf->complex = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t)))) return "!ngx_palloc";
        ngx_http_compile_complex_value_t ccv = {cf, &elts[1], location_conf->complex, 0, 0, 0};
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
        return NGX_CONF_OK;
    } else { /* simple value */
        ngx_url_t url;
        ngx_memzero(&url, sizeof(ngx_url_t));
        url.url = elts[1];
        url.no_resolve = 1;
        if (!(location_conf->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) return "!ngx_http_upstream_add";
        return NGX_CONF_OK;
    }
}


static char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_location_conf_t *location_conf = conf;
    if (location_conf->output.handler) return "is duplicate";
    struct ngx_postgres_output_enum_t *e = ngx_postgres_output_handlers;
    ngx_str_t *elts = cf->args->elts;
    ngx_uint_t i;
    for (i = 0; e[i].name.len; i++) if (e[i].name.len == elts[1].len && !ngx_strncasecmp(e[i].name.data, elts[1].data, elts[1].len)) { location_conf->output.handler = e[i].handler; break; }
    if (!e[i].name.len) return "invalid output format";
    location_conf->output.binary = e[i].binary;
    if (cf->args->nelts > 2 && location_conf->output.handler != ngx_postgres_output_text && location_conf->output.handler != ngx_postgres_output_csv) return "invalid extra parameters for output format";
    if (location_conf->output.handler == ngx_postgres_output_text) {
        location_conf->output.delimiter = '\t';
        ngx_str_set(&location_conf->output.null, "\\N");
    } else if (location_conf->output.handler == ngx_postgres_output_csv) {
        location_conf->output.delimiter = ',';
        ngx_str_set(&location_conf->output.null, "");
        location_conf->output.quote = '"';
        location_conf->output.escape = '"';
    }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (elts[i].len > sizeof("delimiter=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"delimiter=", sizeof("delimiter=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("delimiter=") - 1);
            if (!elts[i].len || elts[i].len > 1) return "invalid delimiter";
            elts[i].data = &elts[i].data[sizeof("delimiter=") - 1];
            location_conf->output.delimiter = *elts[i].data;
        } else if (elts[i].len > sizeof("null=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"null=", sizeof("null=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("null=") - 1);
            if (!(location_conf->output.null.len = elts[i].len)) return "invalid null";
            elts[i].data = &elts[i].data[sizeof("null=") - 1];
            location_conf->output.null.data = elts[i].data;
        } else if (elts[i].len > sizeof("header=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"header=", sizeof("header=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("header=") - 1);
            elts[i].data = &elts[i].data[sizeof("header=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.header = e[j].value; break; }
            if (!e[j].name.len) return "invalid header";
        } else if (elts[i].len > sizeof("string=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"string=", sizeof("string=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("string=") - 1);
            elts[i].data = &elts[i].data[sizeof("string=") - 1];
            ngx_uint_t j;
            ngx_conf_enum_t *e = ngx_postgres_output_options;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { location_conf->output.string = e[j].value; break; }
            if (!e[j].name.len) return "invalid string";
        } else if (elts[i].len >= sizeof("quote=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"quote=", sizeof("quote=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("quote=") - 1);
            if (!elts[i].len) { location_conf->output.quote = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid quote";
            elts[i].data = &elts[i].data[sizeof("quote=") - 1];
            location_conf->output.quote = *elts[i].data;
        } else if (elts[i].len >= sizeof("escape=") - 1 && !ngx_strncasecmp(elts[i].data, (u_char *)"escape=", sizeof("escape=") - 1)) {
            elts[i].len = elts[i].len - (sizeof("escape=") - 1);
            if (!elts[i].len) { location_conf->output.escape = '\0'; continue; }
            else if (elts[i].len > 1) return "invalid escape";
            elts[i].data = &elts[i].data[sizeof("escape=") - 1];
            location_conf->output.escape = *elts[i].data;
        } else return "invalid parameter";
    }
    return NGX_CONF_OK;
}


static ngx_command_t ngx_postgres_commands[] = {
  { .name = ngx_string("postgres_server"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_server_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_keepalive"),
    .type = NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_keepalive_conf,
    .conf = NGX_HTTP_SRV_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_pass"),
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_pass_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_query"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_postgres_query_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_output"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_output_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_set"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE34,
    .set = ngx_postgres_set_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_connect_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_conf_t, upstream.connect_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_result_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_location_conf_t, upstream.read_timeout),
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
