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

#include <assert.h>
#include <pg_config.h>

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
    { ngx_string("reject"), 0 },
    { ngx_string("ignore"), 1 },
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
    location_conf->upstream.buffering = 1;
    location_conf->upstream.ignore_client_abort = 1;
    location_conf->upstream.intercept_errors = 1;
    location_conf->upstream.intercept_404 = 1;
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
    const char                        **keywords;
    const char                        **values;
    int                                 family;
    ngx_addr_t                         *addrs;
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
            peer->keywords = elts[i].keywords;
            peer->values = elts[i].values;
            peer->sockaddr = elts[i].addrs[j].sockaddr;
            peer->socklen = elts[i].addrs[j].socklen;
            peer->name = &elts[i].addrs[j].name;
            if (!(peer->host.data = ngx_pnalloc(cf->pool, NGX_SOCKADDR_STRLEN))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            if (!(peer->host.len = ngx_sock_ntop(peer->sockaddr, peer->socklen, peer->host.data, NGX_SOCKADDR_STRLEN, 0))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_sock_ntop"); return NGX_ERROR; }
            if (!(peer->value = ngx_pnalloc(cf->pool, peer->host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0)))) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pnalloc"); return NGX_ERROR; }
            (void) ngx_cpystrn(peer->value, peer->host.data + (elts[i].family == AF_UNIX ? 5 : 0), peer->host.len + 1 + (elts[i].family == AF_UNIX ? -5 : 0));
            n++;
        }
    }
    server_conf->save = 0;
    if (!server_conf->max_save) return NGX_OK;
    ngx_postgres_save_t *ps = ngx_pcalloc(cf->pool, sizeof(ngx_postgres_save_t) * server_conf->max_save);
    if (!ps) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    for (ngx_uint_t i = 0; i < server_conf->max_save; i++) {
        ngx_queue_insert_head(&server_conf->free, &ps[i].queue);
        ps[i].common.num = i;
    }
    return NGX_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { /* Based on: ngx_http_upstream.c/ngx_http_upstream_server Copyright (C) Igor Sysoev */
    ngx_http_upstream_srv_conf_t *upstream_srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if (!upstream_srv_conf->servers && !(upstream_srv_conf->servers = ngx_array_create(cf->pool, 1, sizeof(ngx_postgres_server_t)))) return "!ngx_array_create";
    ngx_postgres_server_t *server = ngx_array_push(upstream_srv_conf->servers);
    if (!server) return "!ngx_array_push";
    ngx_memzero(server, sizeof(ngx_postgres_server_t));
    ngx_str_t *elts = cf->args->elts;
    size_t len = 0;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (i > 1) len += sizeof(" ") - 1;
        len += elts[i].len;
    }
    u_char *equal = (u_char *)ngx_strchr(elts[1].data, '=');
    if (!equal) len += sizeof("host=") - 1;
    u_char *conninfo = ngx_pnalloc(cf->pool, len + 1);
    if (!conninfo) return "!ngx_pnalloc";
    u_char *p = conninfo;
    if (!equal) p = ngx_cpymem(p, "host=", sizeof("host=") - 1);
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (i > 1) *p++ = ' ';
        p = ngx_cpymem(p, elts[i].data, elts[i].len);
    }
    *p = '\0';
    char *err;
    PQconninfoOption *opts = PQconninfoParse((const char *)conninfo, &err);
    if (!opts) {
        int len;
        if (err && (len = strlen(err))) {
            err[len - 1] = '\0';
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, err);
            PQfreemem(err);
            return NGX_CONF_ERROR;
        }
        return "!PQconninfoParse";
    }
    u_char *host = NULL;
    u_char *hostaddr = NULL;
    u_char *options = NULL;
    in_port_t port = DEF_PGPORT;
    int arg = 4;
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name", sizeof("fallback_application_name") - 1)) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"host", sizeof("host") - 1)) { host = (u_char *)opt->val; continue; }
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"hostaddr", sizeof("hostaddr") - 1)) { hostaddr = (u_char *)opt->val; continue; }
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"options", sizeof("options") - 1)) { options = (u_char *)opt->val; continue; }
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"port", sizeof("port") - 1)) {
            ngx_int_t n = ngx_atoi((u_char *)opt->val, ngx_strlen(opt->val));
            if (n == NGX_ERROR) return "ngx_atoi == NGX_ERROR";
            port = (in_port_t)n;
        }
        arg++;
    }
    if (!host && !hostaddr) host = (u_char *)"unix:///run/postgresql";
    ngx_url_t url;
    ngx_memzero(&url, sizeof(ngx_url_t));
    url.url = hostaddr ? (ngx_str_t){ngx_strlen(hostaddr), hostaddr} : (ngx_str_t){ngx_strlen(host), host};
    url.default_port = port;
    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        if (url.err) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s %V:%i", url.err, &url.url, url.default_port); return NGX_CONF_ERROR; }
        return "ngx_parse_url != NGX_OK";
    }
    server->addrs = url.addrs;
    server->naddrs = url.naddrs;
    server->family = url.family;
    if (host && server->family != AF_UNIX) arg++;
    if (!(server->keywords = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) return "!ngx_pnalloc";
    if (!(server->values = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) return "!ngx_pnalloc";
    arg = 0;
    server->keywords[arg] = server->family == AF_UNIX ? "host" : "hostaddr";
    arg++;
    server->keywords[arg] = "fallback_application_name";
    server->values[arg] = "nginx";
    arg++;
    server->keywords[arg] = "options";
    server->values[arg] = (const char *)options;
    if (host && server->family != AF_UNIX) {
        arg++;
        server->keywords[arg] = "host";
        if (!(server->values[arg] = ngx_pnalloc(cf->pool, url.host.len + 1))) return "!ngx_pnalloc";
        (void) ngx_cpystrn((u_char *)server->values[arg], url.host.data, url.host.len + 1);
    }
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name", sizeof("fallback_application_name") - 1)) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"host", sizeof("host") - 1)) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"hostaddr", sizeof("hostaddr") - 1)) continue;
        if (!ngx_strncasecmp((u_char *)opt->keyword, (u_char *)"options", sizeof("options") - 1)) continue;
        arg++;
        size_t keyword_len = ngx_strlen(opt->keyword);
        if (!(server->keywords[arg] = ngx_pnalloc(cf->pool, keyword_len + 1))) return "!ngx_pnalloc";
        (void) ngx_cpystrn((u_char *)server->keywords[arg], (u_char *)opt->keyword, keyword_len + 1);
        size_t val_len = ngx_strlen(opt->val);
        if (!(server->values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) return "!ngx_pnalloc";
        (void) ngx_cpystrn((u_char *)server->values[arg], (u_char *)opt->val, val_len + 1);
    }
    arg++;
    server->keywords[arg] = NULL;
    server->values[arg] = NULL;
    PQconninfoFree(opts);
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
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == elts[i].len && !ngx_strncasecmp(e[j].name.data, elts[i].data, elts[i].len)) { server_conf->ignore = e[j].value; break; }
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
