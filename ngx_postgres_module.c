#include "ngx_postgres_include.h"


#define DEF_PGPORT 5432


static ngx_int_t ngx_postgres_preconfiguration(ngx_conf_t *cf) {
    return ngx_postgres_variable_add(cf);
}


static void ngx_postgres_upstream_srv_conf_cln_handler(void *data) {
    ngx_postgres_upstream_srv_conf_t *pusc = data;
    queue_each(&pusc->keep.queue, q) ngx_postgres_close(queue_data(q, ngx_postgres_save_t, queue));
    queue_each(&pusc->work.queue, q) ngx_postgres_close(queue_data(q, ngx_postgres_save_t, queue));
}


static void *ngx_postgres_create_srv_conf(ngx_conf_t *cf) {
    ngx_postgres_upstream_srv_conf_t *pusc = ngx_pcalloc(cf->pool, sizeof(*pusc));
    if (!pusc) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    pusc->data.timeout = NGX_CONF_UNSET_MSEC;
    pusc->keep.requests = NGX_CONF_UNSET_UINT;
    pusc->keep.timeout = NGX_CONF_UNSET_MSEC;
    return pusc;
}


static void *ngx_postgres_create_loc_conf(ngx_conf_t *cf) {
    ngx_postgres_loc_conf_t *plc = ngx_pcalloc(cf->pool, sizeof(*plc));
    if (!plc) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pcalloc"); return NULL; }
    plc->read_request_body = NGX_CONF_UNSET;
    plc->upstream.ignore_client_abort = NGX_CONF_UNSET;
    plc->upstream.intercept_errors = NGX_CONF_UNSET;
    plc->upstream.limit_rate = NGX_CONF_UNSET_SIZE;
    plc->upstream.local = NGX_CONF_UNSET_PTR;
    plc->upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    plc->upstream.next_upstream_tries = NGX_CONF_UNSET_UINT;
    plc->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    plc->upstream.read_timeout = NGX_CONF_UNSET_MSEC;
    plc->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    plc->upstream.socket_keepalive = NGX_CONF_UNSET;
    ngx_str_set(&plc->upstream.module, "postgres");
    return plc;
}


static char *ngx_postgres_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_postgres_loc_conf_t *prev = parent;
    ngx_postgres_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->read_request_body, prev->read_request_body, 0);
    if (!conf->complex.value.data) conf->complex = prev->complex;
    if (!conf->query.nelts) conf->query = prev->query;
    if (!conf->upstream.upstream) conf->upstream = prev->upstream;
    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers, prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET);
    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream, NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_ERROR|NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
    ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);
    ngx_conf_merge_size_value(conf->upstream.limit_rate, prev->upstream.limit_rate, 0);
    ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);
    ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);
    ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);
    ngx_conf_merge_value(conf->upstream.socket_keepalive, prev->upstream.socket_keepalive, 0);
    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
    return NGX_CONF_OK;
}


static ngx_int_t ngx_postgres_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *husc) {
    ngx_postgres_upstream_srv_conf_t *pusc = husc->srv_conf ? ngx_http_conf_upstream_srv_conf(husc, ngx_postgres_module) : NULL;
    if (((pusc && pusc->peer.init_upstream) ? pusc->peer.init_upstream : ngx_http_upstream_init_round_robin)(cf, husc) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "peer.init_upstream != NGX_OK"); return NGX_ERROR; }
    if (pusc) pusc->peer.init = husc->peer.init;
    husc->peer.init = ngx_postgres_peer_init;
    if (!pusc) return NGX_OK;
    queue_init(&pusc->data.queue);
    queue_init(&pusc->keep.queue);
    queue_init(&pusc->work.queue);
    ngx_conf_init_msec_value(pusc->data.timeout, 60 * 1000);
    ngx_conf_init_msec_value(pusc->keep.timeout, 60 * 60 * 1000);
    ngx_conf_init_uint_value(pusc->keep.requests, 1000);
    if (!pusc->keep.max) return NGX_OK;
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (!cln) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = ngx_postgres_upstream_srv_conf_cln_handler;
    cln->data = pusc;
    return NGX_OK;
}


static char *ngx_postgres_connect_conf(ngx_conf_t *cf, ngx_command_t *cmd, ngx_postgres_connect_t *connect, ngx_http_upstream_server_t *hus) {
    ngx_str_t *args = cf->args->elts;
    ngx_str_t conninfo = ngx_null_string;
    static const ngx_conf_enum_t e[] = {
        { ngx_string("default"), PQERRORS_DEFAULT },
        { ngx_string("sqlstate"), PQERRORS_SQLSTATE },
        { ngx_string("terse"), PQERRORS_TERSE },
        { ngx_string("verbose"), PQERRORS_VERBOSE },
        { ngx_null_string, 0 }
    };
    connect->verbosity = PQERRORS_DEFAULT;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (hus) {
            if (args[i].len > sizeof("weight=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("weight=") - 1),
                    .data = &args[i].data[sizeof("weight=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"weight\" value \"%V\" must be positive", &cmd->name, &str); return NGX_CONF_ERROR; }
                hus->weight = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("max_conns=") - 1),
                    .data = &args[i].data[sizeof("max_conns=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_conns\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                hus->max_conns = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("max_fails=") - 1),
                    .data = &args[i].data[sizeof("max_fails=") - 1],
                };
                ngx_int_t n = ngx_atoi(str.data, str.len);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"max_fails\" value \"%V\" must be number", &cmd->name, &str); return NGX_CONF_ERROR; }
                hus->max_fails = (ngx_uint_t)n;
                continue;
            }
            if (args[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) {
                ngx_str_t str = {
                    .len = args[i].len - (sizeof("fail_timeout=") - 1),
                    .data = &args[i].data[sizeof("fail_timeout=") - 1],
                };
                ngx_int_t n = ngx_parse_time(&str, 1);
                if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"fail_timeout\" value \"%V\" must be time", &cmd->name, &str); return NGX_CONF_ERROR; }
                hus->fail_timeout = (time_t)n;
                continue;
            }
            if (args[i].len == sizeof("backup") - 1 && !ngx_strncmp(args[i].data, (u_char *)"backup", sizeof("backup") - 1)) {
                hus->backup = 1;
                continue;
            }
            if (args[i].len == sizeof("down") - 1 && !ngx_strncmp(args[i].data, (u_char *)"down", sizeof("down") - 1)) {
                hus->down = 1;
                continue;
            }
#if (T_NGX_HTTP_UPSTREAM_ID)
            if (args[i].len > sizeof("id=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"id=", sizeof("id=") - 1)) {
                hus->id.len = args[i].len - 3;
                hus->id.data = &args[i].data[3];
                continue;
            }
#endif
        }
        if (args[i].len > sizeof("error_verbosity=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"error_verbosity=", sizeof("error_verbosity=") - 1)) {
            ngx_str_t str = {
                .len = args[i].len - (sizeof("error_verbosity=") - 1),
                .data = &args[i].data[sizeof("error_verbosity=") - 1],
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == str.len && !ngx_strncmp(e[j].name.data, str.data, str.len))  break;
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"error_verbosity\" value \"%V\" must be \"default\", \"sqlstate\", \"terse\" or \"verbose\"", &cmd->name, &str); return NGX_CONF_ERROR; }
            connect->verbosity = e[j].value;
            continue;
        }
        if (i > 1) conninfo.len++;
        conninfo.len += args[i].len;
    }
    if (!(conninfo.data = ngx_pnalloc(cf->pool, conninfo.len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); return NGX_CONF_ERROR; }
    u_char *p = conninfo.data;
    for (ngx_uint_t i = 1; i < cf->args->nelts; i++) {
        if (hus) {
            if (args[i].len > sizeof("weight=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"weight=", sizeof("weight=") - 1)) continue;
            if (args[i].len > sizeof("max_conns=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_conns=", sizeof("max_conns=") - 1)) continue;
            if (args[i].len > sizeof("max_fails=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"max_fails=", sizeof("max_fails=") - 1)) continue;
            if (args[i].len > sizeof("fail_timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"fail_timeout=", sizeof("fail_timeout=") - 1)) continue;
            if (args[i].len == sizeof("backup") - 1 && !ngx_strncmp(args[i].data, (u_char *)"backup", sizeof("backup") - 1)) continue;
            if (args[i].len == sizeof("down") - 1 && !ngx_strncmp(args[i].data, (u_char *)"down", sizeof("down") - 1)) continue;
#if (T_NGX_HTTP_UPSTREAM_ID)
            if (args[i].len > sizeof("id=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"id=", sizeof("id=") - 1)) continue;
#endif
        }
        if (args[i].len > sizeof("error_verbosity=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"error_verbosity=", sizeof("error_verbosity=") - 1)) continue;
        if (i > 1) *p++ = ' ';
        p = ngx_copy(p, args[i].data, args[i].len);
    }
    *p = '\0';
    char *err;
    PQconninfoOption *opts = PQconninfoParse((const char *)conninfo.data, &err);
    if (!opts) {
        size_t len;
        if (err && (len = ngx_strlen(err))) {
            err[len - 1] = '\0';
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: %s", &cmd->name, err);
            PQfreemem(err);
            return NGX_CONF_ERROR;
        }
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !PQconninfoParse", &cmd->name);
        return NGX_CONF_ERROR;
    }
    u_char *connect_timeout = NULL;
    u_char *hostaddr = NULL;
    u_char *host = NULL;
    u_char *port = NULL;
    int arg = 0; // hostaddr or host
    arg++; // connect_timeout
    arg++; // fallback_application_name
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"connect_timeout")) { connect_timeout = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue; // !!! discard any fallback_application_name !!!
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) { hostaddr = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host")) { host = (u_char *)opt->val; continue; }
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"port")) port = (u_char *)opt->val; // !!! not continue !!!
        arg++;
    }
    arg++; // last
    if (!connect_timeout) connect->timeout = 60000; else {
        ngx_int_t n = ngx_parse_time(&(ngx_str_t){ngx_strlen(connect_timeout), connect_timeout}, 0);
        if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_parse_time == NGX_ERROR", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        connect->timeout = (ngx_msec_t)n;
    }
    if (hostaddr) {
        connect->url.url.len = ngx_strlen(hostaddr);
        if (!(connect->url.url.data = ngx_pnalloc(cf->pool, connect->url.url.len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(connect->url.url.data, hostaddr, connect->url.url.len + 1);
    } else if (host) {
        connect->url.url.len = ngx_strlen(host);
        if (!(connect->url.url.data = ngx_pnalloc(cf->pool, connect->url.url.len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn(connect->url.url.data, host, connect->url.url.len + 1);
    } else {
        ngx_str_set(&connect->url.url, "unix:///run/postgresql");
        host = connect->url.url.data;
    }
    if (!port) connect->url.default_port = DEF_PGPORT; else {
        ngx_int_t n = ngx_atoi(port, ngx_strlen(port));
        if (n == NGX_ERROR) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_atoi == NGX_ERROR", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        connect->url.default_port = (in_port_t)n;
    }
    if (ngx_parse_url(cf->pool, &connect->url) != NGX_OK) {
        if (connect->url.err) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_parse_url(%V:%i) != NGX_OK and %s", &cmd->name, &connect->url.url, connect->url.default_port, connect->url.err); }
        else { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_parse_url(%V:%i) != NGX_OK", &cmd->name, &connect->url.url, connect->url.default_port); }
        PQconninfoFree(opts);
        return NGX_CONF_ERROR;
    }
    if (hus) {
        hus->addrs = connect->url.addrs;
        hus->naddrs = connect->url.naddrs;
        hus->name = connect->url.url;
    }
    if (host && connect->url.family != AF_UNIX) arg++; // host
    arg++;
    if (!(connect->keywords = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
    if (!(connect->values = ngx_pnalloc(cf->pool, arg * sizeof(const char *)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
    arg = 0; // hostaddr or host
    connect->keywords[arg] = connect->url.family == AF_UNIX ? "host" : "hostaddr";
    connect->values[arg] = (const char *)(connect->url.family == AF_UNIX ? host : hostaddr);
    arg++; // connect_timeout
    connect->keywords[arg] = "connect_timeout";
    if (!connect_timeout) connect->values[arg] = "60"; else {
        size_t val_len = ngx_strlen(connect_timeout);
        if (!(connect->values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->values[arg], (u_char *)connect_timeout, val_len + 1);
    }
    arg++; // fallback_application_name
    connect->keywords[arg] = "fallback_application_name";
    connect->values[arg] = "nginx";
    for (PQconninfoOption *opt = opts; opt->keyword; opt++) {
        if (!opt->val) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"connect_timeout")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"fallback_application_name")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"hostaddr")) continue;
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"host") && connect->url.family == AF_UNIX) continue;
        arg++;
        size_t keyword_len = ngx_strlen(opt->keyword);
        if (!(connect->keywords[arg] = ngx_pnalloc(cf->pool, keyword_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->keywords[arg], (u_char *)opt->keyword, keyword_len + 1);
        size_t val_len = ngx_strlen(opt->val);
        if (!(connect->values[arg] = ngx_pnalloc(cf->pool, val_len + 1))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pnalloc", &cmd->name); PQconninfoFree(opts); return NGX_CONF_ERROR; }
        (void)ngx_cpystrn((u_char *)connect->values[arg], (u_char *)opt->val, val_len + 1);
        if (!ngx_strcasecmp((u_char *)opt->keyword, (u_char *)"client_encoding")) connect->client_encoding = connect->values[arg];
    }
    arg++; // last
    connect->keywords[arg] = NULL;
    connect->values[arg] = NULL;
    PQconninfoFree(opts);
    ngx_pfree(cf->pool, conninfo.data);
    return NGX_CONF_OK;
}


static char *ngx_postgres_server_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_srv_conf_t *husc = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ngx_postgres_upstream_srv_conf_t *pusc = conf;
    pusc->peer.init_upstream = husc->peer.init_upstream;
    husc->peer.init_upstream = ngx_postgres_peer_init_upstream;
    ngx_http_upstream_server_t *hus = ngx_array_push(husc->servers);
    if (!hus) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(hus, sizeof(*hus));
    if (!pusc->connect.nelts && ngx_array_init(&pusc->connect, cf->pool, 1, sizeof(ngx_postgres_connect_t)) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_array_init != NGX_OK"); return NGX_CONF_ERROR; }
    ngx_postgres_connect_t *connect = ngx_array_push(&pusc->connect);
    if (!connect) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_array_push", &cmd->name); return NGX_CONF_ERROR; }
    ngx_memzero(connect, sizeof(*connect));
    hus->fail_timeout = 10;
    hus->max_fails = 1;
    hus->weight = 1;
    return ngx_postgres_connect_conf(cf, cmd, connect, hus);
}


static char *ngx_postgres_keepalive_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_upstream_srv_conf_t *pusc = conf;
    if (pusc->keep.max) return "duplicate";
    ngx_str_t *args = cf->args->elts;
    ngx_int_t n = ngx_atoi(args[1].data, args[1].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be number", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    ngx_http_upstream_srv_conf_t *husc = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    if ((pusc->keep.max = (ngx_uint_t)n) < husc->servers->nelts) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be greater or equal than servers count (%i)", &cmd->name, &args[1], husc->servers->nelts); return NGX_CONF_ERROR; }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (args[i].len > sizeof("overflow=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            args[i].len = args[i].len - (sizeof("overflow=") - 1);
            args[i].data = &args[i].data[sizeof("overflow=") - 1];
            static const ngx_conf_enum_t e[] = {
                { ngx_string("ignore"), 0 },
                { ngx_string("reject"), 1 },
                { ngx_null_string, 0 }
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { pusc->keep.reject = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"overflow\" value \"%V\" must be \"ignore\" or \"reject\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            continue;
        }
        if (args[i].len > sizeof("timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            args[i].len = args[i].len - (sizeof("timeout=") - 1);
            args[i].data = &args[i].data[sizeof("timeout=") - 1];
            n = ngx_parse_time(&args[i], 0);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be time", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            if (n < 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be non-negative", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            pusc->keep.timeout = (ngx_msec_t)n;
            continue;
        }
        if (args[i].len > sizeof("requests=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"requests=", sizeof("requests=") - 1)) {
            args[i].len = args[i].len - (sizeof("requests=") - 1);
            args[i].data = &args[i].data[sizeof("requests=") - 1];
            n = ngx_atoi(args[i].data, args[i].len);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"requests\" value \"%V\" must be number", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            if (n < 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"requests\" value \"%V\" must be non-negative", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            pusc->keep.requests = (ngx_uint_t)n;
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &args[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_queue_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_upstream_srv_conf_t *pusc = conf;
    if (!pusc->keep.max) return "works only with \"postgres_keepalive\"";
    if (pusc->data.max) return "duplicate";
    ngx_str_t *args = cf->args->elts;
    ngx_int_t n = ngx_atoi(args[1].data, args[1].len);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be number", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    pusc->data.max = (ngx_uint_t)n;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (args[i].len > sizeof("overflow=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"overflow=", sizeof("overflow=") - 1)) {
            args[i].len = args[i].len - (sizeof("overflow=") - 1);
            args[i].data = &args[i].data[sizeof("overflow=") - 1];
            static const ngx_conf_enum_t e[] = {
                { ngx_string("ignore"), 0 },
                { ngx_string("reject"), 1 },
                { ngx_null_string, 0 }
            };
            ngx_uint_t j;
            for (j = 0; e[j].name.len; j++) if (e[j].name.len == args[i].len && !ngx_strncmp(e[j].name.data, args[i].data, args[i].len)) { pusc->data.reject = e[j].value; break; }
            if (!e[j].name.len) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"overflow\" value \"%V\" must be \"ignore\" or \"reject\"", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            continue;
        }
        if (args[i].len > sizeof("timeout=") - 1 && !ngx_strncmp(args[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            args[i].len = args[i].len - (sizeof("timeout=") - 1);
            args[i].data = &args[i].data[sizeof("timeout=") - 1];
            n = ngx_parse_time(&args[i], 0);
            if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be time", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"timeout\" value \"%V\" must be positive", &cmd->name, &args[i]); return NGX_CONF_ERROR; }
            pusc->data.timeout = (ngx_msec_t)n;
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: invalid additional parameter \"%V\"", &cmd->name, &args[i]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static char *ngx_postgres_pass_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_loc_conf_t *plc = conf;
    if (plc->upstream.upstream || plc->complex.value.data) return "duplicate";
    ngx_http_core_loc_conf_t *core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core->handler = ngx_postgres_handler;
    if (core->name.data[core->name.len - 1] == '/') core->auto_redirect = 1;
    ngx_url_t url;
    if (cf->args->nelts == 2) {
        ngx_str_t *elts = cf->args->elts;
        ngx_memzero(&url, sizeof(url));
        url.no_resolve = 1;
        url.url = elts[1];
        if (!url.url.len) return "error: empty upstream name";
        if (ngx_http_script_variables_count(&url.url)) {
            ngx_http_compile_complex_value_t ccv = {cf, &url.url, &plc->complex, 0, 0, 0};
            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: ngx_http_compile_complex_value != NGX_OK", &cmd->name); return NGX_CONF_ERROR; }
            return NGX_CONF_OK;
        }
    } else {
        if (!(plc->connect = ngx_pcalloc(cf->pool, sizeof(*plc->connect)))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_pcalloc", &cmd->name); return NGX_CONF_ERROR; }
        if (ngx_postgres_connect_conf(cf, cmd, plc->connect, NULL) == NGX_CONF_ERROR) return NGX_CONF_ERROR;
        url = plc->connect->url;
    }
    if (!(plc->upstream.upstream = ngx_http_upstream_add(cf, &url, 0))) { ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "\"%V\" directive error: !ngx_http_upstream_add", &cmd->name); return NGX_CONF_ERROR; }
    if (cf->args->nelts == 2) return NGX_CONF_OK;
    ngx_http_upstream_srv_conf_t *husc = plc->upstream.upstream;
    husc->peer.init_upstream = ngx_postgres_peer_init_upstream;
    return NGX_CONF_OK;
}


static char *ngx_postgres_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_upstream_srv_conf_t *pusc = conf;
    return ngx_log_set_log(cf, &pusc->keep.log);
}


static char *ngx_postgres_trace_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_upstream_srv_conf_t *pusc = conf;
    return ngx_log_set_log(cf, &pusc->trace.log);
}


static char *ngx_postgres_timeout_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_postgres_loc_conf_t *plc = conf;
    ngx_postgres_query_t *queryelts = plc->query.elts;
    ngx_postgres_query_t *query = plc->query.nelts ? &queryelts[plc->query.nelts - 1] : NULL;
    ngx_str_t *args = cf->args->elts;
    ngx_int_t n = ngx_parse_time(&args[1], 0);
    if (n == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be time", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    if (n <= 0) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"%V\" directive error: \"%V\" must be positive", &cmd->name, &args[1]); return NGX_CONF_ERROR; }
    if (!query) plc->timeout = (ngx_msec_t)n;
    else if (plc->timeout) return "duplicate";
    else if (query->timeout) return "duplicate";
    else query->timeout = (ngx_msec_t)n;
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
    .type = NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_pass_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_query"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_1MORE,
    .set = ngx_postgres_query_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_read_request_body"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, read_request_body),
    .post = NULL },
  { .name = ngx_string("postgres_rewrite"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_2MORE,
    .set = ngx_postgres_rewrite_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("postgres_set"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
    .set = ngx_postgres_set_conf,
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
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.local),
    .post = NULL },
  { .name = ngx_string("postgres_ignore_client_abort"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.ignore_client_abort),
    .post = NULL },
  { .name = ngx_string("postgres_ignore_headers"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_conf_set_bitmask_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.ignore_headers),
    .post = &ngx_http_upstream_ignore_headers_masks },
  { .name = ngx_string("postgres_intercept_errors"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.intercept_errors),
    .post = NULL },
  { .name = ngx_string("postgres_limit_rate"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_size_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.limit_rate),
    .post = NULL },
  { .name = ngx_string("postgres_next_upstream"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    .set = ngx_conf_set_bitmask_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.next_upstream),
    .post = &ngx_postgres_next_upstream_masks },
  { .name = ngx_string("postgres_next_upstream_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.next_upstream_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_next_upstream_tries"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_num_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.next_upstream_tries),
    .post = NULL },
  { .name = ngx_string("postgres_pass_header"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_str_array_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.pass_headers),
    .post = NULL },
  { .name = ngx_string("postgres_read_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.read_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_send_timeout"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    .set = ngx_conf_set_msec_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.send_timeout),
    .post = NULL },
  { .name = ngx_string("postgres_socket_keepalive"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    .set = ngx_conf_set_flag_slot,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(ngx_postgres_loc_conf_t, upstream.socket_keepalive),
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
