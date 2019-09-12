/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
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

#include "ngx_postgres_module.h"
#include "ngx_postgres_processor.h"
#include "ngx_postgres_rewrite.h"


static int ngx_postgres_find_variables(char *variables[10], char *url, int size) {
    int vars = 0;
    // find variables in redirect url
    for (char *p = url; p < url + size - 2; p++) if (*p == ':' && *(p + 1) != '/') variables[vars++] = (p + 1);
    return vars;
}


static char *ngx_postgres_find_values(char *values[10], char *variables[10], int vars, char *columned[10], ngx_postgres_ctx_t *pgctx, int find_error) {
    char *error = NULL;
    int error_in_columns = 0;
    int resolved = 0;
    // check if returned columns match variable
    for (ngx_int_t col = 0; col < pgctx->var_cols; col++) {
        char *col_name = PQfname(pgctx->res, col);
        for (ngx_int_t i = 0; i < vars; i++) {
            if (!ngx_strncmp(variables[i], col_name, ngx_strlen(col_name))) {
                if (!PQgetisnull(pgctx->res, 0, col)) {
                    values[i] = PQgetvalue(pgctx->res, 0, col);
                    columned[i] = values[i];
                    resolved++;
                }
            }
        }
        if (find_error && *col_name == 'e' && *(col_name+1) == 'r' && *(col_name+2) == 'r' && *(col_name+3) == 'o' && *(col_name+4) == 'r') {
            if (!PQgetisnull(pgctx->res, 0, col)) error = PQgetvalue(pgctx->res, 0, col);
            error_in_columns = 1;
        }
    }
    int failed = 0;
    if ((find_error && !error_in_columns) || resolved < vars) {
        int current = -1;
        // find some json in pg results
        for (ngx_int_t row = 0; row < pgctx->var_rows && !failed; row++) {
            for (ngx_int_t col = 0; col < pgctx->var_cols && !failed; col++) {
                if (!PQgetisnull(pgctx->res, row, col)) {
                    char *value = PQgetvalue(pgctx->res, row, col);
                    int size = PQgetlength(pgctx->res, row, col);
                    for (char *p = value; p < value + size; p++) {
                        //if not inside string
                        if (*p == '"') {
                            for (ngx_int_t i = 0; i < vars; i++) {
                                if (values[i]) continue;
                                char *s, *k;
                                if (current == i) {
                                    s = "value";
                                    k = "value";
                                } else {
                                    s = variables[i];
                                    k = variables[i];
                                }
                                for (; *k == *(p + (k - s) + 1); k++) {
                                    char *n = k + 1;
                                    if (*n == '\0' || *n == '=' || *n == '&' || *n == '-' || *n == '%' || *n == '/' || *n == '$') {
                                        if (*(p + (k - s) + 2) != '"') break;
                                        values[i] = p + (k - s) + 3; // 2 quotes + 1 ahead
                                        // skip space & colon
                                        while (*values[i] == ' ' || *values[i] == ':' || *values[i] == '\n') values[i]++;
                                        // {"name": "column", "value": "something"}
                                        if (*values[i] == ',') {
                                            values[i] = NULL;
                                            current = i;
                                            // {"column": "value"}
                                        } else if (current == i) {
                                            current = -1;
                                        }
                                    }
                                }
                            }
                        }
                        // find a key that looks like "errors": something
                        if (find_error && !error_in_columns && *p == 'e' && *(p+1) == 'r'&& *(p+2) == 'r'&& *(p+3) == 'o'&& *(p+4) == 'r') {
                            char *ch = (p + 5);
                            if (*ch == 's') ch++;
                            while (*ch == ' ' || *ch == '\t') ch++;
                            if (*ch != '"') continue;
                            ch++;
                            if (*ch != ':') continue;
                            ch++;
                            while (*ch == ' ' || *ch == '\t') ch++;
                            if (*ch == 'n') continue;
                            error = ch;
                            failed = 1;
                        }
                    }
                }
            }
        }
    }
    return error;
}


char *ngx_postgres_interpolate_url(char *redirect, int size, char *variables[10], int vars, char *columned[10], char *values[10], ngx_http_request_t *r) {
    char url[512] = "";
    ngx_memzero(url, 512);
    int written = 0;
    for (char *p = redirect; p < redirect + size; p++) {
        // substitute nginx variable
        if (*p == '$') {
            ngx_str_t url_variable;
            url_variable.data = (u_char *) p + 1;
            url_variable.len = 0;
            while(url_variable.len < (size_t) ((redirect + size) - (p + 1))) {
                u_char *n = url_variable.data + url_variable.len;
                if (*n == '\0' || *n == '=' || *n == '&' || *n == '-' || *n == '%' || *n == '/' || *n == '#' || *n == '?' || *n == ':') break;
                url_variable.len++;
            }
            ngx_int_t num = ngx_atoi(url_variable.data, url_variable.len);
            // captures $1, $2
            if (num != NGX_ERROR && num > 0 && (ngx_uint_t) num <= r->ncaptures) {
                int *cap = r->captures;
                int ncap = num * 2;
                ngx_str_t capture;
                capture.data = r->captures_data + cap[ncap];
                capture.len = cap[ncap + 1] - cap[ncap];
                for (size_t l = 0; l < capture.len; l++) {
                    url[written] = *(capture.data + l);
                    written++;
                }
                // nginx variables
            } else {
                ngx_uint_t url_variable_hash = ngx_hash_key(url_variable.data, url_variable.len);
                ngx_http_variable_value_t *url_value = ngx_http_get_variable( r, &url_variable, url_variable_hash  );
                if (!url_value->not_found) for (ngx_uint_t l = 0; l < url_value->len; l++) {
                    url[written++] = *(url_value->data + l);
                }
            }
            // skip variable
            while (*p != '\0' && *p != '=' && *p != '&' && *p != '-' && *p != '%' && *p != '/' && *p != '#'&& *p != ':' && *p != '?') p++;
        }
        for (ngx_int_t i = 0; i < vars; i++) {
            if (variables[i] == p +1) {
                // output value
                if (values[i]) {
                    char *n = values[i];
                    char *start = values[i];
                    if (*n == '"') {
                        start++;
                        n++;
                        // find string boundary
                        while (*n != '"' || *(n - 1) == '\\') n++;
                        // output external string
                    } else if (columned[i]) {
                        n += strlen(values[i]);
                    } else {
                        // find unquoted value boundary
                        while (*n != ',' && *n != ' ' && *n != '\n' && *n != '}' && *n != ']') n++;
                    }
                    int l = n - start;
                    int escape = ngx_escape_uri(NULL, (u_char *) start, l, NGX_ESCAPE_URI_COMPONENT);
                    ngx_escape_uri((u_char *) (url + written), (u_char *) start, l, NGX_ESCAPE_URI_COMPONENT);
                    written += l + escape * 3;
                }
                // skip variable
                while (*p != '\0' && *p != '=' && *p != '&' && *p != '-' && *p != '%' && *p != '/' && *p != '#' && *p != '?') p++;
                // Special case, ignore slash after variable if url already has query
                if (*p == '/') {
                    int j = 0;
                    for (;j < written; j++) {
                        if (url[j] == '?') {
                            p++;
                            break;
                        }
                    }
                }
                continue;
            }
        }
        url[written] = *p;
        written++;
    }
    if (written) url[written++] = '\0';
    char *m = ngx_pnalloc(r->pool, written); // !!! BUG !!!
    memcpy(m, url, written);
    return m;
}


ngx_int_t ngx_postgres_rewrite(ngx_http_request_t *r, ngx_postgres_rewrite_conf_t *pgrcf, char *url) {
    if (pgrcf->methods_set & r->method) { /* method-specific */
        ngx_postgres_rewrite_t *rewrite = pgrcf->methods.elts;
        for (ngx_uint_t i = 0; i < pgrcf->methods.nelts; i++) {
            if (rewrite[i].methods & r->method) {
                if (rewrite[i].location.len > 0) {
                    // write template name into $html
                    // if location had no slashes and no variables (can't read template file by variable name)
                    if (!ngx_strnstr(rewrite[i].location.data, "$", rewrite[i].location.len) &&
                        !ngx_strnstr(rewrite[i].location.data, ":", rewrite[i].location.len) &&
                        ngx_strnstr(rewrite[i].location.data, ".html", rewrite[i].location.len)) {
                        ngx_str_t html_variable = ngx_string("html");
                        ngx_uint_t html_variable_hash = ngx_hash_key(html_variable.data, html_variable.len);
                        ngx_http_variable_value_t *raw_html = ngx_http_get_variable(r, &html_variable, html_variable_hash);
                        raw_html->len = rewrite[i].location.len;
                        raw_html->data = rewrite[i].location.data;
                        // bad request 400 on errors
                        // if i return 400 here, pg result is lost :( YF: FIXME
                        if (pgrcf->key % 2 == 1 && pgrcf->handler == &ngx_postgres_rewrite_valid) return 200;
                        else return 200;
                        // redirect to outside url
                    } else {
                        // errors/no_errors rewriters already provide interpolated url,
                        // but others need to do it here
                        if (!url) {
                            char *variables[10];
                            char *columned[10];
                            char *values[10];
                            int vars = ngx_postgres_find_variables(variables, (char *) rewrite[i].location.data, rewrite[i].location.len);
                            url = ngx_postgres_interpolate_url((char *) rewrite[i].location.data, rewrite[i].location.len, variables, vars, columned, values, r);
                        }
                        int len = strlen(url);
                        // redirect out
                        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
                        u_char *m = ngx_pnalloc(r->pool, len + 1); // !!! BUG !!!
                        int written = 0;
                        // remove double // and /0/, leave ://
                        for (char *c = url; c < url + len; c++) {
                            if (*c == '/' && (c == url || *(c - 1) != ':')) {
                                if (*(c + 1) == '/') continue;
                                if (*(c + 1) == '0' && *(c + 2) == '/') {
                                    c++;
                                    continue;
                                }
                            }
                            m[written++] = *c;
                        }
                        m[written] = '\0';
                        r->headers_out.location->value.data = (u_char *) m;
                        r->headers_out.location->value.len = written;
                        r->headers_out.location->hash = 1;
                        ngx_str_set(&r->headers_out.location->key, "Location");
                        return 303;
                    }
                }
                return rewrite[i].status;
            }
        }
    } else if (pgrcf->def) {
        /* default */
        return pgrcf->def->status;
    }
    return NGX_DECLINED;
}


ngx_int_t ngx_postgres_rewrite_changes(ngx_http_request_t *r, ngx_postgres_rewrite_conf_t *pgrcf) {
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (pgrcf->key % 2 == 0 && !pgctx->var_affected) return ngx_postgres_rewrite(r, pgrcf, NULL); /* no_changes */
    if (pgrcf->key % 2 == 1 && pgctx->var_affected > 0) return ngx_postgres_rewrite(r, pgrcf, NULL); /* changes */
    return NGX_DECLINED;
}


ngx_int_t ngx_postgres_rewrite_rows(ngx_http_request_t *r, ngx_postgres_rewrite_conf_t *pgrcf) {
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    if (pgrcf->key % 2 == 0 && !pgctx->var_rows) return ngx_postgres_rewrite(r, pgrcf, NULL); /* no_rows */
    if (pgrcf->key % 2 == 1 && pgctx->var_rows > 0) return ngx_postgres_rewrite(r, pgrcf, NULL); /* rows */
    return NGX_DECLINED;
}


ngx_int_t ngx_postgres_rewrite_valid(ngx_http_request_t *r, ngx_postgres_rewrite_conf_t *pgrcf) {
    ngx_postgres_ctx_t *pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);
    ngx_str_t redirect;
    redirect.len = 0;
    char *variables[10];
    char *columned[10];
    char *values[10];
    for (ngx_uint_t i = 0; i < 10; i++) values[i] = columned[i] = variables[i] = NULL;
    // find callback
    if (pgrcf->methods_set & r->method) {
        ngx_postgres_rewrite_t *rewrite = pgrcf->methods.elts;
        for (ngx_uint_t i = 0; i < pgrcf->methods.nelts; i++) if ((rewrite[i].methods & r->method) && rewrite[i].location.len > 0) {
            redirect.data = rewrite[i].location.data;
            redirect.len = rewrite[i].location.len;
            break;
        }
    }
    int vars = 0;
    if (redirect.len > 0) vars = ngx_postgres_find_variables(variables, (char *)redirect.data, redirect.len);
    // when interpolating redirect url, also look for errors
    char *error = ngx_postgres_find_values(values, variables, vars, columned, pgctx, 1);
    char *url = NULL;
    if (redirect.len > 0) url = ngx_postgres_interpolate_url((char *) redirect.data, redirect.len, variables, vars, columned, values, r);
    if ((pgrcf->key % 2 == 0) && !error) return ngx_postgres_rewrite(r, pgrcf, url); /* no_rows */
    if ((pgrcf->key % 2 == 1) && error) return ngx_postgres_rewrite(r, pgrcf, url); /* rows */
    return NGX_DECLINED;
}
