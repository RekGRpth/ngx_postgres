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

#ifndef DDEBUG
#define DDEBUG 1
#endif

#include "ngx_postgres_ddebug.h"
#include "ngx_postgres_module.h"
#include "ngx_postgres_rewrite.h"


 int ngx_postgres_find_variables(char *variables[10], char *url, int size) {
   int vars = 0;

   // find variables in redirect url
  
   char *p;
   for (p = url; p < url + size; p++)
     if (*p == ':'/* || *p == '$'*/)
       variables[vars++] = (p + 1);

   return vars;
 }

 char *ngx_postgres_find_values(char *values[10], char *variables[10], int vars, char *columned[10], ngx_postgres_ctx_t *pgctx, int find_error) {


   PGresult *res = pgctx->res;

   ngx_int_t col_count = pgctx->var_cols;
   ngx_int_t row_count = pgctx->var_rows;

   char *error = NULL;
   int error_in_columns = 0;
   int resolved = 0;


   // check if returned columns match variable
   ngx_int_t col;
   for (col = 0; col < col_count; col++) {
     char *col_name = PQfname(res, col);
     ngx_int_t i;
     for (i = 0; i < vars; i++) {
       if (strncmp(variables[i], col_name, strlen(col_name)) == 0) {
         if (!PQgetisnull(res, 0, col)) {
           values[i] = PQgetvalue(res, 0, col);
           columned[i] = values[i];
           resolved++;
           //fprintf(stdout, "Resolved variable [%s] to column %s\n", col_name, values[i]);
         }
       }
     }
     if (find_error) {
       if (*col_name == 'e' && *(col_name+1) == 'r'&& *(col_name+2) == 'r'&& *(col_name+3) == 'o'&& *(col_name+4) == 'r') {
         if (!PQgetisnull(res, 0, col)) {
           error = PQgetvalue(res, 0, col);
         }
         error_in_columns = 1;
       }
     }
   }

   //fprintf(stdout, "Is error in column %d\n", error_in_columns);
   //fprintf(stdout, "Resolved to columns %d\n", resolved);

   int failed = 0;
   if ((find_error && !error_in_columns) || resolved < vars) {
     int current = -1; 
     //fprintf(stdout, "Scanning json %d\n", vars - resolved);

     // find some json in pg results
     ngx_int_t row;
     for (row = 0; row < row_count && !failed; row++) {
       ngx_int_t col;
       for (col = 0; col < col_count && !failed; col++) {
         if (!PQgetisnull(res, row, col)) {
           char *value = PQgetvalue(res, row, col);
           int size = PQgetlength(res, row, col);
           char *p;
           for (p = value; p < value + size; p++) {
             //if not inside string
             if (*p == '"') {
               ngx_int_t i;
               for (i = 0; i < vars; i++) {
                 if (values[i] != NULL) continue;
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
                   if (*n == '\0' || *n == '=' || *n == '&' || *n == '-' || *n == '%' || *n == '/') {
                     if (*(p + (k - s) + 2) != '"') break;
                     //fprintf(stdout, "matched %s %d\n", p + (k - s) + 3, i);

                     values[i] = p + (k - s) + 3; // 2 quotes + 1 ahead
                     // skip space & colon
                     while (*values[i] == ' ' || *values[i] == ':' || *values[i] == '\n') values[i]++;

                     // {"name": "column", "value": "something"}
                     if (*values[i] == ',') {
                       //fprintf(stdout, "SETTING CURRENT %s\n", s);
                       values[i] = NULL;
                       current = i;
                     // {"column": "value"}
                     } else if (current == i) {
                       current = -1;
                     }
                     //fprintf(stdout, "matching %d %s\n %s\n", k - s, s, values[i]);
                   }
                 }
               }
             }


             // find a key that looks like "errors": something
             if (find_error && !error_in_columns && 
                 *p == 'e' && *(p+1) == 'r'&& *(p+2) == 'r'&& *(p+3) == 'o'&& *(p+4) == 'r') {
               char *ch = (p + 5);
               if (*ch == 's')
                 ch++;
               while (*ch == ' ' || *ch == '\t') ch++;
               if (*ch != '"') continue;
               ch++;
               if (*ch != ':') continue;
               ch++;
               while (*ch == ' ' || *ch == '\t') ch++;
               if (*ch == 'n') continue;

               error = ch;

               //fprintf(stdout, "found error: %s\n", p);

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

   char url[256] = "";
   ngx_memzero(url, sizeof(url));

   int written = 0;
   char *p;
   for (p = redirect; p < redirect + size; p++) {

     // substitute nginx variable
     if (*p == '$') {
       ngx_str_t url_variable;

       url_variable.data = (u_char *) p + 1;
       url_variable.len = 0;
       //fprintf(stdout, "something here %s\n", p);
       while(1) {
         u_char *n = url_variable.data + url_variable.len;
         if (*n == '\0' || *n == '=' || *n == '&' || *n == '-' || *n == '%' || *n == '/' || *n == '#' || *n == '?' || *n == ':')
           break;
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
         size_t l;
         for (l = 0; l < capture.len; l++) {
           url[written] = *(capture.data + l);
           written++;
         }
         //fprintf(stdout, "capture %d %s\n", capture.len, url);
       // nginx variables
       } else {
         ngx_uint_t url_variable_hash = ngx_hash_key(url_variable.data, url_variable.len);
         ngx_http_variable_value_t *url_value = ngx_http_get_variable( r, &url_variable, url_variable_hash  );
         ngx_uint_t l;
         for (l = 0; l < url_value->len; l++) {
           url[written] = *(url_value->data + l);
           written++;
         }
         //fprintf(stdout, "variable %s\n", url);
       }
       // skip variable
       while (*p != '\0' && *p != '=' && *p != '&' && *p != '-' && *p != '%' && *p != '/' && *p != '#'&& *p != ':' && *p != '?') {
         p++;
       }
     } else {

       //fprintf(stdout, "SHOULD BE VARIABLE HERE %d %s\n", vars, p);
       ngx_int_t i;
       for (i= 0; i < vars; i++) {
         if (variables[i] == p +1) {
         
           // output value
           if (values[i] != NULL) {
             //fprintf(stdout, "OUTPUT VARIABLE%s\n%s\n", values[i], variables[i]);
             char *n = values[i];
             char *start = values[i];
             if (*n == '"') {
               start++;
               n++;
               // find string boundary
               while (*n != '"' || *(n - 1) == '\\') {
                 n++;
               }
               // output external string
             } else if (columned[i] != NULL) {
               n += strlen(values[i]);
             } else {
               // find unquoted value boundary
               while (*n != ',' && *n != ' ' && *n != '\n' && *n != '}' && *n != ']') {
                 n++;
               }
             }

             int l = n - start;
             int escape = ngx_escape_uri(NULL, (u_char *) start, l, NGX_ESCAPE_URI_COMPONENT);
             ngx_escape_uri((u_char *) (url + written), (u_char *) start, l, NGX_ESCAPE_URI_COMPONENT);
             //fprintf(stdout, "HERE VARIABLE%d\n%s\n", l, url + written);

             written += l + escape * 3;
           }
           // skip variable
           while (*p != '\0' && *p != '=' && *p != '&' && *p != '-' && *p != '%' && *p != '/' && *p != '#' && *p != '?') {
             p++;
           }

         }
       }
     }
     url[written] = *p;
     written++;


   }
   if (written)
     url[written++] = '\0';

   //fprintf(stdout, "HERE COMES URL %s\n", url);
   char *m = ngx_pnalloc(r->pool, written);
   memcpy(m, url, written);

   return m;
 }

ngx_int_t
ngx_postgres_rewrite(ngx_http_request_t *r,
    ngx_postgres_rewrite_conf_t *pgrcf, char *url)
{
    ngx_postgres_rewrite_t  *rewrite;
    ngx_uint_t               i;

    dd("entering");
    //fprintf(stdout, "ngx_postgres_rewrite %s\n", url);

    if (pgrcf->methods_set & r->method) {
        /* method-specific */
        rewrite = pgrcf->methods->elts;
                //fprintf(stdout, "XEDIRECTING OUT %d\n", pgrcf->methods->nelts);
        for (i = 0; i < pgrcf->methods->nelts; i++) {
            if (rewrite[i].key & r->method) {
                char *p = NULL;
                if (url != NULL && strlen(url) > 0)
                  p = url;
                else
                  p = rewrite[i].location;

                char *variables[10];
                char *columned[10];
                char *values[10];


                //fprintf(stdout, "ZEDIRECTING OUT %s %d\n", p, url && strlen(url));
                if (p != NULL) {
                    //fprintf(stdout, "rewrite %s\n", rewrite[i].location);

                    // write template name into $html
                    if (*p != '/' && *p != '.') {
                        ngx_str_t html_variable = ngx_string("html");
                        ngx_uint_t html_variable_hash = ngx_hash_key(html_variable.data, html_variable.len);
                        ngx_http_variable_value_t *raw_html = ngx_http_get_variable( r, &html_variable, html_variable_hash  );
                        
                        int l = strlen(p);
                        raw_html->len = l;
                        raw_html->data = ngx_pnalloc(r->pool, l + 1);
                        memcpy(raw_html->data, p, l);
                        raw_html->data[l] = '\0';
                    // redirect to outside url
                    } else {

                        if (p != url) {
                          int size = strlen(p);
                          int vars = 0;
                          //fprintf(stdout, "formatting url %d\n", size);
                          vars = ngx_postgres_find_variables(variables, p, size);
                          //fprintf(stdout, "formatting url %d\n", vars);

                          ngx_postgres_ctx_t  *pgctx;
                          pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

                          // when interpolating redirect url, also look for errors
                          ngx_postgres_find_values(values, variables, vars, columned, pgctx, 0);
                          p = ngx_postgres_interpolate_url(p, size, variables, vars, columned, values, r);
                        }

                        // redirect out
                        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
                        if (r->headers_out.location == NULL) {
                            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                            return NGX_OK;
                        }

                        int len = strlen(p);
                        char *m = ngx_pnalloc(r->pool, len + 1);
                        int written = 0;

                        // remove leading // and /0/
                        char *c;
                        for (c = p; c < p + len; c++) {
                          if (*c == '/') {
                            if (*(c + 1) == '/')
                              continue;
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

                        //fprintf(stdout, "REDIRECTING OUT %s %d\n", m, written);
                        dd("returning status:%d", (int) rewrite[i].status);
                        return 301;
                    }
                }
                return rewrite[i].status;
            }
        }
    } else if (pgrcf->def) {
        /* default */
        dd("returning status:%d", (int) pgrcf->def->status);
        return pgrcf->def->status;
    }

    dd("returning NGX_DECLINED");
    return NGX_DECLINED;
}

ngx_int_t
ngx_postgres_rewrite_changes(ngx_http_request_t *r,
    ngx_postgres_rewrite_conf_t *pgrcf)
{
    ngx_postgres_ctx_t  *pgctx;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    if ((pgrcf->key % 2 == 0) && (pgctx->var_affected == 0)) {
        /* no_changes */
        dd("returning");
        return ngx_postgres_rewrite(r, pgrcf, NULL);
    }

    if ((pgrcf->key % 2 == 1) && (pgctx->var_affected > 0)) {
        /* changes */
        dd("returning");
        return ngx_postgres_rewrite(r, pgrcf, NULL);
    }

    dd("returning NGX_DECLINED");
    return NGX_DECLINED;
}

ngx_int_t
ngx_postgres_rewrite_rows(ngx_http_request_t *r,
    ngx_postgres_rewrite_conf_t *pgrcf)
{
    ngx_postgres_ctx_t  *pgctx;

    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    if ((pgrcf->key % 2 == 0) && (pgctx->var_rows == 0)) {
        /* no_rows */
        dd("returning");
        return ngx_postgres_rewrite(r, pgrcf, NULL);
    }

    if ((pgrcf->key % 2 == 1) && (pgctx->var_rows > 0)) {
        /* rows */
        dd("returning");
        return ngx_postgres_rewrite(r, pgrcf, NULL);
    }

    dd("returning NGX_DECLINED");
    return NGX_DECLINED;
}

ngx_int_t
ngx_postgres_rewrite_valid(ngx_http_request_t *r,
    ngx_postgres_rewrite_conf_t *pgrcf)
{
    ngx_postgres_ctx_t  *pgctx;
    dd("entering");

    pgctx = ngx_http_get_module_ctx(r, ngx_postgres_module);

    char *redirect = NULL;
    char *variables[10];
    char *columned[10];
    char *values[10];

    ngx_postgres_rewrite_t  *rewrite;
    ngx_uint_t               i;

    for (i = 0; i < 10; i++)
    {
      values[i] = columned[i] = variables[i] = NULL;
    }
    
    // find callback
    if (pgrcf->methods_set & r->method) {
        rewrite = pgrcf->methods->elts;
        for (i = 0; i < pgrcf->methods->nelts; i++)
            if (rewrite[i].key & r->method)
                if (rewrite[i].location && rewrite[i].location[0] != '$') {
                    redirect = rewrite[i].location;
                    break;
                }
    }

    int size = 0;
    int vars = 0;
    if (redirect) {
      size = strlen(redirect);
      vars = ngx_postgres_find_variables(variables, redirect, size);

    }
    // when interpolating redirect url, also look for errors
    char *error = ngx_postgres_find_values(values, variables, vars, columned, pgctx, 1);
    char *url = NULL;
    if (redirect) {
      url = ngx_postgres_interpolate_url(redirect, size, variables, vars, columned, values, r);
    }

    

    //fprintf(stdout, "\nFAILED?: %d\n", failed);

    if ((pgrcf->key % 2 == 0) && error == NULL) {
        /* no_rows */
        dd("returning");
        //fprintf(stdout, "Valid: redirect1%s\n", url);
        return ngx_postgres_rewrite(r, pgrcf, url);
    }

    if ((pgrcf->key % 2 == 1) && error != NULL) {
        /* rows */
        dd("returning");
        //fprintf(stdout, "Invalid: %s\n", url);
        return ngx_postgres_rewrite(r, pgrcf, url);
    }

    dd("returning NGX_DECLINED");
    return NGX_DECLINED;
}
