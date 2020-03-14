#ifndef _NGX_POSTGRES_VARIABLE_H_
#define _NGX_POSTGRES_VARIABLE_H_

#include <ngx_http.h>

char *ngx_postgres_set_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_postgres_variable_add(ngx_conf_t *cf);
ngx_int_t ngx_postgres_variable_set(ngx_http_request_t *r);

#endif /* _NGX_POSTGRES_VARIABLE_H_ */
