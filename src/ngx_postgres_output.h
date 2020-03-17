#ifndef _NGX_POSTGRES_OUTPUT_H_
#define _NGX_POSTGRES_OUTPUT_H_

#include <ngx_http.h>

char *ngx_postgres_output_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void ngx_postgres_output_chain(ngx_http_request_t *r);
void ngx_postgres_output_error(ngx_http_request_t *r);

#endif /* _NGX_POSTGRES_OUTPUT_H_ */
