/* Shared by the phpredis fuzz harnesses and the selftest: boots an embedded PHP with the
 * extension registered and builds a RedisSock whose "server" is an in-memory stream. */
#ifndef PHPREDIS_HARNESS_COMMON_H
#define PHPREDIS_HARNESS_COMMON_H

#include "php.h"
#include "php_ini.h"
#include "sapi/embed/php_embed.h"
#include "ext/standard/php_var.h"
#include "main/php_streams.h"
#include "zend_exceptions.h"

#include "common.h"
#include "library.h"

extern zend_module_entry redis_module_entry;

static int phpredis_embed_ready;
static zend_function *phpredis_call_fn;
static void (*phpredis_job)(void *);
static void *phpredis_job_arg;

/* Exceptions need a PHP stack frame to be thrown into, so the job runs inside a registered internal
 * function. The job must clear any pending exception itself before it returns. */
ZEND_BEGIN_ARG_INFO_EX(phpredis_job_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

static void zif_phpredis_job(zend_execute_data *execute_data, zval *return_value) {
    phpredis_job(phpredis_job_arg);
}

static void phpredis_run(void (*job)(void *), void *arg) {
    phpredis_job = job;
    phpredis_job_arg = arg;
    zend_call_known_function(phpredis_call_fn, NULL, NULL, NULL, 0, NULL, NULL);
}

static void phpredis_embed_init(void) {
    if (phpredis_embed_ready)
        return;
    /* PHP's own allocator is invisible to ASan; route emalloc to malloc. */
    setenv("USE_ZEND_ALLOC", "0", 1);
    php_embed_module.php_ini_ignore = 1;
    php_embed_module.ini_entries = strdup(
        "display_errors=0\nlog_errors=0\nhtml_errors=0\nerror_reporting=0\n"
        "memory_limit=-1\nzend.assertions=-1\nimplicit_flush=1\n");
    char *argv[] = {(char *)"phpredis-harness", NULL};
    if (php_embed_init(1, argv) == FAILURE)
        abort();
    if (zend_startup_module(&redis_module_entry) == FAILURE)
        abort();
    static const zend_function_entry fe[] = {
        {"phpredis_job", zif_phpredis_job, phpredis_job_arginfo + 1, 0, 0},
        {NULL, NULL, NULL, 0, 0},
    };
    if (zend_register_functions(NULL, fe, NULL, MODULE_PERSISTENT) == FAILURE)
        abort();
    phpredis_call_fn = zend_hash_str_find_ptr(CG(function_table), "phpredis_job",
                                              sizeof("phpredis_job") - 1);
    if (!phpredis_call_fn)
        abort();
    phpredis_embed_ready = 1;
}

static RedisSock *phpredis_sock_from_bytes(const uint8_t *data, size_t size) {
    RedisSock *sock = redis_sock_create("fuzz.invalid", 12, 6379, 1.0, 1.0, 0, NULL, 0);
    sock->max_retries = 0;
    sock->stream = php_stream_memory_create(TEMP_STREAM_DEFAULT);
    if (size > 0)
        php_stream_write(sock->stream, (const char *)data, size);
    php_stream_seek(sock->stream, 0, SEEK_SET);
    sock->status = REDIS_SOCK_STATUS_READY;
    return sock;
}

static void phpredis_sock_destroy(RedisSock *sock) {
    redis_sock_disconnect(sock, 1, 1);
    redis_free_socket(sock);
    if (EG(exception))
        zend_clear_exception();
}

#endif
