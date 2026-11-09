/* Feeds attacker-controlled bytes to phpredis's reply parsers as if they were a Redis server's
 * answer. Input: [handler][flags][reply bytes...]. */
#include "harness_common.h"

typedef int (*reply_fn)(INTERNAL_FUNCTION_PARAMETERS, RedisSock *, zval *, RedisCmdCtx);

typedef struct {
    reply_fn fn;
    RedisCtxMode mode;
} handler_t;

#define H(f) {f, REDIS_CTX_DEFAULT}
#define HM(f, m) {f, m}

/* A handler is listed once per ctx mode its command can pass it; modes outside that set are
 * unreachable by construction in the extension (ZEND_UNREACHABLE), so they are not fed. */
static const handler_t handlers[] = {
    H(redis_1_response), H(redis_long_response), H(redis_boolean_response),
    H(redis_bulk_double_response), H(redis_string_response), H(redis_bulk_withmeta_response),
    H(redis_ping_response), H(redis_info_response),
    HM(redis_config_response, REDIS_CTX_BOOL), HM(redis_config_response, REDIS_CTX_ZIPPED_RAW),
    H(redis_zrange_response), HM(redis_zrange_response, REDIS_CTX_WITHSCORES),
    H(redis_type_response), H(redis_sock_read_multibulk_reply), H(redis_mbulk_reply_raw),
    H(redis_mbulk_reply_zipped_raw), H(redis_mbulk_reply_zipped_vals),
    H(redis_mbulk_reply_zipped_keys_int), H(redis_mbulk_reply_zipped_keys_dbl),
    H(redis_mbulk_reply_assoc), H(redis_mbulk_reply_double), H(redis_xrange_reply),
    H(redis_xread_reply), H(redis_xclaim_reply), HM(redis_xclaim_reply, REDIS_CTX_XAUTOCLAIM),
    H(redis_xinfo_reply), H(redis_vinfo_reply), H(redis_vemb_reply),
    H(redis_vlinks_reply), HM(redis_vlinks_reply, REDIS_CTX_WITHSCORES),
    H(redis_vgetattr_reply), HM(redis_vgetattr_reply, REDIS_CTX_DECODE_JSON),
    HM(redis_acl_response, REDIS_CTX_VARIANT), HM(redis_acl_response, REDIS_CTX_BOOL),
    HM(redis_acl_response, REDIS_CTX_STRING), HM(redis_acl_response, REDIS_CTX_LONG),
    HM(redis_acl_response, REDIS_CTX_ACL_GETUSER), HM(redis_acl_response, REDIS_CTX_ACL_LOG),
    H(redis_acl_getuser_reply), H(redis_acl_log_reply),
    H(redis_read_variant_reply), H(redis_read_raw_variant_reply),
    H(redis_read_variant_reply_strings), H(redis_client_list_reply),
    H(redis_client_trackinginfo_reply), H(redis_client_info_reply),
    HM(redis_client_response, REDIS_CTX_CLIENT_INFO), HM(redis_client_response, REDIS_CTX_CLIENT_LIST),
    HM(redis_client_response, REDIS_CTX_BOOL), HM(redis_client_response, REDIS_CTX_LONG),
    HM(redis_client_response, REDIS_CTX_STRING), HM(redis_client_response, REDIS_CTX_CLIENT_TRACKINGINFO),
    H(redis_zadd_response), HM(redis_zadd_response, REDIS_CTX_INCR),
    HM(redis_zrandmember_response, REDIS_CTX_STRING), HM(redis_zrandmember_response, REDIS_CTX_COUNT),
    HM(redis_zrandmember_response, REDIS_CTX_WITHSCORES),
    H(redis_zdiff_response), HM(redis_zdiff_response, REDIS_CTX_WITHSCORES),
    H(redis_set_response), HM(redis_set_response, REDIS_CTX_STRING),
    H(redis_geosearch_response), HM(redis_geosearch_response, REDIS_CTX_GEO_WITHMETA),
    HM(redis_hrandfield_response, REDIS_CTX_STRING), HM(redis_hrandfield_response, REDIS_CTX_COUNT),
    HM(redis_hrandfield_response, REDIS_CTX_WITHVALUES),
    H(redis_pop_response), HM(redis_pop_response, REDIS_CTX_COUNT),
    H(redis_randmember_response), HM(redis_randmember_response, REDIS_CTX_COUNT),
    H(redis_lpos_response), HM(redis_lpos_response, REDIS_CTX_COUNT),
    HM(redis_object_response, REDIS_CTX_LONG), HM(redis_object_response, REDIS_CTX_STRING),
    H(redis_himport_response), HM(redis_himport_response, REDIS_CTX_LONG),
    HM(redis_function_response, REDIS_CTX_BOOL), HM(redis_function_response, REDIS_CTX_STRING),
    HM(redis_function_response, REDIS_CTX_FUNCTION), H(redis_function_reply),
    HM(redis_command_response, REDIS_CTX_COMMAND_INFO), HM(redis_command_response, REDIS_CTX_LONG),
    HM(redis_command_response, REDIS_CTX_MULTIBULK_RAW),
    HM(redis_command_response, REDIS_CTX_VARIANT_STRINGS), H(redis_command_info_reply),
    HM(redis_pubsub_response, REDIS_CTX_LONG), HM(redis_pubsub_response, REDIS_CTX_VARIANT),
    HM(redis_pubsub_response, REDIS_CTX_ZIPPED_INT),
    H(redis_select_response), H(redis_hello_server_response), H(redis_hello_version_response),
    H(redis_mpop_response), HM(redis_mpop_response, REDIS_CTX_WITHSCORES),
};
#define NHANDLERS (sizeof(handlers) / sizeof(handlers[0]))
#define NSCAN 4

static const int compressions[] = {REDIS_COMPRESSION_NONE, REDIS_COMPRESSION_LZF,
                                   REDIS_COMPRESSION_ZSTD, REDIS_COMPRESSION_LZ4};

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    phpredis_embed_init();
    return 0;
}

typedef struct {
    const uint8_t *data;
    size_t size;
} input_t;

static void run(void *arg) {
    const uint8_t *data = ((input_t *)arg)->data;
    const size_t size = ((input_t *)arg)->size;
    const unsigned sel = data[0] % (NHANDLERS + NSCAN);
    const uint8_t flags = data[1];

    RedisSock *sock = phpredis_sock_from_bytes(data + 2, size - 2);
    sock->reply_literal = flags & 1;
    sock->null_mbulk_as_null = (flags >> 1) & 1;
    sock->compression = compressions[(flags >> 2) & 3];
    sock->pack_ignore_numbers = (flags >> 4) & 1;

    zval rv;
    ZVAL_UNDEF(&rv);
    if (sel < NHANDLERS) {
        RedisCmdCtx ctx = redis_empty_ctx;
        ctx.mode = handlers[sel].mode;
        /* HMGET pairs the reply with the requested keys, passed as a HashTable in the ctx. */
        HashTable *keys = NULL;
        if (handlers[sel].fn == redis_mbulk_reply_assoc) {
            keys = zend_new_array(0);
            for (unsigned i = 0; i < (flags >> 5); i++)
                { zval zk; ZVAL_STRING(&zk, "k"); zend_hash_next_index_insert(keys, &zk); };
            ctx.ptr = keys;
        }
        handlers[sel].fn(NULL, &rv, sock, NULL, ctx);
        if (keys) {
            zend_array_release(keys);
        }
    } else {
        uint64_t cursor = 0;
        redis_sock_read_scan_reply(NULL, &rv, sock, (REDIS_SCAN_TYPE)(sel - NHANDLERS), &cursor);
    }
    zval_ptr_dtor(&rv);
    phpredis_sock_destroy(sock);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return -1;
    input_t in = {data, size};
    phpredis_run(run, &in);
    return 0;
}
