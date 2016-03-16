#include <dnscrypt/plugin.h>

#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ldns/ldns.h>
#include <hiredis.h>

#include "config.h"
#include "../../proxy/logger.h"

DCPLUGIN_MAIN(__FILE__);

/*
typedef enum {POLICY_UNKNOWN, POLICY_DEFAULT, POLICY_DIRECT, POLICY_PROXY, POLICY_BLOCK} policy_type_t;

struct plugin_priv_data {
    FILE *fp;
#ifdef USE_MYSQL
    MYSQL mysql;
    int connected;
#endif
#ifdef USE_MEMCACHED
    memcached_st *memc;
#endif
} _priv_data;
*/

#define REDIS_SOCK "/var/run/redis/redis.sock" 

static const char *redis_sock = REDIS_SOCK;
static const char *redis_host = NULL;
static int redis_port = 6379;

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Log DNS A Records to redis";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "Log client queries\n"
        "\n"
        "This plugin logs the client queries to the standard output (default)\n"
        "or to a file.\n"
        "\n"
        "  # dnscrypt-proxy --plugin libdcplugin_ldns_a_redis[,-s,/var/run/redis/redis.sock|,-h,redis_ip,-p,redis_port]";
}

#if 0
int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    return 0;
}
#endif
static redisContext * redis = NULL;

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
	int opt;

    fprintf(stderr, "dcplugin_init\n");

    optind = 1;

	while ((opt = getopt(argc, argv, "s:h:p:")) != -1) {
		switch (opt) {
			case 's':
                fprintf(stderr, "redis socket %s\n", optarg);
				redis_sock = strdup(optarg);
				break;
			case 'h':
                fprintf(stderr, "redis host %s\n", optarg);
				redis_host = strdup(optarg);
				break;
			case 'p':
                fprintf(stderr, "redis port %s\n", optarg);
				redis_port = strtoul(optarg, NULL, 10);
				if (redis_port == ULONG_MAX) {
					fprintf(stderr, "invalid redis port %s", optarg);
					return -1;
				}
				break;
			default:
                fprintf(stderr, "valid params: [-h host -p port ] | [-s socket]\n");
                return -1;
		}
	}

	if (redis_host) {
        fprintf(stderr, "connect to %s, port %d\n", redis_host, redis_port);
		redis = redisConnect(redis_host, redis_port);
	} else {
        fprintf(stderr, "connect to %s\n", redis_sock);
		redis = redisConnectUnix(redis_sock);
	}

    if (redis->err) {
        fprintf(stderr, "Connection error: %s\n", redis->errstr);
		return -1;
    }

	//redisEnableKeepAlive(redis);
    return 0;
}

#if 0
DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    return DCP_SYNC_FILTER_RESULT_OK;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    return 0;
}

#else
int
dcplugin_destroy(DCPlugin * const dcplugin)
{
	if (redis) {
		redisFree(redis);
	}
    return 0;
}

static void
_redisPrintReply(FILE *fp, const char *prefix, const redisReply *reply)
{
    switch (reply->type) {
        case REDIS_REPLY_STRING:
            fprintf(fp, "%sS:%s\n", prefix, reply->str);
            break;
        case REDIS_REPLY_ARRAY:
            {
                int j;
                char buf[1024];

                fprintf(fp, "%sARRAY:\n", prefix);
                snprintf(buf, sizeof(buf), "%s%s", prefix,prefix);
                for (j = 0; j < reply->elements; j++) {
                    _redisPrintReply(fp, buf, reply->element[j]);
                }
            }
            break;
        case REDIS_REPLY_INTEGER:
            fprintf(fp, "%sINT:%lld\n", prefix, reply->integer);
            break;
        case REDIS_REPLY_NIL:
            fprintf(fp, "%sNIL\n", prefix);
            break;
        case REDIS_REPLY_STATUS:
            fprintf(fp, "%sST:%s\n", prefix, reply->str);
            break;
        case REDIS_REPLY_ERROR:
            fprintf(fp, "%sERR:%s\n", prefix, reply->str);
            break;
    }
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
	int i, j, commands;
    char *domain_name = NULL;
	redisReply *reply = NULL;
    //struct plugin_priv_data *priv = dcplugin_get_user_data(dcplugin);

    ldns_pkt *resp = NULL;

    ldns_rr_list *list;
    uint8_t  *wire_data = dcplugin_get_wire_data(dcp_packet);
    size_t   wire_data_len = dcplugin_get_wire_data_len(dcp_packet);
    

    if (LDNS_RCODE_WIRE(wire_data) != LDNS_RCODE_NOERROR) {
        return DCP_SYNC_FILTER_RESULT_OK;
    }

    if (ldns_wire2pkt(&resp, wire_data, dcplugin_get_wire_data_len(dcp_packet)) != LDNS_STATUS_OK)
        return DCP_SYNC_FILTER_RESULT_OK;

    list = ldns_pkt_question(resp);

    if (ldns_rr_list_rr_count(list) != 1)
        goto packet_end;

    ldns_rr * rr = ldns_rr_list_rr(list, 0);
    ldns_rr_class klz = ldns_rr_get_class(rr);
    ldns_rr_type type = ldns_rr_get_type(rr);

    if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
        goto packet_end;
    }

    domain_name = ldns_rdf2str(ldns_rr_owner(rr));

    fprintf(stderr, "Q: %s\n", domain_name);

    list = ldns_pkt_answer (resp);

    commands = 0;
    for (i = 0; list && i < ldns_rr_list_rr_count(list); i++) {
        ldns_rr * rr = ldns_rr_list_rr(list, i);
        ldns_rr_class klz = ldns_rr_get_class(rr);
        ldns_rr_type type = ldns_rr_get_type(rr);

        if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
            continue;
        } 

        for (j = 0; j < ldns_rr_rd_count(rr); j++) {
            ldns_rdf *rdf = ldns_rr_rdf(rr, j);
            int rdf_sz = ldns_rdf_size(rdf);

            ldns_rdf_type rdf_type = ldns_rdf_get_type(rdf);

            if (rdf_type == LDNS_RDF_TYPE_A) {
                char *ipaddr = ldns_rdf2str(rdf);
                fprintf(stderr, "sadd %s %s\n", domain_name, ipaddr);
				redisAppendCommand(redis, "sadd %s %s", domain_name, ipaddr);
                commands++;
                free(ipaddr);
            }
        }
    }

    fprintf(stderr, "get reply 1\n");
    while (commands--) {
        redisGetReply(redis, (void **)&reply);
	/* TODO: parse results and free memory */
        if (reply) {
            _redisPrintReply(stderr, "  ", reply);
            freeReplyObject(reply);
        }
    }

    fprintf(stderr,  "PUBLISH DNAME %s\n", domain_name);
	reply = redisCommand(redis, "PUBLISH DNAME %s", domain_name);
	/* TODO: parse results and free memory */

#if 1
    _redisPrintReply(stderr, "  ", reply);
    freeReplyObject(reply);
#else
    fprintf(stderr, "reply type %d\n", reply->type);
    if (reply->type == REDIS_REPLY_ARRAY) {
        int j;
        for (j = 0; j < reply->elements; j++) {
            fprintf(stderr, "%u) %s\n", j, reply->element[j]->str);
        }
    } else if ({
        fprintf(stderr, " %s\n", reply->str);
    }

	if (reply) {
        freeReplyObject(reply);
        reply = NULL;
    }
#endif

packet_end:
    if (domain_name)
        free(domain_name);

    ldns_pkt_free(resp);

    return DCP_SYNC_FILTER_RESULT_OK;
}
#endif

/* vim: set ts=4 sw=4 et: */
