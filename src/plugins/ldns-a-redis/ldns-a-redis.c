#include <dnscrypt/plugin.h>

#include <limits.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ldns/ldns.h>

#include "config.h"

DCPLUGIN_MAIN(__FILE__);

#include <hiredis.h>

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
static int redis_port = 3879;

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

redisContext * redis = NULL;

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "s:h:p:")) != -1) {
		switch (opt) {
			case 's':
				redis_sock = strdup(optarg);
				break;
			case 'h':
				redis_host = strdup(optarg);
				break;
			case 'p':
				redis_port = strtoul(optarg, NULL, 10);
				if (redis_port == ULONG_MAX) {
					fprintf(stderr, "invalid redis port %s", optarg);
					return -1;
				}
				break;
			default:
				break;
		}
	}

	if (redis_host) {
		redis = redisConnect(redis_host, redis_port);
	} else {
		redis = redisConnectUnix(redis_sock);
	}
	if (redis == NULL) {
		fprintf(stderr, "connect to redis failed: %s\n", strerror(errno));
		return -1;
	}

	redisEnableKeepAlive(redis);
    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
	if (redis) {
		redisFree(redis);
	}
    return 0;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
	int i, j;
    char *domain_name = NULL;
	void *reply = NULL;
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

    fprintf(stdout, "Q: %s\n", domain_name);

    list = ldns_pkt_answer (resp);

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
				redisAppendCommand(redis, "sadd %s %s", domain_name, ipaddr);
                free(ipaddr);
            }
        }
    }

	redisGetReply(redis, &reply);
	/* TODO: parse results and free memory */
	freeReplyObject(reply);

	redisCommand(redis, "publish DNAME:%s", domain_name);
	redisGetReply(redis, &reply);
	/* TODO: parse results and free memory */
	freeReplyObject(reply);

packet_end:
    if (domain_name)
        free(domain_name);

    ldns_pkt_free(resp);

    return DCP_SYNC_FILTER_RESULT_OK;
}
/* vim: set ts=4 sw=4 et: */
