/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdatomic.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "config.h"
#include "duplicate_filter.h"
#include "lf.h"
#include "lib/log/log.h"
#include "lib/utils/packet.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"
#include "statistics.h"
#include "worker.h"

/**
 * This file is missing the packet parsing, the processing pipeline for incoming
 * and outoing LF packets. These functionalities are provided either by
 * worker_checks.c and worker_scion.c/worker_ip.c.
 */

#ifndef LF_OFFLOAD_CKSUM
#define LF_OFFLOAD_CKSUM 0
#endif

int
lf_worker_init(bool worker_lcores[RTE_MAX_LCORE],
		struct lf_worker_context worker_contexts[RTE_MAX_LCORE])
{
	uint16_t lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!worker_lcores[lcore_id]) {
			continue;
		}
		memset(&worker_contexts[lcore_id], 0, sizeof(struct lf_worker_context));
		worker_contexts[lcore_id].lcore_id = lcore_id;
	}

	return 0;
}

void
lf_worker_pkt_mod(struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr,
		void *l3_hdr, const struct lf_config_pkt_mod *pkt_mod)
{
	uint8_t tmp[RTE_ETHER_ADDR_LEN];

	if (ether_hdr != NULL && pkt_mod->ether_switch) {
		/* switch destination and source Ethernet address */
		(void)rte_memcpy(&tmp, &(ether_hdr->dst_addr), RTE_ETHER_ADDR_LEN);
		(void)rte_memcpy(&(ether_hdr->dst_addr), &(ether_hdr->src_addr),
				RTE_ETHER_ADDR_LEN);
	} else if (ether_hdr != NULL && pkt_mod->ether_option) {
		/* set destination Ethernet address*/
		(void)rte_memcpy(&(ether_hdr->dst_addr), pkt_mod->ether,
				RTE_ETHER_ADDR_LEN);
	}

#if LF_IPV6
	struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;
	if (ipv6_hdr != NULL) {
		if (pkt_mod->ip_option) {
			memcpy(ipv6_hdr->dst_addr, pkt_mod->ipv6, sizeof(pkt_mod->ipv6));
		}
		(void)lf_pktv6_set_cksum(m, ether_hdr, ipv6_hdr, LF_OFFLOAD_CKSUM);
	}
#else
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
	if (ipv4_hdr != NULL) {
		if (pkt_mod->ip_option) {
			ipv4_hdr->dst_addr = pkt_mod->ip;
		} else {
			size_t i, n;
			i = 0,
			n = sizeof pkt_mod->ip_src_map / sizeof pkt_mod->ip_src_map[0];
			while (i != n &&
					pkt_mod->ip_src_map[i].from != ipv4_hdr->src_addr &&
					(pkt_mod->ip_src_map[i].from != 0 ||
							pkt_mod->ip_src_map[i].to == 0)) {
				i++;
			}
			if (i != n) {
				LF_WORKER_LOG_DP(DEBUG, "Src IP: " PRIIP " -> " PRIIP "\n",
						PRIIP_VAL(ipv4_hdr->src_addr),
						PRIIP_VAL(pkt_mod->ip_src_map[i].to));
				ipv4_hdr->src_addr = pkt_mod->ip_src_map[i].to;
			}
			i = 0,
			n = sizeof pkt_mod->ip_dst_map / sizeof pkt_mod->ip_dst_map[0];
			while (i != n &&
					pkt_mod->ip_dst_map[i].from != ipv4_hdr->dst_addr &&
					(pkt_mod->ip_dst_map[i].from != 0 ||
							pkt_mod->ip_dst_map[i].to == 0)) {
				i++;
			}
			if (i != n) {
				LF_WORKER_LOG_DP(DEBUG, "Dst IP: " PRIIP " -> " PRIIP "\n",
						PRIIP_VAL(ipv4_hdr->dst_addr),
						PRIIP_VAL(pkt_mod->ip_dst_map[i].to));
				ipv4_hdr->dst_addr = pkt_mod->ip_dst_map[i].to;
			}
		}
		(void)lf_pkt_set_cksum(m, ether_hdr, ipv4_hdr, LF_OFFLOAD_CKSUM);
	}
#endif /* LF_IPV6 */
}

static void
update_pkt_statistics(struct lf_statistics_worker *stats, struct rte_mbuf *pkt,
		enum lf_pkt_action pkt_action)
{
	lf_statistics_worker_counter_add(stats, rx_bytes, pkt->pkt_len);
	lf_statistics_worker_counter_add(stats, rx_pkts, 1);

	switch (pkt_action) {
	case LF_PKT_UNKNOWN_DROP:
		lf_statistics_worker_counter_inc(stats, unknown_drop);
		break;
	case LF_PKT_UNKNOWN_FORWARD:
		lf_statistics_worker_counter_inc(stats, unknown_forward);
		break;
	case LF_PKT_OUTBOUND_DROP:
		lf_statistics_worker_counter_inc(stats, outbound_drop);
		break;
	case LF_PKT_OUTBOUND_FORWARD:
		lf_statistics_worker_counter_inc(stats, outbound_forward);
		break;
	case LF_PKT_INBOUND_DROP:
		lf_statistics_worker_counter_inc(stats, inbound_drop);
		break;
	case LF_PKT_INBOUND_FORWARD:
		lf_statistics_worker_counter_inc(stats, inbound_forward);
		break;
	default:
		break;
	}
}

static void
set_pkt_action(struct rte_mbuf *pkt, enum lf_pkt_action pkt_action)
{
	switch (pkt_action) {
	case LF_PKT_UNKNOWN_DROP:
	case LF_PKT_INBOUND_DROP:
	case LF_PKT_OUTBOUND_DROP:
		*lf_pkt_action(pkt) = LF_DISTRIBUTOR_ACTION_DROP;
		break;
	case LF_PKT_UNKNOWN_FORWARD:
	case LF_PKT_OUTBOUND_FORWARD:
	case LF_PKT_INBOUND_FORWARD:
		*lf_pkt_action(pkt) = LF_DISTRIBUTOR_ACTION_FORWARD;
		break;
	default:
		*lf_pkt_action(pkt) = LF_DISTRIBUTOR_ACTION_DROP;
		LF_WORKER_LOG_DP(ERR, "Unknown packet action (%u)\n", pkt_action);
		break;
	}
}

/* main processing loop */
static void
lf_worker_main_loop(struct lf_worker_context *worker_context)
{
	unsigned int i;
	uint16_t nb_rx;

	/* packet buffers */
	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	enum lf_pkt_action pkt_res[LF_MAX_PKT_BURST];

	/* worker constants */
	struct rte_rcu_qsbr *qsv = worker_context->qsv;
	struct lf_time_worker *time = &worker_context->time;
	struct lf_statistics_worker *stats = worker_context->statistics;

	LF_WORKER_LOG_DP(INFO, "enter main loop\n");
	while (likely(!lf_force_quit)) {
		/*
		 * Update Quiescent State
		 * This indicates that the worker does not reference memory shared with
		 * services, such as the key manager or ratelimiter, at this moment.
		 */
		(void)rte_rcu_qsbr_quiescent(qsv, worker_context->qsv_id);

		/*
		 * Update current time
		 * A worker keeps its own nanosecond timestamp, caches it and regularly
		 * updates it.
		 */
		(void)lf_time_worker_update(time);
		nb_rx = lf_distributor_worker_rx(&worker_context->distributor, worker_context->mirror_ctx, rx_pkts);

		if (unlikely(nb_rx <= 0)) {
			continue;
		}

		(void)lf_statistics_worker_add_burst(stats, nb_rx);

		for (i = 0; i < nb_rx; ++i) {
			pkt_res[i] = LF_PKT_UNKNOWN;
			pkt_res[i] = lf_plugins_pre(worker_context, rx_pkts[i], pkt_res[i]);
		}

		lf_worker_handle_pkt(worker_context, rx_pkts, nb_rx, pkt_res);

		for (i = 0; i < nb_rx; ++i) {
			pkt_res[i] =
					lf_plugins_post(worker_context, rx_pkts[i], pkt_res[i]);
		}

		for (i = 0; i < nb_rx; ++i) {
			update_pkt_statistics(stats, rx_pkts[i], pkt_res[i]);
			set_pkt_action(rx_pkts[i], pkt_res[i]);
		}

		lf_distributor_worker_tx(&worker_context->distributor, rx_pkts, nb_rx);
	}
}

int
lf_worker_run(struct lf_worker_context *worker_context)
{
	int res;
	LF_WORKER_LOG_DP(DEBUG, "run\n");

	/* register and start reporting quiescent state */
	res = rte_rcu_qsbr_thread_register(worker_context->qsv,
			worker_context->qsv_id);
	if (res != 0) {
		LF_WORKER_LOG_DP(ERR,
				"Register for QS Variable failed. gsv: %p, qsv_id: %u\n",
				worker_context->qsv, worker_context->qsv_id);
		return -1;
	}
	(void)rte_rcu_qsbr_thread_online(worker_context->qsv,
			worker_context->qsv_id);

	(void)lf_worker_main_loop(worker_context);

	/* stop reporting quiescent state and unregister */
	(void)rte_rcu_qsbr_thread_offline(worker_context->qsv,
			worker_context->qsv_id);
	(void)rte_rcu_qsbr_thread_unregister(worker_context->qsv,
			worker_context->qsv_id);

	LF_WORKER_LOG_DP(DEBUG, "terminate\n");
	return 0;
}
