// IDEA:
// 1. Create packet with GO implementation. Try to parse and validate it with LF
// SPAO implementation.
// 2. Create packet with LF and try to parse it with GO implementation.

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include "../drkey.h"
#include "scion_spao/spao.h"

#define LF_TEST_NO_RCU 1

volatile bool lf_force_quit = false;

void
print_pkt(uint8_t expected[128])
{
	printf("GO SPAO Packet: \n");
	for (int i = 0; i < 32; i++) {
		for (int j = 0; j < 4; j++) {
			printf("%02hhx", expected[i * 4 + j]);
		}
		printf("\n");
	}
	printf("\n");
}


int
test1()
{
	const uint8_t zero_key[LF_CRYPTO_DRKEY_SIZE] = { 0 };
	uint8_t output_buffer[128];

	int res = (int)CreateSpaoPacket((uint64_t)0, (void *)zero_key,
			(void *)output_buffer);
	print_pkt(output_buffer);
	return res;
}

int
main(int argc, char *argv[])
{
	int res = rte_eal_init(argc, argv);
	if (res < 0) {
		return -1;
	}
	int error_counter = 0;

	error_counter += test1();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}