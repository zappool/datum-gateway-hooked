/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

// This is quick and dirty for now.  Will be improved over time.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>
#include <jansson.h>

#include "datum_hook.h"

int hook_init() {
}

int submit_hook(
	const char *username_in,
	char* username_out,
	size_t username_out_buflen
) {
	strncpy(username_out, username_in, username_out_buflen);
	printf("datum_hook: submit_hook user_in: '%s' user_out: '%s' \n", username_in, username_out);
	return 0;
}

int accept_hook(
	const char *username,
	const uint64_t target_diff,
	const T_DATUM_STRATUM_JOB *job
) {
	printf("datum_hook: accept_hook user '%s'  tdiff %ld \n", username, target_diff);

	return 0;
}

int do_hook_test() {
	// uint64_t a = 3, b = 5, c = 0;
	// c = mh_add(3, 5);
	// printf("ADD %ld + %ld = %ld\n", a, b, c);

	const char* user1 = "User1";

	const uint32_t buflen = 100;
	char user2[buflen];

	submit_hook(user1, user2, buflen);
	printf("do_hook_test: user after submit: '%s'\n", user2);

	accept_hook(user2, 1000, NULL);

	return 0;
}
