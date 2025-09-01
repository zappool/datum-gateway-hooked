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

#ifndef _DATUM_HOOK_H_
#define _DATUM_HOOK_H_

#include "datum_stratum.h"

int hook_init();

/// @brief Called before work package submit, performs username mapping,
/// from miner username to upstream proxy pool username.
/// @param username_in - Original full miner username
/// @param username_out - Buffer to hold mapped username
/// @param username_out_buflen - Size of username_out buffer
/// @return 0 on success
int submit_hook(
	const char *username_in,
	char* username_out,
	size_t username_out_buflen
);

/// @brief Called at work package submit
/// TODO: Currently called just before submission to upstream pool; should be done after acceptance.
/// @param username_orig - Original full miner username
/// @param username_upstream - Upstream full username (proxypool username + derived worker)
/// @param target_diff - Target difficulty
/// @param job - Job structure
/// @return 0 on success
int accept_hook(
	const char *username_orig,
	const char *username_upstream,
	const uint64_t target_diff,
	const T_DATUM_STRATUM_JOB *job
);

int do_hook_test();

#endif
