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

// #include <assert.h>
// #include <limits.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <microhttpd.h>
// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <pthread.h>
// #include <inttypes.h>
// #include <jansson.h>

#include "datum_hook.h"

#include "datum_conf.h"
#include "datum_utils.h"

#include <string.h>
#include <curl/curl.h>


#define WORKER_HASH_LEN 8

// Size for http response write buffer
#define HTTP_RESPONSE_BUFFER_SIZE 10000

// Callback function to handle response data
size_t http_write_callback(void *contents, size_t size, size_t nmemb, char *buf, size_t bufsize) {
	size_t total_size = size * nmemb;
	size_t remain_buf_size;
	remain_buf_size = HTTP_RESPONSE_BUFFER_SIZE - strlen(buf);
	strncat(buf, (const char*)contents, remain_buf_size);
	return total_size;
}

int ping_workstat() {
	// Initialize libcurl
	CURL* curl = curl_easy_init();

	if (!curl) {
		fprintf(stderr, "Error: Failed to initialize libcurl\n");
		return -1;
	}

	// Store the response
	char response_data[HTTP_RESPONSE_BUFFER_SIZE];
	response_data[0] = 0;

	char url[1500];
	snprintf(url, sizeof(url), "%sping", datum_config.workstat_api_url);

	// Set libcurl options
	curl_easy_setopt(curl, CURLOPT_URL, url);
	// curl_easy_setopt(curl, CURLOPT_POST, 1L);

	// Set headers
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Set the write callback function
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	// Perform the request
	CURLcode res = curl_easy_perform(curl);

	// Check for errors
	if (res != CURLE_OK) {
		fprintf(stderr, "Error: %s \n", curl_easy_strerror(res));
		return -2;
	} else {
		// Get HTTP response code
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		// printf("HTTP Response Code: %ld \n", http_code);
		if (http_code != 200) {
			fprintf(stderr, "Error response code: %ld \n", http_code);
			return -3;
		}
		// printf("Response: %s \n", response_data);
	}

	// Clean up
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return 0;
}

int submit_work_workstat(const char *username_orig, const char *username_upstream, uint64_t target_diff) {
	// Initialize libcurl
	CURL* curl = curl_easy_init();

	if (!curl) {
		fprintf(stderr, "Error: Failed to initialize libcurl\n");
		return -1;
	}

	// Create the JSON payload
	char json_payload[1000];
	snprintf(json_payload, sizeof(json_payload), "{\"uname_o\": \"%s\", \"uname_u\": \"%s\", \"tdiff\": %ld}", username_orig, username_upstream, target_diff);

	// Store the response
	char response_data[HTTP_RESPONSE_BUFFER_SIZE];
	response_data[0] = 0;

	char url[1500];
	snprintf(url, sizeof(url), "%swork-insert", datum_config.workstat_api_url);

	// Set libcurl options
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);

	// Set headers
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	// Set the write callback function
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

	// Perform the request
	// printf("Sending POST request to %s \n", url);
	// printf("Payload: %s \n", json_payload);

	CURLcode res = curl_easy_perform(curl);

	// Check for errors
	if (res != CURLE_OK) {
		fprintf(stderr, "Error: %s \n", curl_easy_strerror(res));
		return -2;
	} else {
		// Get HTTP response code
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

		// printf("HTTP Response Code: %ld \n", http_code);
		if (!((http_code == 200) || (http_code == 201))) {
			fprintf(stderr, "Error response code: %ld \n", http_code);
			return -3;
		}
		printf("Response: %s \n", response_data);
	}

	// Clean up
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	return 0;
}

int hook_init() {
	printf("datum_hook: hook_init \n");

	int ping_workstat_res;
	ping_workstat_res = ping_workstat();
	if (ping_workstat_res) {
		fprintf(stderr, "Error pinging workstat API: %d \n", ping_workstat_res);
		return ping_workstat_res;
	}

	printf("datum_hook: hook_init OK \n");

	return 0;
}

int submit_hook(
	const char *username_in,
	char* username_out,
	size_t username_out_buflen
) {
	// Upstream username: from config
	const char* us_username = datum_config.proxypool_us_username;

	// Upstream worker: hashed from full original username (incl. worker)
	unsigned char hash[32];
	if (!my_sha256((void*)hash, (const void*)username_in, strlen(username_in))) {
		printf("datum_hook: submit_hook: Error in hashing \n");
		return -1;
	}
	char hashstr[65];
	hash2hex(hash, hashstr);
	// printf("hashstr %s \n", hashstr);
	// crop it
	hashstr[WORKER_HASH_LEN] = 0;
	// printf("hashstr %s \n", hashstr);

	// Concatenate
	char us_username_full[512];
	snprintf(us_username_full, sizeof(us_username_full), "%s.%s", us_username, hashstr);
	// printf("us_username_full %s \n", us_username_full);

	strncpy(username_out, us_username_full, username_out_buflen);
	printf("datum_hook: submit_hook user_in: '%s' user_out: '%s' \n", username_in, username_out);
	return 0;
}

int accept_hook(
	const char *username_orig,
	const char *username_upstream,
	const uint64_t target_diff,
	const T_DATUM_STRATUM_JOB *_job
) {
	printf("datum_hook: accept_hook user '%s' '%s'  tdiff %ld \n", username_orig, username_upstream, target_diff);

	int res;
	res = submit_work_workstat(username_orig, username_upstream, target_diff);
	if (!res) {
		return res;
	}

	return 0;
}

int do_hook_test() {
	// uint64_t a = 3, b = 5, c = 0;
	// c = mh_add(3, 5);
	// printf("ADD %ld + %ld = %ld\n", a, b, c);

	const char* user_orig = "lnaddress1dummy.bitaxe";

	char user_upstream[100];

	int sres;
	sres = submit_hook(user_orig, user_upstream, sizeof(user_upstream));
	printf("do_hook_test: user after submit: '%s' %d \n", user_upstream, sres);

	int ares;
	ares = accept_hook(user_orig, user_upstream, 65536, NULL);
	printf("do_hook_test: ares %d \n", ares);

	return 0;
}
