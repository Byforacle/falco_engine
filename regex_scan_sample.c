/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_regex.h>
#include <doca_regex_mempool.h>

#include <common.h>

DOCA_LOG_REGISTER(REGEX_SCAN::SAMPLE);

#define NB_CHUNKS 6			/* Number of chunks to send to RegEx engine */
#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */

/* Sample context structure */
struct regex_scan_ctx {
	char *data_buffer;				/* Data buffer */
	size_t data_buffer_len;				/* Length of data buffer */
	char *rules_buffer;				/* Rules buffer */
	size_t rules_buffer_len;			/* Length of rules buffer */
	size_t chunk_len;				/* size of chunk to send to RegEx */
	const char *pci_address;			/* RegEx PCI address to use */
	struct doca_buf *buf;				/* active job buffer */
	struct doca_buf_inventory *buf_inv;		/* Pool of doca_buf objects */
	struct doca_dev *dev;				/* DOCA device */
	struct doca_mmap *mmap;				/* DOCA Memory orchestration */
	struct doca_regex *doca_regex;			/* DOCA RegEx interface */
	struct doca_workq *workq;			/* DOCA work queue */
	struct doca_regex_search_result *results;	/* Pointer to array of result objects */
};

/*
 * Printing the RegEx results for line-by-line mode
 *
 * @line_number [in]: current line number being processed
 * @line_data [in]: the complete JSON line data
 * @result [in]: DOCA regex search result
 */
static void
regex_scan_report_line_results(uint64_t line_number, const char *line_data, struct doca_regex_search_result *result)
{
	struct doca_regex_match *ptr;

	if (result->num_matches == 0)
		return;
	
	ptr = result->matches;
	while (ptr != NULL) {
		DOCA_LOG_INFO("=== MATCH FOUND ===");
		DOCA_LOG_INFO("Line number: %lu", line_number);
		DOCA_LOG_INFO("Rule ID: %d", ptr->rule_id);
		DOCA_LOG_INFO("Match position: %u (length: %u)", ptr->match_start, ptr->length);
		DOCA_LOG_INFO("Full JSON line: %s", line_data);
		DOCA_LOG_INFO("==================");
		
		struct doca_regex_match *const to_release_match = ptr;
		ptr = ptr->next;
		doca_regex_mempool_put_obj(result->matches_mempool, to_release_match);
	}
}

/*
 * Printing the RegEx results
 *
 * @regex_cfg [in]: sample RegEx configuration struct
 * @event [in]: DOCA event structure
 * @chunk_len [in]: chunk size, used for calculate job data offset
 */
static void
regex_scan_report_results(struct regex_scan_ctx *regex_cfg, struct doca_event *event, size_t chunk_len)
{
	size_t offset;
	struct doca_regex_match *ptr;
	struct doca_regex_search_result * const result = (struct doca_regex_search_result *)event->result.ptr;

	if (result->num_matches == 0)
		return;
	ptr = result->matches;
	/* Match start is relative to the whole file data and not the current chunk */
	offset = chunk_len * event->user_data.u64;
	while (ptr != NULL) {
		DOCA_LOG_INFO("Date rule id: %d", ptr->rule_id);
		regex_cfg->data_buffer[ptr->match_start + offset + ptr->length] = '\0';
		DOCA_LOG_INFO("Date value: %*s", ptr->length,
			      (char *)(regex_cfg->data_buffer + offset + ptr->match_start));
		struct doca_regex_match *const to_release_match = ptr;

		ptr = ptr->next;
		doca_regex_mempool_put_obj(result->matches_mempool, to_release_match);
	}
}

/*
 * Initialize DOCA RegEx resources for line-by-line mode (without pre-allocated data buffer)
 *
 * @regex_cfg [in]: RegEx configuration struct
 * @line_buffer [in]: Buffer for single line processing
 * @buffer_size [in]: Size of the line buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
regex_scan_init_for_lines(struct regex_scan_ctx *regex_cfg, void *line_buffer, size_t buffer_size)
{
	doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 8;

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(regex_cfg->pci_address, NULL, &regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found");
		return result;
	}

	/* Create a DOCA RegEx instance */
	result = doca_regex_create(&(regex_cfg->doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create RegEx device");
		return result;
	}

	/* Set the RegEx device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_regex_as_ctx(regex_cfg->doca_regex), regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set RegEx device. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Size per workq memory pool */
	result = doca_regex_set_workq_matches_memory_pool_size(regex_cfg->doca_regex, mempool_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set matches mempool size. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Load compiled rules into the RegEx */
	result = doca_regex_set_hardware_compiled_rules(
		regex_cfg->doca_regex, regex_cfg->rules_buffer, regex_cfg->rules_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to program rules file. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, 1, DOCA_BUF_EXTENSION_NONE, &regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap for line buffer */
	result = doca_mmap_create(NULL, &regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(regex_cfg->mmap, regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Set memory range for line buffer */
	result = doca_mmap_set_memrange(regex_cfg->mmap, line_buffer, buffer_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory region of memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Initialize DOCA RegEx resources according to the configuration struct fields
 *
 * @regex_cfg [in]: RegEx configuration struct
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
regex_scan_init(struct regex_scan_ctx *regex_cfg)
{
	doca_error_t result = DOCA_SUCCESS;
	const int mempool_size = 8;

	/* Find doca_dev according to the PCI address */
	result = open_doca_device_with_pci(regex_cfg->pci_address, NULL, &regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("No device matching PCI address found");
		return result;
	}

	/* Create a DOCA RegEx instance */
	result = doca_regex_create(&(regex_cfg->doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create RegEx device");
		return result;
	}

	/* Set the RegEx device as the main HW accelerator */
	result = doca_ctx_dev_add(doca_regex_as_ctx(regex_cfg->doca_regex), regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set RegEx device.Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Size per workq memory pool */
	result = doca_regex_set_workq_matches_memory_pool_size(regex_cfg->doca_regex, mempool_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable set matches mempool size. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Load compiled rules into the RegEx */
	result = doca_regex_set_hardware_compiled_rules(
		regex_cfg->doca_regex, regex_cfg->rules_buffer, regex_cfg->rules_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to program rules file. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start buffer inventory */
	result = doca_buf_inventory_create(NULL, 1, DOCA_BUF_EXTENSION_NONE, &regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_buf_inventory_start(regex_cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory. Reason: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and start mmap */
	result = doca_mmap_create(NULL, &regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_dev_add(regex_cfg->mmap, regex_cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_set_memrange(regex_cfg->mmap, regex_cfg->data_buffer, regex_cfg->data_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory region of memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_mmap_start(regex_cfg->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start memory map. Reason: %s", doca_get_error_string(result));
		return result;
	}

	regex_cfg->results = calloc(NB_CHUNKS, sizeof(struct doca_regex_search_result));
	if (regex_cfg->results == NULL) {
		DOCA_LOG_ERR("Unable to add allocate results storage");
		return DOCA_ERROR_NO_MEMORY;
	}

	return result;
}

/*
 * Enqueue job to DOCA RegEx qp
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @job_request [in]: RegEx job request, already initialized with first chunk.
 * @remaining_bytes [in]: the remaining bytes to send all jobs (chunks).
 * @return: number of the enqueued jobs on success and negative value otherwise
 */
static int
regex_scan_enq_job(struct regex_scan_ctx *regex_cfg, struct doca_regex_job_search *job_request,
		   uint32_t *remaining_bytes)
{
	doca_error_t result;
	int nb_enqueued = 0;
	uint32_t nb_free = 0;

	doca_buf_inventory_get_num_free_elements(regex_cfg->buf_inv, &nb_free);

	if (*remaining_bytes != 0 && nb_free != 0) {
		struct doca_buf *buf;
		const size_t job_size =
			regex_cfg->chunk_len < *remaining_bytes ? regex_cfg->chunk_len : *remaining_bytes;
		int const read_offset = regex_cfg->data_buffer_len - *remaining_bytes;
		void *mbuf_data;

		if (doca_buf_inventory_buf_by_addr(regex_cfg->buf_inv, regex_cfg->mmap,
						   regex_cfg->data_buffer + read_offset, job_size,
						   &buf) != DOCA_SUCCESS)
			return nb_enqueued;

		doca_buf_get_data(buf, &mbuf_data);
		doca_buf_set_data(buf, mbuf_data, job_size);

		regex_cfg->buf = buf;
		job_request->buffer = buf;
		job_request->result = regex_cfg->results + nb_enqueued;
		job_request->allow_batching = false;
		result = doca_workq_submit(regex_cfg->workq, (struct doca_job *)job_request);
		if (result == DOCA_ERROR_NO_MEMORY) {
			doca_buf_refcount_rm(buf, NULL);
			return nb_enqueued; /* qp is full, try to dequeue */
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to enqueue job. Reason: %s", doca_get_error_string(result));
			return -1;
		}
		*remaining_bytes -= job_size; /* Update remaining bytes to scan */
		nb_enqueued++;
		--nb_free;

		/* Prepare next chunk */
		job_request->base.user_data.u64++;
	}

	return nb_enqueued;
}

/*
 * Dequeue jobs responses
 *
 * @regex_cfg [in]: regex_scan_ctx configuration struct
 * @chunk_len [in]: job chunk size
 * @return: number of the dequeue jobs on success and negative value otherwise
 */
static int
regex_scan_deq_job(struct regex_scan_ctx *regex_cfg, size_t chunk_len)
{
	doca_error_t result;
	int nb_dequeued = 0;
	struct doca_event event = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};

	do {
		result = doca_workq_progress_retrieve(regex_cfg->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_SUCCESS) {
			/* release the buffer back into the pool so it can be re-used */
			doca_buf_refcount_rm(regex_cfg->buf, NULL);
			regex_scan_report_results(regex_cfg, &event, chunk_len);
			++nb_dequeued;
		} else if (result == DOCA_ERROR_AGAIN) {
			/* Wait for the job to complete */
			nanosleep(&ts, &ts);
		} else {
			DOCA_LOG_ERR("Failed to dequeue results. Reason: %s", doca_get_error_string(result));
			return -1;
		}

	} while (result == DOCA_SUCCESS);

	return nb_dequeued;
}

/*
 * RegEx scan cleanup, destroy all DOCA RegEx resources
 *
 * @regex_cfg [in]: sample RegEx configuration struct
 */
static void
regex_scan_destroy(struct regex_scan_ctx *regex_cfg)
{
	if (regex_cfg->workq != NULL) {
		doca_ctx_workq_rm(doca_regex_as_ctx(regex_cfg->doca_regex), regex_cfg->workq);
		doca_workq_destroy(regex_cfg->workq);
	}

	if (regex_cfg->doca_regex != NULL) {
		doca_ctx_stop(doca_regex_as_ctx(regex_cfg->doca_regex));
		doca_regex_destroy(regex_cfg->doca_regex);
		regex_cfg->doca_regex = NULL;
	}

	if (regex_cfg->results != NULL) {
		free(regex_cfg->results);
		regex_cfg->results = NULL;
	}

	if (regex_cfg->mmap != NULL) {
		doca_mmap_destroy(regex_cfg->mmap);
		regex_cfg->mmap = NULL;
	}

	if (regex_cfg->buf_inv != NULL) {
		doca_buf_inventory_stop(regex_cfg->buf_inv);
		doca_buf_inventory_destroy(regex_cfg->buf_inv);
		regex_cfg->buf_inv = NULL;
	}

	if (regex_cfg->dev != NULL) {
		doca_dev_close(regex_cfg->dev);
		regex_cfg->dev = NULL;
	}
}

/*
 * Run DOCA RegEx sample
 *
 * @data_buffer [in]: User data used to find the matches
 * @data_buffer_len [in]: data_buffer length
 * @pci_addr [in]: pci address for HW RegEx device
 * @rules_buffer [in]: Rules data (compiled rules(rof2.binary))
 * @rules_buffer_len [in]: rules_buffer length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
regex_scan(char *data_buffer, size_t data_buffer_len, const char *pci_addr, char *rules_buffer,
	size_t rules_buffer_len)
{
	if (data_buffer == NULL || data_buffer_len == 0 || pci_addr == NULL || rules_buffer == NULL ||
		rules_buffer_len == 0)
		return DOCA_ERROR_INVALID_VALUE;

	doca_error_t result;
	uint32_t remaining_bytes, nb_dequeued = 0, nb_enqueued = 0;
	const uint32_t nb_chunks = NB_CHUNKS;
	struct regex_scan_ctx rgx_cfg = {0};
	struct doca_regex_job_search job_request;
	int ret;

	memset(&job_request, 0, sizeof(job_request));

	/* Set DOCA RegEx configuration fields in regex_cfg according to our sample */
	rgx_cfg.data_buffer = data_buffer;
	rgx_cfg.data_buffer_len = data_buffer_len;
	rgx_cfg.rules_buffer = rules_buffer;
	rgx_cfg.rules_buffer_len = rules_buffer_len;
	rgx_cfg.chunk_len = (rgx_cfg.data_buffer_len < nb_chunks) ? rgx_cfg.data_buffer_len
								  : 1 + (rgx_cfg.data_buffer_len / nb_chunks);
	rgx_cfg.pci_address = pci_addr;

	/* Init DOCA RegEx */
	result = regex_scan_init(&rgx_cfg);
	if (result != DOCA_SUCCESS) {
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	/* Start DOCA RegEx */
	result = doca_ctx_start(doca_regex_as_ctx(rgx_cfg.doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA RegEx. [%s]", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_workq_create(NB_CHUNKS, &(rgx_cfg.workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue. Reason: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_ctx_workq_add(doca_regex_as_ctx(rgx_cfg.doca_regex), rgx_cfg.workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to attach work queue to RegEx. Reason: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	job_request.base.type = DOCA_REGEX_JOB_SEARCH;
	job_request.rule_group_ids[0] = 1;
	job_request.base.ctx = doca_regex_as_ctx(rgx_cfg.doca_regex);
	remaining_bytes = data_buffer_len;

	/* The main loop, enqueues jobs (chunks) and dequeues for results */
	do {
		/* Enqueue jobs */
		ret = regex_scan_enq_job(&rgx_cfg, &job_request, &remaining_bytes);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to enqueue jobs");
			regex_scan_destroy(&rgx_cfg);
			return DOCA_ERROR_IO_FAILED;
		}

		nb_enqueued += ret;

		/* Dequeue responses */
		ret = regex_scan_deq_job(&rgx_cfg, rgx_cfg.chunk_len);
		if (ret < 0) {
			DOCA_LOG_ERR("Failed to dequeue jobs responses");
			regex_scan_destroy(&rgx_cfg);
			return DOCA_ERROR_IO_FAILED;
		}
		nb_dequeued += ret;
	} while (remaining_bytes > 0 || nb_dequeued != nb_enqueued);

	/* RegEx scan recognition cleanup */
	regex_scan_destroy(&rgx_cfg);
	return DOCA_SUCCESS;
}

/*
 * Process a single line (JSON) with RegEx
 *
 * @regex_cfg [in]: RegEx context
 * @line_data [in]: Single line of data (JSON string)
 * @line_len [in]: Length of the line
 * @line_number [in]: Line number for reporting
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
regex_scan_process_line(struct regex_scan_ctx *regex_cfg, char *line_data, size_t line_len, uint64_t line_number)
{
	doca_error_t result;
	struct doca_buf *buf = NULL;
	struct doca_regex_job_search job_request = {0};
	struct doca_event event = {0};
	void *mbuf_data;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Create buffer for this line */
	result = doca_buf_inventory_buf_by_addr(regex_cfg->buf_inv, regex_cfg->mmap,
						line_data, line_len, &buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create buffer for line %lu", line_number);
		return result;
	}

	doca_buf_get_data(buf, &mbuf_data);
	doca_buf_set_data(buf, mbuf_data, line_len);

	/* Prepare job request */
	job_request.base.type = DOCA_REGEX_JOB_SEARCH;
	job_request.base.ctx = doca_regex_as_ctx(regex_cfg->doca_regex);
	job_request.base.user_data.u64 = line_number;
	job_request.buffer = buf;
	job_request.result = regex_cfg->results;
	job_request.rule_group_ids[0] = 1;
	job_request.allow_batching = false;

	/* Submit job */
	result = doca_workq_submit(regex_cfg->workq, (struct doca_job *)&job_request);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit job for line %lu: %s", 
			     line_number, doca_get_error_string(result));
		doca_buf_refcount_rm(buf, NULL);
		return result;
	}

	/* Wait for result */
	do {
		result = doca_workq_progress_retrieve(regex_cfg->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
		if (result == DOCA_ERROR_AGAIN) {
			nanosleep(&ts, &ts);
		} else if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to retrieve result for line %lu: %s",
				     line_number, doca_get_error_string(result));
			doca_buf_refcount_rm(buf, NULL);
			return result;
		}
	} while (result == DOCA_ERROR_AGAIN);

	/* Report results for this line */
	regex_scan_report_line_results(line_number, line_data, 
				       (struct doca_regex_search_result *)event.result.ptr);

	/* Cleanup */
	doca_buf_refcount_rm(buf, NULL);
	return DOCA_SUCCESS;
}

/*
 * Run DOCA RegEx in line-by-line mode for JSON data
 *
 * @data_file_path [in]: Path to the data file (JSON lines)
 * @pci_addr [in]: PCI address for HW RegEx device
 * @rules_buffer [in]: Rules data (compiled rules)
 * @rules_buffer_len [in]: rules_buffer length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
regex_scan_lines(const char *data_file_path, const char *pci_addr, char *rules_buffer, size_t rules_buffer_len)
{
	if (data_file_path == NULL || pci_addr == NULL || rules_buffer == NULL || rules_buffer_len == 0)
		return DOCA_ERROR_INVALID_VALUE;

	doca_error_t result;
	FILE *fp = NULL;
	char *line_buffer = NULL;
	size_t line_cap = 0;
	ssize_t line_len;
	uint64_t line_number = 0;
	uint64_t total_matches = 0;
	struct regex_scan_ctx rgx_cfg = {0};
	const size_t max_line_size = 1024 * 1024; /* 1MB max line size */

	/* Allocate a fixed-size buffer for line processing */
	line_buffer = (char *)malloc(max_line_size);
	if (line_buffer == NULL) {
		DOCA_LOG_ERR("Failed to allocate line buffer");
		return DOCA_ERROR_NO_MEMORY;
	}

	/* Set DOCA RegEx configuration */
	rgx_cfg.rules_buffer = rules_buffer;
	rgx_cfg.rules_buffer_len = rules_buffer_len;
	rgx_cfg.pci_address = pci_addr;

	/* Init DOCA RegEx with line buffer */
	result = regex_scan_init_for_lines(&rgx_cfg, line_buffer, max_line_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to initialize RegEx: %s", doca_get_error_string(result));
		free(line_buffer);
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	/* Start DOCA RegEx */
	result = doca_ctx_start(doca_regex_as_ctx(rgx_cfg.doca_regex));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DOCA RegEx: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	/* Create work queue */
	result = doca_workq_create(1, &(rgx_cfg.workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	result = doca_ctx_workq_add(doca_regex_as_ctx(rgx_cfg.doca_regex), rgx_cfg.workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to attach work queue to RegEx: %s", doca_get_error_string(result));
		regex_scan_destroy(&rgx_cfg);
		return result;
	}

	/* Allocate results array */
	rgx_cfg.results = (struct doca_regex_search_result *)malloc(sizeof(struct doca_regex_search_result));
	if (rgx_cfg.results == NULL) {
		DOCA_LOG_ERR("Failed to allocate results buffer");
		free(line_buffer);
		regex_scan_destroy(&rgx_cfg);
		return DOCA_ERROR_NO_MEMORY;
	}

	/* Open data file */
	fp = fopen(data_file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open data file: %s", data_file_path);
		free(line_buffer);
		regex_scan_destroy(&rgx_cfg);
		return DOCA_ERROR_IO_FAILED;
	}

	DOCA_LOG_INFO("Starting line-by-line RegEx scan on: %s", data_file_path);

	/* Process file line by line */
	while (fgets(line_buffer, max_line_size, fp) != NULL) {
		line_number++;
		line_len = strlen(line_buffer);
		
		/* Remove trailing newline if present */
		if (line_len > 0 && line_buffer[line_len - 1] == '\n') {
			line_buffer[line_len - 1] = '\0';
			line_len--;
		}
		if (line_len > 0 && line_buffer[line_len - 1] == '\r') {
			line_buffer[line_len - 1] = '\0';
			line_len--;
		}

		/* Skip empty lines */
		if (line_len == 0)
			continue;

		/* Process this line */
		result = regex_scan_process_line(&rgx_cfg, line_buffer, line_len, line_number);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_WARN("Failed to process line %lu, skipping...", line_number);
			continue;
		}

		/* Progress indicator every 1000 lines */
		if (line_number % 1000 == 0) {
			DOCA_LOG_INFO("Processed %lu lines...", line_number);
		}
	}

	DOCA_LOG_INFO("Completed scanning %lu lines", line_number);

	/* Cleanup */
	if (fp != NULL)
		fclose(fp);
	if (line_buffer != NULL)
		free(line_buffer);
	regex_scan_destroy(&rgx_cfg);

	return DOCA_SUCCESS;
}
