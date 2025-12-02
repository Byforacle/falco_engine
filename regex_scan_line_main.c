/*
 * DOCA RegEx Line-by-Line Scan for JSON Data
 * 
 * 此程序专门用于按行读取和处理JSON格式的日志数据
 * 每行是一个独立的JSON对象，程序会逐行发送给DPU进行正则匹配
 *
 */

#include <string.h>
#include <stdlib.h>

#include <doca_argp.h>
#include <doca_log.h>
#include <doca_regex.h>

#include <utils.h>

DOCA_LOG_REGISTER(REGEX_LINE_SCAN::MAIN);

#define MAX_USER_FILE_NAME 255			/* Maximal length of user file path */
#define MAX_FILE_NAME (MAX_USER_FILE_NAME + 1)	/* Maximal length of file path */

/* Sample's Logic - Line-by-line processing */
doca_error_t regex_scan_lines(const char *data_file_path, const char *pci_addr, char *rules_buffer,
			      size_t rules_buffer_len);

/* Configuration struct */
struct regex_line_config {
	char *rules_buffer;				/* Buffer holds the RegEx rules */
	size_t rules_buffer_len;			/* Rules buffer size */
	char pci_address[DOCA_DEVINFO_PCI_ADDR_SIZE];	/* RegEx PCI address to use */
	char data[MAX_FILE_NAME];			/* Data to scan file path */
};

/*
 * ARGP Callback - Handle RegEx PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
pci_address_callback(void *param, void *config)
{
	struct regex_line_config *rgx_cfg = (struct regex_line_config *)config;
	char *pci_address = (char *)param;
	int len;

	len = strnlen(pci_address, DOCA_DEVINFO_PCI_ADDR_SIZE);
	if (len >= DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", 
			     DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strncpy(rgx_cfg->pci_address, pci_address, len + 1);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle RegEx rules path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rules_callback(void *param, void *config)
{
	struct regex_line_config *rgx_cfg = (struct regex_line_config *)config;
	char *rules_path = (char *)param;

	/* Read rules file into the rules buffer */
	return read_file(rules_path, &rgx_cfg->rules_buffer, &rgx_cfg->rules_buffer_len);
}

/*
 * ARGP Callback - Handle data to scan path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
data_callback(void *param, void *config)
{
	struct regex_line_config *rgx_cfg = (struct regex_line_config *)config;
	char *data_path = (char *)param;
	int len;

	len = strnlen(data_path, MAX_FILE_NAME);
	if (len >= MAX_FILE_NAME) {
		DOCA_LOG_ERR("Data path is too long max %d", MAX_USER_FILE_NAME);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strncpy(rgx_cfg->data, data_path, len + 1);
	return DOCA_SUCCESS;
}

/*
 * Register the command line parameters for the sample.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
register_regex_line_scan_params(void)
{
	doca_error_t result = DOCA_SUCCESS;
	struct doca_argp_param *pci_param, *rules_param, *data_param;

	/* Create and register PCI address of RegEx device param */
	result = doca_argp_param_create(&pci_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(pci_param, "p");
	doca_argp_param_set_long_name(pci_param, "pci-addr");
	doca_argp_param_set_description(pci_param, "DOCA RegEx device PCI address");
	doca_argp_param_set_callback(pci_param, pci_address_callback);
	doca_argp_param_set_type(pci_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(pci_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register RegEx rules param */
	result = doca_argp_param_create(&rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rules_param, "r");
	doca_argp_param_set_long_name(rules_param, "rules");
	doca_argp_param_set_arguments(rules_param, "<path>");
	doca_argp_param_set_description(rules_param, "Path to compiled rules file (rof2.binary)");
	doca_argp_param_set_callback(rules_param, rules_callback);
	doca_argp_param_set_type(rules_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(rules_param);
	result = doca_argp_register_param(rules_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register data to scan param*/
	result = doca_argp_param_create(&data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(data_param, "d");
	doca_argp_param_set_long_name(data_param, "data");
	doca_argp_param_set_arguments(data_param, "<path>");
	doca_argp_param_set_description(data_param, "Path to JSON lines data file");
	doca_argp_param_set_callback(data_param, data_callback);
	doca_argp_param_set_type(data_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(data_param);
	result = doca_argp_register_param(data_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	doca_error_t result;
	struct regex_line_config cfg = {0};
	int exit_status = EXIT_FAILURE;

	/* 默认配置 */
	strcpy(cfg.pci_address, "03:00.0");
	strcpy(cfg.data, "data_to_scan.txt");

	/* Register a logger backend */
	result = doca_log_create_standard_backend();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("===========================================");
	DOCA_LOG_INFO("Starting RegEx Line-by-Line Scan for JSON");
	DOCA_LOG_INFO("===========================================");

	/* Parse cmdline/json arguments */
	result = doca_argp_init("doca_regex_line_scan", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		goto sample_exit;
	}

	/* Register RegEx scan params */
	result = register_regex_line_scan_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register sample parameters: %s", doca_get_error_string(result));
		goto argp_cleanup;
	}

	/* Start parsing sample arguments */
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
		goto rules_buf_cleanup;
	}

	DOCA_LOG_INFO("Configuration:");
	DOCA_LOG_INFO("  PCI Address: %s", cfg.pci_address);
	DOCA_LOG_INFO("  Data File:   %s", cfg.data);
	DOCA_LOG_INFO("  Rules Size:  %zu bytes", cfg.rules_buffer_len);

	/* Run RegEx line-by-line scan */
	result = regex_scan_lines(cfg.data, cfg.pci_address, cfg.rules_buffer, cfg.rules_buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("regex_scan_lines() encountered an error: %s", doca_get_error_string(result));
		goto rules_buf_cleanup;
	}

	exit_status = EXIT_SUCCESS;

rules_buf_cleanup:
	if (cfg.rules_buffer != NULL)
		free(cfg.rules_buffer);
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS) {
		DOCA_LOG_INFO("===========================================");
		DOCA_LOG_INFO("Sample finished successfully");
		DOCA_LOG_INFO("===========================================");
	} else {
		DOCA_LOG_INFO("===========================================");
		DOCA_LOG_INFO("Sample finished with errors");
		DOCA_LOG_INFO("===========================================");
	}
	return exit_status;
}
