// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This component was written to conform to the tlsio_requirements.md specification located
// in the Azure IoT C Utility: 
// https://github.com/Azure/azure-c-shared-utility/blob/master/devdoc/tlsio_requirements.md
// Comments throughout this code refer to requirements in that spec.

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "tlsio_pal.h"
#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/tlsio_options.h"
#include "mbedtls/config.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/net_sockets.h"

/* /pal/src/cert.c has cert for server verification */
#include "certs.h"
#include "osal.h"
//#define ENABLE_T2_TLS_DEBUG

#ifdef ENABLE_T2_TLS_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 512
#define T2_TLS_DEBUG(...)    \
	{\
	os_printf("DEBUG:   %s L#%d ", __func__, __LINE__);  \
	os_printf(__VA_ARGS__); \
	os_printf("\n"); \
	}
#else
#define T2_TLS_DEBUG(...)
#endif

/* Error enum
 *
 * Enumeration of return values from the t2_tls_conn_* functions.
 */
typedef enum {
    SUCCESS = 1,
    FAILURE = -1,
} t2_tls_error_t;

/* TLS Connection Parameters
 *
 */
typedef struct t2_tls {
	
    mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	uint32_t flags;
	mbedtls_x509_crt cacert;
	mbedtls_x509_crt clicert;
	mbedtls_pk_context pkey;
	mbedtls_net_context server_fd;
} t2_tls_t;


/* TLS Config Parameters
 *
 */
typedef struct t2_tls_cfg {
	char *pRootCAPath;
	char *pDeviceCertPath;
	char *pDevicePrivateKeyPath;
	bool ServerVerificationNeeded;
	char *pHostURL;
	uint16_t HostPort;

} t2_tls_cfg_t;


typedef struct
{
    unsigned char* bytes;
    size_t size;
    size_t unsent_size;
    ON_SEND_COMPLETE on_send_complete;
    void* callback_context;
} PENDING_TRANSMISSION;

#define MAX_VALID_PORT 0xffff

// The TLSIO_RECEIVE_BUFFER_SIZE has very little effect on performance, and is kept small
// to minimize memory consumption.
#define TLSIO_RECEIVE_BUFFER_SIZE 64

#define MAX_RCV_COUNT 5

typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_CLOSED,
    TLSIO_STATE_INIT,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_ERROR,
} TLSIO_STATE;

bool is_an_opening_state(TLSIO_STATE state)
{
    return state == TLSIO_STATE_INIT;
}

// This structure definition is mirrored in the unit tests, so if you change anything
// here, please replicate in UT as well.
typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    ON_IO_OPEN_COMPLETE on_open_complete;
    void* on_bytes_received_context;
    void* on_io_error_context;
    void* on_open_complete_context;
    t2_tls_cfg_t t2_tls_cfg;
    t2_tls_t *t2_tls_handle;
    TLSIO_STATE tlsio_state;
    uint16_t port;
    char* hostname;
    SINGLYLINKEDLIST_HANDLE pending_transmission_list;
    TLSIO_OPTIONS options;
} TLS_IO_INSTANCE;


/******************** t2_tls_conn_* specific functions ********************/

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth,
		uint32_t *flags) {
	char *buf = osal_alloc(2048);
	((void) data);

	mbedtls_x509_crt_info(buf, 2048 - 1, "", crt);

	if ((*flags) == 0) {
		os_printf("  This certificate has no flags\n");
	} else {
		os_printf(buf, *flags);
		os_printf("%s\n", buf);
	}
	osal_free(buf);
	return 0;
}

int mbedtls_ctr_drbg_random_ex(void *p_rng, unsigned char *output,
		size_t output_len) {
	mbedtls_ctr_drbg_random(p_rng, output, output_len);
	return 0;
}

t2_tls_error_t  t2_tls_conn_connect(const char *hostname, int hostlen, int port, const t2_tls_cfg_t *cfg, t2_tls_t *tls) {

	int ret = 0;
	const char *pers = "t2_tls_conn_connect";
	char portBuffer[6];

#ifdef ENABLE_T2_TLS_DEBUG
	unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
#endif

	if (NULL == tls) {
		return FAILURE;
	}

	mbedtls_net_init(&(tls->server_fd));
	mbedtls_ssl_init(&(tls->ssl));
	mbedtls_ssl_config_init(&(tls->conf));
	mbedtls_ctr_drbg_init(&(tls->ctr_drbg));
	mbedtls_x509_crt_init(&(tls->cacert));
	mbedtls_x509_crt_init(&(tls->clicert));
	mbedtls_pk_init(&(tls->pkey));

	mbedtls_entropy_init(&(tls->entropy));
	if ((ret = mbedtls_ctr_drbg_seed(&(tls->ctr_drbg),
			mbedtls_entropy_func, &(tls->entropy),
			(const unsigned char *) pers, strlen(pers))) != 0) {
		os_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        return FAILURE;
	}

	ret = mbedtls_x509_crt_parse(&(tls->cacert),
			(const unsigned char*) cfg->pRootCAPath,
			strlen(cfg->pRootCAPath) + 1);

	if (ret < 0) {
		os_printf(
				" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n",
				-ret);
        return FAILURE;
	}

	os_printf(
			"\n Root Done[%d]Loading the client cert. and key. size tls:%d\n",
			ret, sizeof(tls));

    if (cfg->pDeviceCertPath != NULL && cfg->pDevicePrivateKeyPath != NULL) {
	    ret =
			    mbedtls_x509_crt_parse(&(tls->clicert),
					    (const unsigned char*) cfg->pDeviceCertPath,
					    strlen(cfg->pDeviceCertPath) + 1);

	    os_printf("\n Loading the client cert done.... ret[%d]", ret);
	    if (ret != 0) {
		    os_printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\n\n", -ret);
            return FAILURE;
	    }

	    ret =
			    mbedtls_pk_parse_key(&(tls->pkey),
					    (const unsigned char*) cfg->pDevicePrivateKeyPath,
					    strlen(cfg->pDevicePrivateKeyPath)
							    + 1, NULL, 0);

	    os_printf("\n Client pkey loaded[%d]\n", ret);
	    if (ret != 0) {
            return FAILURE;
	    }

	    if ((ret = mbedtls_ssl_conf_own_cert(&(tls->conf),
			    &(tls->clicert), &(tls->pkey))) != 0) {
		    os_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
				    ret);
            return FAILURE;
	    }


    }
    else if (cfg->pDeviceCertPath != NULL || cfg->pDevicePrivateKeyPath != NULL) {
        T2_TLS_DEBUG("both pDeviceCertPath and pDevicePrivateKeyPath must be valid for mutual authentication");
        return -1; // think!
    }

	snprintf(portBuffer, 6, "%d", cfg->HostPort);
	os_printf("  . Connecting to %s/%s...",
			cfg->pHostURL, portBuffer);
	if ((ret = mbedtls_net_connect(&(tls->server_fd),
			cfg->pHostURL, portBuffer,
			MBEDTLS_NET_PROTO_TCP)) != 0) {
		os_printf(
				" failed\n  ! mbedtls_net_connect returned [-0x%x] uRL[%s] port[%s]\n\n",
				-ret, cfg->pHostURL, portBuffer);
		switch (ret) {
		case MBEDTLS_ERR_NET_SOCKET_FAILED:
            return FAILURE;
		case MBEDTLS_ERR_NET_UNKNOWN_HOST:
            return FAILURE;
		case MBEDTLS_ERR_NET_CONNECT_FAILED:
		default:
            return FAILURE;
		};
	}

	ret = mbedtls_net_set_nonblock(&(tls->server_fd));
	if (ret != 0) {
		os_printf(" failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
        return FAILURE;
	}
	os_printf(" ok\n");

	os_printf("  . Setting up the SSL/TLS structure...");
	if ((ret = mbedtls_ssl_config_defaults(&(tls->conf),
			MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		os_printf(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n",
				-ret);
        return FAILURE;
	}
	mbedtls_ssl_conf_verify(&(tls->conf), _iot_tls_verify_cert, NULL);
	if (cfg->ServerVerificationNeeded == true) {
		mbedtls_ssl_conf_authmode(&(tls->conf),
				MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		os_printf("verification is optional\n");
		mbedtls_ssl_conf_authmode(&(tls->conf),
				MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	mbedtls_ssl_conf_rng(&(tls->conf), mbedtls_ctr_drbg_random_ex,
			&(tls->ctr_drbg));
	mbedtls_ssl_conf_ca_chain(&(tls->conf), &(tls->cacert),
			NULL);

	/* Assign the resulting configuration to the SSL context. */
	if ((ret = mbedtls_ssl_setup(&(tls->ssl), &(tls->conf)))
			!= 0) {
		os_printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        return FAILURE;
	}
	if ((ret = mbedtls_ssl_set_hostname(&(tls->ssl),
			cfg->pHostURL)) != 0) {
		os_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        return FAILURE;
	}

	mbedtls_ssl_set_bio(&(tls->ssl), &(tls->server_fd),
			mbedtls_net_send, mbedtls_net_recv, NULL);

	while ((ret = mbedtls_ssl_handshake(&(tls->ssl))) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			os_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n",
					-ret);
			if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				os_printf("    Unable to verify the server's certificate. "
						"Either it is invalid,\n"
						"    or you didn't set ca_file or ca_path "
						"to an appropriate value.\n"
						"    Alternatively, you may want to use "
						"auth_mode=optional for testing purposes.\n");
			}
            return FAILURE;
		}
	}
	os_printf("SSL/TLS handshake. DONE ..ret:%d\n", ret);

	os_printf(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
			mbedtls_ssl_get_version(&(tls->ssl)),
			mbedtls_ssl_get_ciphersuite(&(tls->ssl)));
	if ((ret = mbedtls_ssl_get_record_expansion(&(tls->ssl))) >= 0) {
		os_printf("    [ Record expansion is %d ]\n", ret);
	} else {
		os_printf("    [ Record expansion is unknown (compression) ]\n");
	}

	os_printf(". Verifying peer X.509 certificate...\n");

	if (cfg->ServerVerificationNeeded == true) {
		char *vrfy_buf = osal_alloc(512);
		if ((tls->flags = mbedtls_ssl_get_verify_result(
				&(tls->ssl))) != 0) {
			os_printf(" failed\n");
			mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ",
					tls->flags);
			os_printf("%s\n", vrfy_buf);
            return FAILURE;
		} else {
			os_printf(" ok\n");
			ret = SUCCESS;
		}
		osal_free(vrfy_buf);
	} else {
		os_printf(" Server Verification skipped\n");
		ret = SUCCESS;
	}

	//ret = SUCCESS;

#ifdef ENABLE_T2_TLS_DEBUG
	if (mbedtls_ssl_get_peer_cert(&(tls->ssl)) != NULL) {
		T2_TLS_DEBUG("  . Peer certificate information    ...");
		mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tls->ssl)));
		T2_TLS_DEBUG("%s\n", buf);
	}
#endif

	return (t2_tls_error_t) ret;
}

void t2_tls_conn_delete(t2_tls_t *tls){

	mbedtls_net_free(&(tls->server_fd));

	mbedtls_x509_crt_free(&(tls->clicert));
	mbedtls_x509_crt_free(&(tls->cacert));
	mbedtls_pk_free(&(tls->pkey));
	mbedtls_ssl_free(&(tls->ssl));
	mbedtls_ssl_config_free(&(tls->conf));
	mbedtls_ctr_drbg_free(&(tls->ctr_drbg));
	mbedtls_entropy_free(&(tls->entropy));
}

t2_tls_error_t t2_tls_conn_write(t2_tls_t *tls, const void *data, size_t datalen, size_t *written_len)
{
	int ret = 0;

    ret = mbedtls_ssl_write(&(tls->ssl), data, datalen);
    if (ret < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ
                && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
	        os_printf(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n",
				    -ret);
		    /* All other negative return values indicate connection needs to be reset.
		    * Will be caught in ping request so ignored here */
            return FAILURE;
        }
    }

    *written_len = ret;
	return SUCCESS;
}


t2_tls_error_t t2_tls_conn_read(t2_tls_t *tls, void  *data, size_t datalen,  size_t *read_len) {

    mbedtls_ssl_context *ssl = &(tls->ssl);

	int ret;

    ret = mbedtls_ssl_read(ssl, data, datalen);
    if (ret < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_TIMEOUT) {

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                os_printf("t2_tls_conn_read -- peer notified us that the connection is going to be closed \n");
            }
			return FAILURE;
        }
	}

    *read_len = ret;
    if(ret == datalen){
        return SUCCESS;
    }
    else{
        //os_printf("t2_tls_conn_read -- this can be due to ssl read timeout \n");
        return FAILURE;
    }
}
/*******************************************************************************/


/* Codes_SRS_TLSIO_30_005: [ The phrase "enter TLSIO_STATE_EXT_ERROR" means the adapter shall call the on_io_error function and pass the on_io_error_context that was supplied in tlsio_open_async. ]*/
static void enter_tlsio_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

// Return true if a message was available to remove
static bool process_and_destroy_head_message(TLS_IO_INSTANCE* tls_io_instance, IO_SEND_RESULT send_result)
{
    bool result;
    LIST_ITEM_HANDLE head_pending_io;
    if (send_result == IO_SEND_ERROR)
    {
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        enter_tlsio_error_state(tls_io_instance);
    }
    head_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    if (head_pending_io != NULL)
    {
        PENDING_TRANSMISSION* head_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(head_pending_io);
        // Must remove the item from the list before calling the callback because 
        // SRS_TLSIO_30_091: [ If  tlsio_tls_dowork  is able to send all the bytes in an enqueued message, it shall first dequeue the message then call the messages's  on_send_complete  along with its associated  callback_context  and  IO_SEND_OK . ]
        if (singlylinkedlist_remove(tls_io_instance->pending_transmission_list, head_pending_io) != 0)
        {
            // This particular situation is a bizarre and unrecoverable internal error
            /* Codes_SRS_TLSIO_30_094: [ If the send process encounters an internal error or calls on_send_complete with IO_SEND_ERROR due to either failure or timeout, it shall also call on_io_error and pass in the associated on_io_error_context. ]*/
            enter_tlsio_error_state(tls_io_instance);
            LogError("Failed to remove message from list");
        }
        // on_send_complete is checked for NULL during PENDING_TRANSMISSION creation
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        head_message->on_send_complete(head_message->callback_context, send_result);

        free(head_message->bytes);
        free(head_message);
        result = true;
    }
    else
    {
        result = false;
    }
    return result;
}

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
    /* Codes_SRS_TLSIO_30_009: [ The phrase "enter TLSIO_STATE_EXT_CLOSING" means the adapter shall iterate through any unsent messages in the queue and shall delete each message after calling its on_send_complete with the associated callback_context and IO_SEND_CANCELLED. ]*/
    /* Codes_SRS_TLSIO_30_006: [ The phrase "enter TLSIO_STATE_EXT_CLOSED" means the adapter shall forcibly close any existing connections then call the on_io_close_complete function and pass the on_io_close_complete_context that was supplied in tlsio_close_async. ]*/
    /* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EXT_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/

    t2_tls_conn_delete(tls_io_instance->t2_tls_handle);

    while (process_and_destroy_head_message(tls_io_instance, IO_SEND_CANCELLED));
    // singlylinkedlist_destroy gets called in the main destroy

    tls_io_instance->on_bytes_received = NULL;
    tls_io_instance->on_io_error = NULL;
    tls_io_instance->on_bytes_received_context = NULL;
    tls_io_instance->on_io_error_context = NULL;
    tls_io_instance->tlsio_state = TLSIO_STATE_CLOSED;
    tls_io_instance->on_open_complete = NULL;
    tls_io_instance->on_open_complete_context = NULL;
}

static void tlsio_t2_tls_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_020: [ If tlsio_handle is NULL, tlsio_destroy shall do nothing. ]*/
        LogError("NULL tlsio");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
        if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
        {
            /* Codes_SRS_TLSIO_30_022: [ If the adapter is in any state other than TLSIO_STATE_EX_CLOSED when tlsio_destroy is called, the adapter shall enter TLSIO_STATE_EX_CLOSING and then enter TLSIO_STATE_EX_CLOSED before completing the destroy process. ]*/
            LogError("tlsio_t2_tls_destroy called while not in TLSIO_STATE_CLOSED.");
            internal_close(tls_io_instance);
        }
        /* Codes_SRS_TLSIO_30_021: [ The tlsio_destroy shall release all allocated resources and then release tlsio_handle. ]*/
        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }
        
        tlsio_options_release_resources(&tls_io_instance->options);

        if (tls_io_instance->pending_transmission_list != NULL)
        {
            /* Pending messages were cleared in internal_close */
            singlylinkedlist_destroy(tls_io_instance->pending_transmission_list);
        }
        free(tls_io_instance);
    }
}

/* Codes_SRS_TLSIO_30_010: [ The tlsio_tls_create shall allocate and initialize all necessary resources and return an instance of the tlsio_tls. ]*/
static CONCRETE_IO_HANDLE tlsio_t2_tls_create(void* io_create_parameters)
{
    TLS_IO_INSTANCE* result;

    if (io_create_parameters == NULL)
    {
        /* Codes_SRS_TLSIO_30_013: [ If the io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
        LogError("NULL tls_io_config");
        result = NULL;
    }
    else
    {
        /* Codes_SRS_TLSIO_30_012: [ The tlsio_create shall receive the connection configuration as a TLSIO_CONFIG* in io_create_parameters. ]*/
        TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
        if (tls_io_config->hostname == NULL)
        {
            /* Codes_SRS_TLSIO_30_014: [ If the hostname member of io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
            LogError("NULL tls_io_config->hostname");
            result = NULL;
        }
        else if (tls_io_config->port < 0 || tls_io_config->port > MAX_VALID_PORT)
        {
            /* Codes_SRS_TLSIO_30_015: [ If the port member of io_create_parameters value is less than 0 or greater than 0xffff, tlsio_tls_create shall log an error and return NULL. ]*/
            LogError("tls_io_config->port out of range");
            result = NULL;
        }
        else
        {
            result = malloc(sizeof(TLS_IO_INSTANCE));
            if (result == NULL)
            {
                /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_tls_create shall return NULL. ]*/
                LogError("malloc failed");
            }
            else
            {
                int ms_result;
                memset(result, 0, sizeof(TLS_IO_INSTANCE));
                result->port = (uint16_t)tls_io_config->port;
                result->tlsio_state = TLSIO_STATE_CLOSED;
                result->hostname = NULL;

                result->pending_transmission_list = NULL;

                tlsio_options_initialize(&result->options, TLSIO_OPTION_BIT_TRUSTED_CERTS |
                TLSIO_OPTION_BIT_x509_RSA_CERT | TLSIO_OPTION_BIT_x509_ECC_CERT);

                result->t2_tls_handle = calloc(1, sizeof(t2_tls_t));
                if (result->t2_tls_handle == NULL)
                {
                    /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                    LogError("malloc failed");
                    tlsio_t2_tls_destroy(result);
                    result = NULL;
                }

                /* Codes_SRS_TLSIO_30_016: [ tlsio_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
                ms_result = mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
                if (ms_result != 0)
                {
                    /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                    LogError("malloc failed");
                    tlsio_t2_tls_destroy(result);
                    result = NULL;
                }
                else
                {
                    // Create the message queue
                    result->pending_transmission_list = singlylinkedlist_create();
                    if (result->pending_transmission_list == NULL)
                    {
                        /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                        LogError("Failed singlylinkedlist_create");
                        tlsio_t2_tls_destroy(result);
                        result = NULL;
                    }
                }
            }
        }
    }

    return (CONCRETE_IO_HANDLE)result;
}


static int tlsio_t2_tls_open_async(CONCRETE_IO_HANDLE tls_io,
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{

    int result;
    if (on_io_open_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
        LogError("Required parameter on_io_open_complete is NULL");
        result = MU_FAILURE;
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_030: [ If the tlsio_handle parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
            result = MU_FAILURE;
            LogError("NULL tlsio");
        }
        else
        {
            if (on_bytes_received == NULL)
            {
                /* Codes_SRS_TLSIO_30_032: [ If the on_bytes_received parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                LogError("Required parameter on_bytes_received is NULL");
                result = MU_FAILURE;
            }
            else
            {
                if (on_io_error == NULL)
                {
                    /* Codes_SRS_TLSIO_30_033: [ If the on_io_error parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                    LogError("Required parameter on_io_error is NULL");
                    result = MU_FAILURE;
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

                    if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
                    {
                        /* Codes_SRS_TLSIO_30_037: [ If the adapter is in any state other than TLSIO_STATE_EXT_CLOSED when tlsio_open  is called, it shall log an error, and return FAILURE. ]*/
                        LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_CLOSED.");
                        result = MU_FAILURE;
                    }
                    else
                    {
                        /* Codes_SRS_TLSIO_30_034: [ The tlsio_open shall store the provided on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context, on_io_open_complete, and on_io_open_complete_context parameters for later use as specified and tested per other line entries in this document. ]*/
                        tls_io_instance->on_bytes_received = on_bytes_received;
                        tls_io_instance->on_bytes_received_context = on_bytes_received_context;

                        tls_io_instance->on_io_error = on_io_error;
                        tls_io_instance->on_io_error_context = on_io_error_context;

                        tls_io_instance->on_open_complete = on_io_open_complete;
                        tls_io_instance->on_open_complete_context = on_io_open_complete_context;

                        if (tls_io_instance->options.x509_key != NULL && tls_io_instance->options.x509_cert != NULL) {
                            tls_io_instance->t2_tls_cfg.pDeviceCertPath = (char *)tls_io_instance->options.x509_cert;
                            tls_io_instance->t2_tls_cfg.pDevicePrivateKeyPath = (char *)tls_io_instance->options.x509_key;
                        }

                        tls_io_instance->tlsio_state = TLSIO_STATE_INIT;
                        result = 0;
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_039: [ On failure, tlsio_open_async shall not call on_io_open_complete. ]*/
    }

    return result;
}

// This implementation does not have asynchronous close, but uses the _async name for consistency with the spec
static int tlsio_t2_tls_close_async(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_050: [ If the tlsio_handle parameter is NULL, tlsio_tls_close_async shall log an error and return FAILURE. ]*/
        LogError("NULL tlsio");
        result = MU_FAILURE;
    }
    else
    {
        if (on_io_close_complete == NULL)
        {
            /* Codes_SRS_TLSIO_30_055: [ If the on_io_close_complete parameter is NULL, tlsio_tls_close_async shall log an error and return FAILURE. ]*/
            LogError("NULL on_io_close_complete");
            result = MU_FAILURE;
        }
        else
        {
            TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

            if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN &&
                tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
            {
                /* Codes_SRS_TLSIO_30_053: [ If the adapter is in any state other than TLSIO_STATE_EXT_OPEN or TLSIO_STATE_EXT_ERROR then tlsio_close_async shall log that tlsio_close_async has been called and then continue normally. ]*/
                // LogInfo rather than LogError because this is an unusual but not erroneous situation
                LogInfo("tlsio_t2_tls_close has been called when in neither TLSIO_STATE_OPEN nor TLSIO_STATE_ERROR.");
            }

            if (is_an_opening_state(tls_io_instance->tlsio_state))
            {
                /* Codes_SRS_TLSIO_30_057: [ On success, if the adapter is in TLSIO_STATE_EXT_OPENING, it shall call on_io_open_complete with the on_io_open_complete_context supplied in tlsio_open_async and IO_OPEN_CANCELLED. This callback shall be made before changing the internal state of the adapter. ]*/
                tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_CANCELLED);
            }
            // This adapter does not support asynchronous closing
            /* Codes_SRS_TLSIO_30_056: [ On success the adapter shall enter TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EX_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_052: [ On success tlsio_close shall return 0. ]*/
            internal_close(tls_io_instance);
            on_io_close_complete(callback_context);
            result = 0;
        }
    }
    /* Codes_SRS_TLSIO_30_054: [ On failure, the adapter shall not call on_io_close_complete. ]*/
    return result;
}

static int dowork_read(TLS_IO_INSTANCE* tls_io_instance)
{
    // TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
    // then the framework just calls dowork repeatedly until it gets everything. So
    // a bigger buffer would just use memory without buying anything.
    // Putting this buffer in a small function also allows it to exist on the stack
    // rather than adding to heap fragmentation.
    unsigned char buffer[TLSIO_RECEIVE_BUFFER_SIZE];
    int rcv_bytes = 0;
    int rcv_count = 0;
    size_t read_len = 0;
    if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
    {
        t2_tls_conn_read(tls_io_instance->t2_tls_handle, buffer, sizeof(buffer), &read_len);
        rcv_bytes = read_len;
        while (rcv_bytes > 0)
        {
            // tls_io_instance->on_bytes_received was already checked for NULL
            // in the call to tlsio_t2_tls_open_async
            /* Codes_SRS_TLSIO_30_100: [ As long as the TLS connection is able to provide received data, tlsio_dowork shall repeatedly read this data and call on_bytes_received with the pointer to the buffer containing the data, the number of bytes received, and the on_bytes_received_context. ]*/
            tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
            
            if (++rcv_count > MAX_RCV_COUNT)
            {
                // Read no more than "MAX_RCV_COUNT" times to avoid starvation of other processes.
                // LogInfo("Skipping further reading to avoid starvation.");
                break;
            }
            t2_tls_conn_read(tls_io_instance->t2_tls_handle, buffer, sizeof(buffer), &read_len);
            rcv_bytes = read_len;
        }
        /* Codes_SRS_TLSIO_30_102: [ If the TLS connection receives no data then tlsio_dowork shall not call the on_bytes_received callback. ]*/
    }
    return rcv_bytes;
}

static int dowork_send(TLS_IO_INSTANCE* tls_io_instance)
{
    LIST_ITEM_HANDLE first_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    int write_result = 0;
    size_t sentLen = 0;
    if (first_pending_io != NULL)
    {
        PENDING_TRANSMISSION* pending_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(first_pending_io);
        uint8_t* buffer = ((uint8_t*)pending_message->bytes) +
            pending_message->size - pending_message->unsent_size;

        t2_tls_conn_write(tls_io_instance->t2_tls_handle, buffer, pending_message->unsent_size, &sentLen);
        write_result = sentLen;
        if (write_result > 0)
        {
            pending_message->unsent_size -= write_result;
            if (pending_message->unsent_size == 0)
            {
                /* Codes_SRS_TLSIO_30_091: [ If tlsio_tls_dowork is able to send all the bytes in an enqueued message, it shall call the messages's on_send_complete along with its associated callback_context and IO_SEND_OK. ]*/
                // The whole message has been sent successfully
                process_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
            }
            else
            {
                /* Codes_SRS_TLSIO_30_093: [ If the TLS connection was not able to send an entire enqueued message at once, subsequent calls to tlsio_dowork shall continue to send the remaining bytes. ]*/
                // Repeat the send on the next pass with the rest of the message
                // This empty else compiles to nothing but helps readability
            }
        }
        else
        {
            LogInfo("Error from SSL_write: %d", write_result); // this will change, our read/wrire wont give error in this way i guess, fix with t2_tls_error_t rc
        }
    }
    else
    {
        /* Codes_SRS_TLSIO_30_096: [ If there are no enqueued messages available, tlsio_tls_dowork shall do nothing. ]*/
    }
    return write_result;
}

static void tlsio_t2_tls_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_070: [ If the tlsio_handle parameter is NULL, tlsio_dowork shall do nothing except log an error. ]*/
        LogError("NULL tlsio");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        // This switch statement handles all of the state transitions during the opening process
        switch (tls_io_instance->tlsio_state)
        {
        case TLSIO_STATE_CLOSED:
            /* Codes_SRS_TLSIO_30_075: [ If the adapter is in TLSIO_STATE_EXT_CLOSED then  tlsio_dowork  shall do nothing. ]*/
            // Waiting to be opened, nothing to do
            break;
        case TLSIO_STATE_INIT:
            {
                t2_tls_error_t rc = FAILURE;

                tls_io_instance->t2_tls_cfg.HostPort = tls_io_instance->port;
	            tls_io_instance->t2_tls_cfg.pHostURL = tls_io_instance->hostname;//(char *)hostname;

                /* for now, cert for server verification is taken from /pal/src/certc */
                tls_io_instance->t2_tls_cfg.pRootCAPath = (char*) certificates;
                tls_io_instance->t2_tls_cfg.ServerVerificationNeeded = true;

                rc = t2_tls_conn_connect(tls_io_instance->hostname, strlen(tls_io_instance->hostname), tls_io_instance->port, &tls_io_instance->t2_tls_cfg, tls_io_instance->t2_tls_handle);
                if (rc == SUCCESS) {
                    tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
                    tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_OK);
                }
                else if (rc == FAILURE) {
                    tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                }
            }
            break;
        case TLSIO_STATE_OPEN:
            if (dowork_read(tls_io_instance) < 0 && errno != EAGAIN)
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                LogError("TLSIO_STATE_OPEN dowork_read failure \n");
            }
            if (dowork_send(tls_io_instance) < 0 && errno != EAGAIN)
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
                LogError("TLSIO_STATE_OPEN dowork_send failure \n");
            }
            break;
        case TLSIO_STATE_ERROR:
            /* Codes_SRS_TLSIO_30_071: [ If the adapter is in TLSIO_STATE_EXT_ERROR then tlsio_dowork shall do nothing. ]*/
            // There's nothing valid to do here but wait to be retried

            LogError("TLSIO_STATE_ERROR \n");
            break;
        default:
            LogError("Unexpected internal tlsio state");
            break;
        }
    }
}

static int tlsio_t2_tls_send_async(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (on_send_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_062: [ If the on_send_complete is NULL, tlsio_tls_send_async shall log the error and return FAILURE. ]*/
        result = MU_FAILURE;
        LogError("NULL on_send_complete");
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_060: [ If the tlsio_handle parameter is NULL, tlsio_tls_send_async shall log an error and return FAILURE. ]*/
            result = MU_FAILURE;
            LogError("NULL tlsio");
        }
        else
        {
            if (buffer == NULL)
            {
                /* Codes_SRS_TLSIO_30_061: [ If the buffer is NULL, tlsio_tls_send_async shall log the error and return FAILURE. ]*/
                result = MU_FAILURE;
                LogError("NULL buffer");
            }
            else
            {
                if (size == 0)
                {
                    /* Codes_SRS_TLSIO_30_067: [ If the  size  is 0,  tlsio_send  shall log the error and return FAILURE. ]*/
                    result = MU_FAILURE;
                    LogError("0 size");
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
                    if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
                    {
                        result = MU_FAILURE;
                        LogError("tlsio_t2_tls_send_async without a prior successful open");
                    }
                    else
                    {
                        PENDING_TRANSMISSION* pending_transmission = (PENDING_TRANSMISSION*)malloc(sizeof(PENDING_TRANSMISSION));
                        if (pending_transmission == NULL)
                        {
                            /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_tls_send shall log an error and return FAILURE. ]*/
                            result = MU_FAILURE;
                            LogError("malloc failed");
                        }
                        else
                        {
                            /* Codes_SRS_TLSIO_30_063: [ The tlsio_tls_send_async shall enqueue for transmission the on_send_complete, the callback_context, the size, and the contents of buffer. ]*/
                            pending_transmission->bytes = (unsigned char*)malloc(size);

                            if (pending_transmission->bytes == NULL)
                            {
                                /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_tls_send shall log an error and return FAILURE. ]*/
                                LogError("malloc failed");
                                free(pending_transmission);
                                result = MU_FAILURE;
                            }
                            else
                            {
                                pending_transmission->size = size;
                                pending_transmission->unsent_size = size;
                                pending_transmission->on_send_complete = on_send_complete;
                                pending_transmission->callback_context = callback_context;
                                (void)memcpy(pending_transmission->bytes, buffer, size);

                                if (singlylinkedlist_add(tls_io_instance->pending_transmission_list, pending_transmission) == NULL)
                                {
                                    /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_tls_send_async shall log an error and return FAILURE. ]*/
                                    LogError("Unable to add socket to pending list.");
                                    free(pending_transmission->bytes);
                                    free(pending_transmission);
                                    result = MU_FAILURE;
                                }
                                else
                                {
                                    /* Codes_SRS_TLSIO_30_063: [ On success, tlsio_tls_send_async shall enqueue for transmission the  on_send_complete , the  callback_context , the  size , and the contents of  buffer  and then return 0. ]*/
                                    dowork_send(tls_io_instance);
                                    result = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_066: [ On failure, on_send_complete shall not be called. ]*/
    }
    return result;
}

static int tlsio_t2_tls_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_120: [ If the tlsio_handle parameter is NULL, tlsio_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
    int result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = MU_FAILURE;
    }
    else
    {
        /* Codes_SRS_TLSIO_30_121: [ If the optionName parameter is NULL, tlsio_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
        /* Codes_SRS_TLSIO_30_122: [ If the value parameter is NULL, tlsio_tls_setoption shall do nothing except log an error and return FAILURE. ]*/
        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_520 [ The tlsio_tls_setoption shall do nothing and return FAILURE. ]*/
        TLSIO_OPTIONS_RESULT options_result = tlsio_options_set(&tls_io_instance->options, optionName, value);
        if (options_result != TLSIO_OPTIONS_RESULT_SUCCESS)
        {
            LogError("Failed tlsio_options_set");
            result = MU_FAILURE;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_560: [ The  tlsio_tls_retrieveoptions  shall do nothing and return an empty options handler. ]*/
static OPTIONHANDLER_HANDLE tlsio_t2_tls_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_160: [ If the tlsio_handle parameter is NULL, tlsio_tls_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
    OPTIONHANDLER_HANDLE result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = NULL;
    }
    else
    {
        result = tlsio_options_retrieve_options(&tls_io_instance->options, tlsio_t2_tls_setoption);
    }
    return result;
}

/* Codes_SRS_TLSIO_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
static const IO_INTERFACE_DESCRIPTION tlsio_t2_tls_interface_description =
{
    tlsio_t2_tls_retrieveoptions,
    tlsio_t2_tls_create,
    tlsio_t2_tls_destroy,
    tlsio_t2_tls_open_async,
    tlsio_t2_tls_close_async,
    tlsio_t2_tls_send_async,
    tlsio_t2_tls_dowork,
    tlsio_t2_tls_setoption
};

/* Codes_SRS_TLSIO_30_001: [ The tlsio_tls shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ]*/
const IO_INTERFACE_DESCRIPTION* tlsio_pal_get_interface_description(void)
{
    return &tlsio_t2_tls_interface_description;
}

