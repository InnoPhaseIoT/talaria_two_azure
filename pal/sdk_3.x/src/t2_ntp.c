/*******************************************************************************
*
*  File: t2_ntp.c
*
*  Copyright (c) 2020, InnoPhase, Inc.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
*  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
*  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
*  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
*  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
*  POSSIBILITY OF SUCH DAMAGE.
*
*******************************************************************************/

#include <kernel/os.h>
#include "string.h"
#include <stdlib.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "sntp.h"
#include "osal.h"
/*Getting Current time from nist.time.gov */

#define NTP_SERVER_PORT "443"
#define NTP_SERVER_URL "nist.time.gov"
#define BUF_SIZE 256
#define GET_REQUEST "GET /actualtime.cgi HTTP/1.1\r\nHost: nist.time.gov\r\n\r\n"
unsigned int time_sntp = 0;

/**
 * Get current time
 *
 * Get the real-time  and return it.
 * 
 */
uint64_t t2_get_current_time() {

    while(1)
    {
        time_sntp = sntp_time();
        if(time_sntp != 0)
         {
            break;
         }
	}

    if (time_sntp)
    {
		return ( time_sntp + os_systime()/1000000);
    }
    int ret;
    uint64_t current_time = 0;
    mbedtls_net_context *server_fd = osal_alloc(sizeof(mbedtls_net_context));
    mbedtls_entropy_context *entropy = osal_alloc(
			sizeof(mbedtls_entropy_context));
    mbedtls_ctr_drbg_context *ctr_drbg = osal_alloc(
			sizeof(mbedtls_ctr_drbg_context));
    mbedtls_ssl_context *ssl = osal_alloc(sizeof(mbedtls_ssl_context));
    mbedtls_ssl_config *conf = osal_alloc(sizeof(mbedtls_ssl_config));
    char *buf = NULL;
    const char *pers = "ssl_client1";

    //Connection start
    mbedtls_net_init(server_fd);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);

    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
			(const unsigned char *) pers, strlen(pers));
    os_printf("\nmbedtls_ctr_drbg_seed 0x%x\r\n", -ret);

    ret = mbedtls_net_connect(server_fd, NTP_SERVER_URL,
    NTP_SERVER_PORT, MBEDTLS_NET_PROTO_TCP);

    if (ret)
        os_printf("\n mbedtls_net_connect for ntp ret:0x%x", -ret);

    mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    ret = mbedtls_ssl_setup(ssl, conf);
    mbedtls_ssl_set_hostname(ssl, NTP_SERVER_URL);
    mbedtls_ssl_set_bio(ssl, server_fd, mbedtls_net_send, mbedtls_net_recv,
			NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
				&& ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			pr_err(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
					-ret);
			goto done;
		}
	}

	//read time
	buf = osal_alloc(BUF_SIZE+3);
	int len = snprintf(buf, BUF_SIZE, GET_REQUEST);

	while ((ret = mbedtls_ssl_write(ssl, (unsigned char*) buf, len)) <= 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ
			    && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
		    goto done;
	    }
    }

    len = ret;
    do {
	    len = BUF_SIZE - 1;
	    memset(buf, 0, BUF_SIZE);
	    ret = mbedtls_ssl_read(ssl, (unsigned char*) buf, len);

	    if (strstr(buf, "timestamp")) {
		    char *pend;
		    char time_buf[20] = { 0, };
		    char *pstart = strstr(buf, "timestamp time=")
					+ strlen("timestamp time=") + 1;
		    pend = strstr(pstart, "\"");
		    snprintf(time_buf, pend - pstart + 1, pstart);
		    current_time = (atoll(time_buf)-os_systime()) / 1000000; //time from ntp server is in micro seconds
		    time_sntp = current_time;
		    //os_printf("\n current time came as [%llu]", g_cur_time);
		    break;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ
				|| ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;

	    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		    break;

	    if (ret < 0) {
		    os_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
		    break;
	    }

	    if (ret == 0) {
		    break;
	    }

	    len = ret;
    } while (1);

    done:
	//clean up

    mbedtls_ssl_close_notify( ssl);

    mbedtls_ssl_config_free(conf);
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    mbedtls_net_free(server_fd);
    mbedtls_ssl_free(ssl);

    osal_free(buf);

    osal_free(server_fd);
    osal_free(conf);
    osal_free(ctr_drbg);
    osal_free(entropy);
    osal_free(ssl);

    return time_sntp;
}

