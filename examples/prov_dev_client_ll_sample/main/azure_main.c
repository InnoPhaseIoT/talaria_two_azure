/*******************************************************************************
*
*  File: azure_main.c
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
#include "errno.h"
#include <wifi/wcm.h>

#define INPUT_PARAMETER_SSID "ssid"
#define INPUT_PARAMETER_PASSPHRASE "passphrase"

// read the boot args
const char *ssid;
const char *passphrase;
const char *hwaddr;

static struct wcm_handle *h = NULL;
static bool ap_link_up = false;
static bool ap_got_ip = false;

OS_APPINFO {.stack_size=4096};
static int init_platform();

#define AZURE_TASK_PRIO 1			    /* thread priority*/
#define AZURE_TASK_STACK_SIZE 4096 		/* thread stack size*/


/* declares an os_thread variable */
static struct os_thread *azure_task;		


/* the thread function */
static void* azure_task_fun(void* arg)
{
     os_printf("starting app_thread\n");
     prov_dev_client_ll_sample_run();
     return NULL;
}

/**
 * WCM notification callback function pointer
 */
static void wcm_notify_callback(void *ctx, struct os_msg *msg)
{
    switch(msg->msg_type)
    {
        case(WCM_NOTIFY_MSG_LINK_UP):
            os_printf("wcm_notify_cb to App Layer - WCM_NOTIFY_MSG_LINK_UP\n");
            ap_link_up = true;
            break;

        case(WCM_NOTIFY_MSG_LINK_DOWN):
            os_printf("wcm_notify_cb to App Layer - WCM_NOTIFY_MSG_LINK_DOWN\n");
            ap_link_up = false;
            ap_got_ip = false;
            break;

        case(WCM_NOTIFY_MSG_ADDRESS):
            os_printf("wcm_notify_cb to App Layer - WCM_NOTIFY_MSG_ADDRESS\n");
            ap_got_ip = true;
            break;

        case(WCM_NOTIFY_MSG_DISCONNECT_DONE):
            os_printf("wcm_notify_cb to App Layer - WCM_NOTIFY_MSG_DISCONNECT_DONE\n");
            ap_got_ip = false;
            break;

        case(WCM_NOTIFY_MSG_CONNECTED):
            os_printf("wcm_notify_cb to App Layer - WCM_NOTIFY_MSG_CONNECTED\n");
            break;

        default:
            break;
    }
    os_msg_release(msg);
}

/**
 * Calls WCM APIs to asynchronously connect to a WiFi network.
 * @param ssid Pointer to string with the SSID of the desired network.
 * @param passphrase The passphrase of the desired network.
 *
 * @return Returns zero on success, negative error code from 
 * errorno.h in case of an error.
 */
int wifi_main(const char *ssid, const char *pw)
{
    int status;
    os_printf("\n\rWiFi Details  SSID: %s, PASSWORD: %s\n\r", ssid, pw);

    h = wcm_create(NULL);
    if( h == NULL ){
        os_printf(" wcm_notify_enable failed.\n");
        return -ENOMEM;
    }
    os_msleep(2000);

    wcm_notify_enable(h, wcm_notify_callback, NULL);

    /* async connect to a WiFi network */
    os_printf("Connecting to WiFi...\n");
    status = wcm_add_network(h, ssid, NULL, pw);
    os_printf("add network status: %d\n", status);
    if(status != 0){
        os_printf("adding network Failed\n");
        /* can fail due to, already busy, no memory, or badly formatted password */
        return status;
    }

    os_printf("added network successfully, will try connecting..\n");
    status = wcm_auto_connect(h, 1);
    os_printf("connecting to network status: %d\n", status);
    if(status != 0){
        os_printf("trying to connect to network Failed\n");
        /* can fail due to, already busy, no memory */
        return status;
    }
    return status;
}

/**
 * Disconnect and cleanup a WiFi Connection Manager interface.
 * @param state_connected connection state
 */
void wifi_destroy(bool state_connected)
{
    int status;
    if(state_connected){
        status = wcm_auto_connect(h, 0);
        if(status != 0){
            os_printf("trying to disconnect to network Failed\n");
        }
    }
    wcm_destroy(h);
}

int main() {
	int rc;
	rc = init_platform();
	if (rc) {
		os_printf("init platform failed. ret:%d\n", rc);
		return rc;
	}

	/* Enable device suspend (deep sleep) via boot argument */
	if (os_get_boot_arg_int("suspend", 0) != 0)
		os_suspend_enable();

    while(!ap_got_ip) {
    os_msleep(1000);
    }

	/* creates a thread */
	azure_task = os_create_thread("azure_task", azure_task_fun, NULL, AZURE_TASK_PRIO, AZURE_TASK_STACK_SIZE);
	 
	if( azure_task == NULL )
	{
		os_printf(" thread creation failed\n");
		return -1;
	}
	 
	/* waits for thread function to finish */
	os_join_thread(azure_task);

	while (true) {
		os_msleep(1000);
	}
	return 0;
}

static int init_platform() {

    int ret;
    ssid = os_get_boot_arg_str(INPUT_PARAMETER_SSID);
    passphrase = os_get_boot_arg_str(INPUT_PARAMETER_PASSPHRASE);
	ret = wifi_main(ssid,passphrase);
    if(ret != 0) {
        os_printf("main -- WiFi Connection Failed due to WCM returning error \n");
        wifi_destroy(0);
    }
    return ret;
}

