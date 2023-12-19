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
#include "wifi_utils.h"
#include "fs_utils.h"
#include "iothub_client_device_twin_and_methods_sample.h"

static struct wcm_handle *h = NULL;
static bool ap_link_up = false;
static bool ap_got_ip = false;

OS_APPINFO {.stack_size=4096};
static int init_platform();

#define AZURE_TASK_PRIO 1			    /* thread priority*/
#define AZURE_TASK_STACK_SIZE 4096 		/* thread stack size*/


/* declares an os_thread variable */
BaseType_t azure_task;		


/* the thread function */
static void azure_task_fun(void* arg)
{
     os_printf("starting app_thread\n");
     iothub_client_device_twin_init();
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
 *
 * @return Returns zero on success, negative error code from 
 * errorno.h in case of an error.
 */
int wifi_main()
{
    int rval;
    struct network_profile *profile;
    const char *np_conf_path = os_get_boot_arg_str("np_conf_path")?: NULL;

    h = wcm_create(NULL);
    if( h == NULL ){
        os_printf(" wcm_notify_enable failed.\n");
        return -ENOMEM;
    }
    vTaskDelay(2000);

    wcm_notify_enable(h, wcm_notify_callback, NULL);

    /* Connect to network */
    if (np_conf_path != NULL) {
        /* Create a Network Profile from a configuration file in
         *the file system*/
        rval = network_profile_new_from_file_system(&profile, np_conf_path);
    } else {
        /* Create a Network Profile using BOOT ARGS*/
        rval = network_profile_new_from_boot_args(&profile);
    }
    if (rval < 0) {
        pr_err("could not create network profile %d\n", rval);
        return rval;
    }

    rval = wcm_add_network_profile(h, profile);
    if (rval <  0) {
        pr_err("could not associate network profile to wcm %d\n", rval);
        return rval;
    }

    os_printf("added network profile successfully, will try connecting..\n");
    rval = wcm_auto_connect(h, true);
    if(rval < 0) {
        pr_err("network connection trial Failed, wcm_auto_connect returned %d\n", rval);
        /* can fail due to, already busy, no memory */
        return rval;
    }
    return rval;
}

/**
 * Disconnect and cleanup a WiFi Connection Manager interface.
 * @param state_connected connection state
 */
void wifi_destroy(bool state_connected)
{
    int rval;
    if(state_connected){
        rval = wcm_auto_connect(h, 0);
        if(rval != 0){
            os_printf("trying to disconnect to network failed with %d\n", rval);
        }

        rval = wcm_delete_network_profile(h, NULL);
        if(rval != 0){
            os_printf("trying to remove network profile failed with %d\n", rval);
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
        vTaskDelay(1000);
    }

    /* creates a thread */
  //  azure_task = os_create_thread("azure_task", azure_task_fun, NULL, AZURE_TASK_PRIO, AZURE_TASK_STACK_SIZE);
	 azure_task = xTaskCreate(azure_task_fun, /* The function that implements the task. */
        "azure_task", /* The text name assigned to the task - for debug only
                         * as it is not used by the kernel. */
        AZURE_TASK_STACK_SIZE, /* The size of the stack to allocate to the task. */
        NULL, /* The parameter passed to the task - not used in this case. */
        AZURE_TASK_PRIO, /* The priority assigned to the task. */
        NULL);

    if( (void *)azure_task == NULL )
    {
        os_printf(" thread creation failed\n");
        return -1;
    }
	 
    /* waits for thread function to finish */
    vTaskSuspend((void *)azure_task);

    while (true) {
        vTaskDelay(1000);
    }
    return 0;
}

static int init_platform() {
    int ret;

	os_printf("Mounting file system\n");
	ret = utils_mount_rootfs();

    ret = wifi_main();
    if(ret != 0) {
        os_printf("main -- WiFi Connection Failed due to WCM returning error \n");
        wifi_destroy(0);
    }
    return ret;
}

