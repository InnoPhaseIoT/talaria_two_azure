// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <kernel/os.h>
#include "azure_macro_utils/macro_utils.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/xlogging.h"

#define AZ_PAL_THREAD_PRIO 1			/* thread priority*/
#define AZ_PAL_THREAD_STACK_SIZE 512 	/* thread stack size*/

MU_DEFINE_ENUM_STRINGS(THREADAPI_RESULT, THREADAPI_RESULT_VALUES);

THREADAPI_RESULT ThreadAPI_Create(THREAD_HANDLE* threadHandle, THREAD_START_FUNC func, void* arg)
{
    THREADAPI_RESULT result;
    if ((threadHandle == NULL) ||
        (func == NULL))
    {
        /*Codes_SRS_THREADAPI_30_011: [ If threadHandle is NULL ThreadAPI_Create shall return THREADAPI_INVALID_ARG. ]*/
        /*Codes_SRS_THREADAPI_30_012: [ If func is NULL ThreadAPI_Create shall return THREADAPI_INVALID_ARG. ]*/
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
    }
    else
    {
        /*Codes_SRS_THREADAPI_30_014: [ On success, ThreadAPI_Create shall return the created thread object in threadHandle. ]*/
        *threadHandle = os_create_thread("az_pal", (os_entrypoint_t)func, arg, AZ_PAL_THREAD_PRIO, AZ_PAL_THREAD_STACK_SIZE);
        /* Note -- this API returns NULL only in the case of memory alloc fails (stack size plus thread housekeeping)*/
        if(*threadHandle == NULL)
        {
            /*Codes_SRS_THREADAPI_30_013: [ If ThreadAPI_Create is unable to create a thread it shall return THREADAPI_ERROR or THREADAPI_NO_MEMORY, whichever seems more appropriate. ]*/
            result = THREADAPI_NO_MEMORY;
            LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
        }
        else
        {
            /*Codes_SRS_THREADAPI_30_015: [ On success, ThreadAPI_Create shall return THREADAPI_OK. ]*/
            result = THREADAPI_OK;
        }
    }

    return result;
}

THREADAPI_RESULT ThreadAPI_Join(THREAD_HANDLE threadHandle, int *res)
{
    THREADAPI_RESULT result = THREADAPI_OK;

    if (threadHandle == NULL)
    {
        /*Codes_SRS_THREADAPI_30_021: [ If threadHandle is NULL ThreadAPI_Join shall return THREADAPI_INVALID_ARG. ]*/
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %" PRI_MU_ENUM ")", MU_ENUM_VALUE(THREADAPI_RESULT, result));
    }
    else
    {
        void* threadResult;
        threadResult = os_join_thread(threadHandle);

        /* No error handelling possible with t2 os_join_thread(), to do something like below */
        #if 0
        /*Codes_SRS_THREADAPI_30_022: [ If ThreadAPI_Join fails it shall return THREADAPI_ERROR. ]*/
        if (os_join_thread() == FAILURE)
        result = THREADAPI_ERROR;
        #endif

        if (res != NULL)
        {
            *res = (int)(intptr_t)threadResult;
        }

        /*Codes_SRS_THREADAPI_30_026: [ On success, ThreadAPI_Join shall return THREADAPI_OK. ]*/
        result = THREADAPI_OK;
    }

    return result;
}

void ThreadAPI_Exit(int res)
{
    (void)res;
    LogError("Exit is not supported.");
}

void ThreadAPI_Sleep(unsigned int milliseconds)
{
    /*Codes_SRS_THREADAPI_30_001: [ ThreadAPI_Sleep shall suspend the thread for at least the supplied value of milliseconds. ]*/
    os_sleep_us(milliseconds * 1000, OS_TIMEOUT_NO_WAKEUP);
}
