// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#include <stdlib.h>
#include <kernel/os.h>
#include <kernel/semaphore.h>
#include "azure_c_shared_utility/lock.h"
#include "azure_c_shared_utility/xlogging.h"

LOCK_HANDLE Lock_Init(void)
{
    /* Codes_SRS_LOCK_10_002: [Lock_Init on success shall return a valid lock handle which should be a non NULL value] */
    struct os_semaphore* result = (struct os_semaphore*) malloc(sizeof(struct os_semaphore));
    if (result == NULL)
    {
        LogError("malloc failed.");
        /* Codes_SRS_LOCK_10_003: [Lock_Init on error shall return NULL ] */
    }
    else
    {
        os_sem_init(result, 0);

        /* No error handelling possible with t2 Semaphores Init to do something like below */
        #if 0
        if (os_sem_init() == FAILURE)
        {
            /* Codes_SRS_LOCK_10_003: [Lock_Init on error shall return NULL ] */
            LogError("os_sem_init failed.");
            free(result);
            result = NULL;
        }
        #endif

    }

    return (LOCK_HANDLE)result;
}

LOCK_RESULT Lock(LOCK_HANDLE handle)
{
    LOCK_RESULT result;
    if (handle == NULL)
    {
        /* Codes_SRS_LOCK_10_007: [Lock on NULL handle passed returns LOCK_ERROR] */
        LogError("Invalid argument; handle is NULL.");
        result = LOCK_ERROR;
    }
    else
    {
        os_sem_wait((struct os_semaphore*)handle);

        /* No error handelling possible with t2 Semaphores os_sem_wait() to do something like below */
        #if 0
        if (os_sem_wait() == SUCCESS )
        {
            /* Codes_SRS_LOCK_10_005: [Lock on success shall return LOCK_OK] */
            result = LOCK_OK;
        }
        else
        {
            /* Codes_SRS_LOCK_10_006: [Lock on error shall return LOCK_ERROR] */
            LogError("os_sem_wait failed.");
            result = LOCK_ERROR;
        }
        #endif

        /* Codes_SRS_LOCK_10_005: [Lock on success shall return LOCK_OK] */
        result = LOCK_OK;
    }

    return result;
}

LOCK_RESULT Unlock(LOCK_HANDLE handle)
{
    LOCK_RESULT result;
    if (handle == NULL)
    {
        /* Codes_SRS_LOCK_10_007: [Unlock on NULL handle passed returns LOCK_ERROR] */
        LogError("Invalid argument; handle is NULL.");
        result = LOCK_ERROR;
    }
    else
    {
        os_sem_post((struct os_semaphore*)handle);

        /* No error handelling possible with t2 Semaphores os_sem_post() to do something like below */
        #if 0
        if (os_sem_post() == SUCCESS)
        {
            /* Codes_SRS_LOCK_10_009: [Unlock on success shall return LOCK_OK] */
            result = LOCK_OK;
        }
        else
        {
            /* Codes_SRS_LOCK_10_010: [Unlock on error shall return LOCK_ERROR] */
            LogError("os_sem_post failed.");
            result = LOCK_ERROR;
        }
        #endif

        /* Codes_SRS_LOCK_10_010: [Unlock on error shall return LOCK_ERROR] */
        result = LOCK_OK;
    }

    return result;
}

LOCK_RESULT Lock_Deinit(LOCK_HANDLE handle)
{
    LOCK_RESULT result;
    if (NULL == handle)
    {
        /* Codes_SRS_LOCK_10_013: [ Lock_Deinit on NULL handle passed returns LOCK_ERROR ] */
        LogError("Invalid argument; handle is NULL.");
        result = LOCK_ERROR;
    }
    else
    {
        /* CodesSRS_LOCK_10_012: [ Lock_Deinit frees all resources associated with handle ] */

        free(handle);
        handle = NULL;
        result = LOCK_OK;
    }

    return result;
}
