// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "azure_c_shared_utility/gballoc.h"
#include <kernel/os.h>
#include <time.h>
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/xlogging.h"

#define INVALID_TIME_VALUE      (time_t)(-1)

typedef struct TICK_COUNTER_INSTANCE_TAG
{
    clock_t last_clock_value;
    tickcounter_ms_t current_ms;
} TICK_COUNTER_INSTANCE;

TICK_COUNTER_HANDLE tickcounter_create(void)
{
    TICK_COUNTER_INSTANCE* result = (TICK_COUNTER_INSTANCE*)malloc(sizeof(TICK_COUNTER_INSTANCE));
    if (result != NULL)
    {

        result->last_clock_value = clock();
        /* T2 clock() has no error handelling, so no use of 'INVALID_TIME_VALUE' */

        result->current_ms = result->last_clock_value * 1000 / CLOCKS_PER_SEC;
    }
    return result;
}

void tickcounter_destroy(TICK_COUNTER_HANDLE tick_counter)
{
    if (tick_counter != NULL)
    {
        free(tick_counter);
    }
}

int tickcounter_get_current_ms(TICK_COUNTER_HANDLE tick_counter, tickcounter_ms_t * current_ms)
{
    int result;

    if (tick_counter == NULL || current_ms == NULL)
    {
        LogError("tickcounter failed: Invalid Arguments.");
        result = MU_FAILURE;
    }
    else
    {
        clock_t clock_value = clock();
        /* T2 clock() has no error handelling, so no use of 'INVALID_TIME_VALUE' */

        TICK_COUNTER_INSTANCE* tick_counter_instance = (TICK_COUNTER_INSTANCE*)tick_counter;
        tick_counter_instance->current_ms += (clock_value - tick_counter_instance->last_clock_value) * 1000 / CLOCKS_PER_SEC;
        tick_counter_instance->last_clock_value = clock_value;
        *current_ms = tick_counter_instance->current_ms;

        result = 0;
    }

    return result;
}
