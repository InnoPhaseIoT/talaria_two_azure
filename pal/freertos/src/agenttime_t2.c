// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <time.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/agenttime.h"

/*Codes_SRS_AGENT_TIME_99_001: [ AGENT_TIME shall have the following interface ]*/
/* get_time() as C's time() and get_difftime() as C's difftime() */

/*Codes_SRS_AGENT_TIME_30_002: [ The time_t values in this interface shall be seconds since 00:00 hours, Jan 1, 1970 UTC. ]*/
/*Codes_SRS_AGENT_TIME_30_003: [ The get_gmtime, get_mktime, and get_ctime functions in are deprecated and shall not be used. ]*/

extern uint64_t t2_get_current_time();

time_t get_time(time_t* p)
{
    return t2_get_current_time();
}

struct tm* get_gmtime(time_t* currentTime)
{
    return gmtime(currentTime);
}

time_t get_mktime(struct tm* cal_time)
{
    return mktime(cal_time);
}

char* get_ctime(time_t* timeToGet)
{
    return ctime(timeToGet);
}

double get_difftime(time_t stopTime, time_t startTime)
{
    return difftime(stopTime, startTime);
}
