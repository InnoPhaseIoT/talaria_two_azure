// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include "azure_c_shared_utility/platform.h"
#include "tlsio_pal.h"
#include "sntp.h"

/*Codes_SRS_PLATFORM_30_000: [ The platform_init call shall perform any global initialization needed by the platform and return 0 on success. ]*/
/*Codes_SRS_PLATFORM_30_001: [ On failure, platform_init shall return a non-zero value. ]*/
int platform_init(void)
{
    /* Initialize sntp module.*/
    sntp_init();
    return 0;
}

/*Codes_SRS_PLATFORM_30_010: [ The platform_deinit call shall perform any global deinitialization needed by the platform. ]*/
void platform_deinit(void)
{
    sntp_stop();
}

STRING_HANDLE platform_get_platform_info(PLATFORM_INFO_OPTION options)
{
    return STRING_construct("(Talaria TWO)");
}

/*Codes_SRS_PLATFORM_30_020: [ The platform_get_default_tlsio call shall return the IO_INTERFACE_DESCRIPTION* for the platform's tlsio. ]*/
const IO_INTERFACE_DESCRIPTION* platform_get_default_tlsio(void)
{
    return tlsio_pal_get_interface_description();
}


