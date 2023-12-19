// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROV_DEV_CLIENT_LL_SAMPLE_H
#define PROV_DEV_CLIENT_LL_SAMPLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* USER STEP: Ensure paths and common name of certificate are correct */
#define     X509_CERT    "/cert/device_cert.pem"
#define     X509_KEY     "/cert/device_key.pem"
#define     COMMON_NAME  "<CN of cert>"

int prov_dev_client_ll_sample_run(void);

#ifdef __cplusplus
}
#endif

#endif /* PROV_DEV_CLIENT_LL_SAMPLE_H */
