// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/* This file contains minimalistic cert needed to communicate with Azure (IoT) */

#include "certs.h"

const char leaf_cert_pem_start[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBrzCCAVYCFCxHiM7qKpGi3xANa84Af4hOny6lMAoGCCqGSM49BAMCMFkxCzAJ\r\n"
"BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\r\n"
"dCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMMCWlubm9waGFzZTAeFw0yMTA2MTgw\r\n"
"MDAwMDlaFw0yMTA3MTgwMDAwMDlaMFwxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT\r\n"
"b21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTAT\r\n"
"BgNVBAMMDGlubm9Qcm92RFBTMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAmC\r\n"
"pDwTelx06G6x9qsO4+GwVgexhqJ/KpEKViBVAX9Iyvws+tKAzg6X55fmshPR1Ofg\r\n"
"FiqsvH7Ybt250BerJIcwCgYIKoZIzj0EAwIDRwAwRAIgFmHk/UL7Glr9f2bSvc3q\r\n"
"lPCBUnludhtCRIJDQ+pwd7YCIEB+zz6U3YKR//Omh19ObfiVPvQHr8k7MsrJwAyY\r\n"
"oEhd\r\n"
"-----END CERTIFICATE-----\r\n";

const char leaf_pv_key_pem_start[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIKYf89NYLIYzIK+J98FsVZEOg/hIM0XMZOo0Q5A8AKsxoAoGCCqGSM49\r\n"
"AwEHoUQDQgAECYKkPBN6XHTobrH2qw7j4bBWB7GGon8qkQpWIFUBf0jK/Cz60oDO\r\n"
"Dpfnl+ayE9HU5+AWKqy8fthu3bnQF6skhw==\r\n"
"-----END EC PRIVATE KEY-----\r\n";
