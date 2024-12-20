# Azure IoT Hub Device Provisioning Service Sample

This Sample Application demonstrates the working of Talaria TWO devices with Device Provisioning Service (DPS) for Azure IoT Hub.
DPS is a helper service for IoT Hub that enables zero-touch, just-in-time provisioning to the right IoT hub without requiring human intervention. 
Transport used in the Sample is MQTT.

This Sample App demonstrates the device provisioning using Symmetric Key based attestation and X.509 CA Certificates based attestation.
More details about the attestation mechanism supported by Azure IoT Hub can be found [here](https://docs.microsoft.com/en-us/azure/iot-dps/concepts-service#attestation-mechanism).

## Creating Device Provisioning Service Resource

- Azure IoT Hub created in steps defined in the repo [README](../../../README.md#creating-an-azure-iot-device) document can be used here.
- Let's assume, for the example and document's logs showcase purposes that the Azure IoT Hub we created is named `InnoAzureIoTHub`.
- In the Azure portal, go for the option 'Create a resource'.
- Search for "device provisioning" and select `IoT Hub Device Provisioning Service`.
- Provide the details in the IoT Hub Device Provisioning Service form and click "Create" at the bottom.
- Then using this DPS resource, select `Linked IoT hubs` under `Settings` and click on `Add`.
- `Add link to IoT hub` option page will appear
	- in `IoT hub`: Select the IoT hub to be linked with this Device Provisioning Service instance. (created earlier.)
	- in `Access Policy`: Select `iothubowner`.

More details with the screenshots about creating a DPS service instance and linking it to a Hub can be found [here](https://docs.microsoft.com/en-us/azure/iot-dps/quick-setup-auto-provision).

## Provisioning using Symmetric Key based attestation

### Setting up DPS for Symmetric Key based device enrollment

- Select the `Manage Enrollments` tab under `Settings`, and then select the `Add individual enrollment` button at the top.

- In the `Add Enrollment` panel, enter the following information, and press the Save button.

	- `Mechanism`: Select "Symmetric Key" as the identity attestation Mechanism.

	- `Auto-generate keys`: Check this box.

	- `Registration ID`: Enter a registration ID to identify the enrollment. Use only lowercase alphanumeric and dash ('-') characters. For example, `InnoProvSymmKey`.

	- `IoT Hub Device ID`: Enter a device identifier. For example, `InnoProvSymmKey_Device-001`. A device of this name will be created when provisioning is successful.

	- `IoT Edge device` : Keep this as "False"

- Once this enrollment entity is saved, the Primary Key and Secondary Key will be generated and added to the enrollment entry. The symmetric key device enrollment entity appears as `InnoProvSymmKey` under the Registration ID column in the Individual Enrollments tab. (..or by whatever name you have given.)

- Click on this enrollment entity and copy the value of the generated Primary Key. This will be used later when preparing the code to run on Talaria TWO Device.

More details with the screenshots about these steps can be found [here](https://docs.microsoft.com/en-us/azure/iot-dps/quick-create-simulated-device-symm-key#create-a-device-enrollment-entry-in-the-portal).

### Device Configuration

For this method, we will need to populate `ID Scope`, `Registration ID` and `Symmetric Key` in the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/prov_dev_client_ll_sample.c`. 

In this file search for the function `prov_dev_client_ll_sample_run()`. Here you will find the code :

```
    // Set the symmetric key if using this auth type
    prov_dev_set_symmetric_key_info("<symm_registration_id>", "<symmetric_Key>");
```

From the [previous step](#Setting-up-DPS-for-Symmetric-Key-based-device-enrollment), we will use the `Registration ID` we provided and the `Primary Key` we copied
to populate this, as shown below for example -
```
    // Set the symmetric key if using this auth type
    prov_dev_set_symmetric_key_info("InnoProvSymmKey", "0IAggsc5RDa0Bwmkqos5vW90znNf5wl/bgFCO0ssTAI8sTA7UeWS8vgv9l+pEnzm8XVedo7pgcaOgD1k5Vu0RA==");
```

Now, copy the ID Scope of the Device Provisioning Service we created. This can be found on the Azure portal under the "Overview" section of DPS.

Then in the same file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/prov_dev_client_ll_sample.c`, searching for `id_scope` you will find the code :

```
static const char* id_scope = "XXXXXXXXXXX";
```
Now populate this with the value we just copied from our DPS.

For example
```
static const char* id_scope = "0ne001E4235";
```

Now, do a `make clean` and then run `make build_type=prov_build_with_symm_key` for generating `Azure IoT Hub Device Provisioning Service Sample` provisioning build with HSM_TYPE_SYMM_KEY.

### Trying out the example

Using Talaria TWO Download Tool, program the EVB-A with the example binary 'prov_dev_client_ll_sample.elf' giving the ssid and passphrase of your access point. No other boot arguments are needed to run this example. Details on how to use the Download Tool can be found in the repo [README](../../../README.md#creating-an-azure-iot-device) document.

After running the provisioning application successfully, in the Talaria TWO Console you will notice the logs detailed below :
- The device connects to the DPS server with the `ID Scope` and communicates with the enrollment entity named `Registration ID` we provided.

For the example names of IoT Hub, devices, DPS ID Scope and enrollment we used / created in this document, you will notice below logs among other appearing logs :
(Actual logs will reflect names of the Hub, devices, ID Scope and DPS enrollment you have actually used. Example logs provided here are just for reference.)

A connection with the username :
```
CONNECT
.
.
USERNAME: 0ne001E4235/registrations/InnoProvSymmKey/api-version=2019-03-31&ClientVersion=1.4.1
```

As provisioning proceeds the provisioning status logs appear :
```
.
.
Provisioning Status: PROV_DEVICE_REG_STATUS_CONNECTED
.
.
.
Provisioning Status: PROV_DEVICE_REG_STATUS_ASSIGNING
.
.
.
```
When registration completes, we receive details of where to connect Hub and newly created device name.

```
register_device_callback iothub_uri: InnoAzureIoTHub.azure-devices.net! device_id: InnoProvSymmKey_Device-001!

Registration Information received from service: InnoAzureIoTHub.azure-devices.net!
```
This means the DPS has successfully provisioned the device with the device name we gave at the enrollment form, on the IoT Hub the DPS is linked with.

After this, 
- the device disconnects from the DPS server 
- reconnects to the newly created device in the Hub 
- exchanges a few messages with this device just to confirm the connectivity.
- disconnects again.

Among other logs, you will notice the below exchanges in this reconnection part of the run to showcase the points listed above:

```
.
.
DISCONNECT

Creating IoTHub Device handle

Sending 1 message to IoTHub every 2 seconds for 2 messages (Send any message to stop)
.
.
CONNECT
.
.
USERNAME: InnoAzureIoTHub.azure-devices.net/InnoProvSymmKey_Device-001/?api-version=2019-10-01&DeviceClientType=iothubclient%2f1.4.1%20(Talaria%20TWO)
.
.
IoTHubClient_LL_SendEventAsync accepted message [1] for transmission to IoT Hub.
.
.
IoTHubClient_LL_SendEventAsync accepted message [2] for transmission to IoT Hub.
.
.
DISCONNECT

```

In the Azure IoT Hub portal, you will see the device `InnoProvSymmKey_Device-001` being added.

In the DPS Enrollment entity `InnoProvSymmKey` you will notice the created device details and timestamps being updated.

All this, means the provisioning using Symmetric Key based device enrollment, was successful.

## Provisioning using X.509 CA Certificates based attestation
Please note that X.509 based attestation is possible with RSA and ECC both options. For the detailed sequence, we will follow the ECC example.
However, most of the steps for both ECC and RSA attestation are exactly the same. The only difference is in the ECC and RSA specific OpenSSL commands we use for generating the key and the certificates.
Only these specific steps (which are different) are provided as a note towards the end of this section for the users to achieve DPS using RSA.

Refer [this azure documentation](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-x509ca-overview) to learn more about X.509 CA Certificates on Azure.

### Certificate Generation (ECC)
- For the example purpose, [OpenSSL](https://www.openssl.org/) will be used for certificate generation. [Download](https://www.openssl.org/source/) and install OpenSSL.
- Below commands are tested with Ubuntu machine. For other systems or packages other than OpenSSL, please check for the equivalent commands for similar operations as listed below.
- Make a new directory and copy the file `x509_config.cfg` from the path `<sdk_path>/apps/talaria_two_azure/tools/OpenSSL_ECC_Config/` to this newly created directory. Then use following steps:

	- Generate a Root CA private key

	```
	$ openssl ecparam -out rootCA.key -name prime256v1 -genkey
	```
	- Generate Root CA certificate:

	```
	$ openssl req -new -days 1024 -nodes -x509 -key rootCA.key -out rootCA.pem -config x509_config.cfg -subj "/CN=InnoRootCA_ECC"
	```
	All the parameters can be kept at defaults except Common Name (CN). Give any user-friendly common name to your root CA certificate.
    For this example we have given the name `InnoRootCA_ECC`
	
	- Generate private key for the Talaria TWO device. (Let's call the cert and key generated for device as leaf cert and leaf key):
	
	```
	$ openssl ecparam -out leaf_private_key.pem -name prime256v1 -genkey
	```
	- Generate Certificate Signing Request for the creating leaf cert for Talaria TWO device:

	```
	$ openssl req -new -key leaf_private_key.pem -out leaf.csr
	```
	All the parameters can be kept at defaults (by pressing enter) except Common Name (CN).

	**The Common Name to be given here should be the same as the intended name of the Enrollment Entity we want to create.**

	For this example's purpose, let's give CN as `InnoProvServiceECC`.

	- Generate device certificate (leaf certificate):
	```
	$ openssl x509 -req -in leaf.csr -CA rootCA.pem -CAkey rootCA.key -days 1024 -CAcreateserial -out leaf_certificate.pem
	```

### CA Certificate Registration on Azure IoT Hub

- In the previously created IoT Hub in the portal, select the `Certificates` tab under `Settings` in the menu bar, and click `Add`.
- Give a certificate name (eg `InnoPhaseCA_ECC`) and add the `rootCA.pem` which was created in the above steps, and click `Save`.
- It will show the certificate status to be "Unverified". 
- To verify this click on the certificate name to open the `Cetificates` pane. 
- Click on `Generate Verification Code` at the bottom. Copy the generated verification code. The screenshot for this step can be found [here](https://docs.microsoft.com/en-us/azure/iot-hub/tutorial-x509-prove-possession#verify-certificate-manually-after-upload).
- Using this verification code, we will provide the 'Proof of Possession' to prove that we own this certificate. For this we need to generate a 'verification certificate'.
- While generating the 'verification certificate', this verification code must be set as the certificate Common Name, as shown in the next step.
- As we are using OpenSSL to generate the certificates, we will generate a certificate signing request (CSR) using the `rootCA.key` private key in our possession.
- In the terminal, navigate to directory where `rootCA.pem` was created and run following command to generate a certificate signing request:

```
	$ openssl req -new -key rootCA.key -out verification.csr
```

All the parameters can be kept at defaults (by pressing enter) except Common Name (CN).

**Give the Verification Code copied in previous step as Common Name to make sure the certificate generated using the CSR will have this code as the Subject.**

- Generate Verification Certificate:

```
$ openssl x509 -req -in verification.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out verification_certificate.pem
```
- Now, Upload this certificate on the Azure Portal. and now It will show the certificate status to be "Verified".

### Setting up DPS for X.509 CA Certificates based device enrollment

- Select the `Manage Enrollments` tab under `Settings`, and then select the `Add individual enrollment` button at the top.
- In the `Add Enrollment` panel, enter the following information, and press the Save button.

	- `Mechanism`: Select "X.509" as the identity attestation Mechanism.

	- `Primary Certificate` : Upload device certificate created earlier (`leaf_certificate.pem`) in place of "Primary Certificate". Leave "Secondary Certificate" blank.

	- `IoT Edge device` : Keep this as "False"

	- `IoT Hub Device ID`: Enter a device identifier. For example, `InnoProvServiceECC_Device-001`. A device of this name will be created when provisioning is successful.

You will notice that an enrollment entity has been created with the same name we gave as the Common Name of the 'leaf.csr'. Eg `InnoProvServiceECC`.

### Device Configuration

For this method, we will need to populate 
- `ID Scope` in the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/prov_dev_client_ll_sample.c`
- `COMMON_NAME` in the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/custom_hsm.c`
- `leaf_cert_pem_start[]` and `leaf_pv_key_pem_start[]` in file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/certs/certs.c`

Copy the ID Scope of the Device Provisioning Service we created. This can be found on the Azure portal under the "Overview" section of DPS.

Then in the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/prov_dev_client_ll_sample.c`, searching for `id_scope` you will find the code :

```
static const char* id_scope = "XXXXXXXXXXX";
```
Now populate this with the value we just copied from our DPS.

For example
```
static const char* id_scope = "0ne001E4235";
```

The name of the Enrollment Entity we created in previous step is to be populated in below portion of file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/custom_hsm.c`.
```
static const char* const COMMON_NAME = "XXYYZZ";
```

For Example --

```
static const char* const COMMON_NAME = "InnoProvServiceECC";
```

In the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/certs/certs.c`, content of `leaf_cert_pem_start[]` and `leaf_pv_key_pem_start[]` are to be populated with the contents from 
`leaf_private_key.pem` and `leaf_certificate.pem` we created earlier.

The way to populate this is shown in the example file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/certs/ecc_example_certs.c`

Confirm that these needed changes are in place and files saved
Now, do a `make clean` and then run `make build_type=prov_build_with_x509` for generating `Azure IoT Hub Device Provisioning Service Sample` provisioning build with HSM_TYPE_X509.

### Trying out the example

Using Talaria TWO Download Tool, program the EVB-A with the example binary 'prov_dev_client_ll_sample.elf' giving the ssid and passphrase of your access point. No other boot arguments are needed to run this example. Details on how to use the Download Tool can be found in the repo [README](../../../README.md#creating-an-azure-iot-device) document.

After running the provisioning application successfully, in the Talaria TWO Console you will notice the logs detailed below :
- The device connects to the DPS server with the `ID Scope` and communicates with the enrollment entity named in `COMMON_NAME` of 'leaf.csr' we provided.

For the example names of IoT Hub, devices, DPS ID Scope and enrollment we used / created in this document, you will notice below logs among other appearing logs :
(Actual logs will reflect names of the Hub, devices, ID Scope and DPS enrollment you have actually used. Example logs provided here are just for reference.)

A connection with the username :
```
CONNECT
.
.
USERNAME: 0ne001E2330/registrations/InnoProvServiceECC/api-version=2019-03-31&ClientVersion=1.4.1
```

As provisioning proceeds the provisioning status logs appear :
```
.
.
Provisioning Status: PROV_DEVICE_REG_STATUS_CONNECTED
.
.
.
Provisioning Status: PROV_DEVICE_REG_STATUS_ASSIGNING
.
.
.
```
When registration completes, we receive details of where to connect Hub and newly created device name.

```
register_device_callback iothub_uri: InnoAzureIoTHub.azure-devices.net! device_id: InnoProvServiceECC_Device-001!

Registration Information received from service: InnoAzureIoTHub.azure-devices.net!
```
This means the DPS has successfully provisioned the device with the device name we gave at the enrollment form, on the IoT Hub the DPS is linked with.

After this, 
- the device disconnects from the DPS server 
- reconnects to the newly created device in the Hub 
- exchanges a few messages with this device just to confirm the connectivity.
- disconnects again.

Among other logs, you will notice the below exchanges in this reconnection part of the run to showcase the points listed above:

```
.
.
DISCONNECT

Creating IoTHub Device handle

Sending 1 message to IoTHub every 2 seconds for 2 messages (Send any message to stop)
.
.
CONNECT
.
.
USERNAME: InnoAzureIoTHub.azure-devices.net/InnoProvServiceECC_Device-001/?api-version=2019-10-01&DeviceClientType=iothubclient%2f1.4.1%20(Talaria%20TWO)
.
.
IoTHubClient_LL_SendEventAsync accepted message [1] for transmission to IoT Hub.
.
.
IoTHubClient_LL_SendEventAsync accepted message [2] for transmission to IoT Hub.
.
.
DISCONNECT

```

In the Azure IoT Hub portal, you will see the device `InnoProvServiceECC_Device-001` being added.

In the DPS Enrollment entity `InnoProvServiceECC` you will notice the created device details and timestamps being updated.

All this, means the provisioning using X.509 CA Certificate based device enrollment, was successful.

### Notes

#### RSA Specific OpenSSL key and cert generation steps

- In the example above, we have covered the OpenSSL commands for key and certificate generation for ECC. The equivalent steps and variations to achieve provisioning for the RSA is detailed below :

	- Generate a Root CA private key

	```
	$ openssl genrsa -out rootCA.key 4096
	```
	- Generate Root CA certificate:

	```
	$ openssl req -x509 -new -key rootCA.key -days 1024 -out rootCA.pem
	```
	All the parameters can be kept at defaults (by pressing enter) except Common Name (CN). Give any user-friendly common name to your root CA certificate.

    For this example we have given the name `InnoRootCA_RSA`
	
	- Generate private key for the Talaria TWO device. (Let's call the cert and key generated for device as leaf cert and leaf key):
	
	```
	$ openssl genrsa -out leaf_private_key.pem 4096
	```
	- Generate Certificate Signing Request for the creating leaf cert for Talaria TWO device:

	```
	$ openssl req -new -key leaf_private_key.pem -out leaf.csr
	```
	All the parameters can be kept at defaults (by pressing enter) except Common Name (CN).

	**The Common Name to be given here should be the same as the intended name of the Enrollment Entity we want to create.**

	For this example's purpose, let's give CN as `InnoProvServiceRSA`.

	Apart from the steps listed above, all the other steps (device configuration, enrollment etc) for RSA are exactly the same as what we followed for the ECC example.

	For example, using the 'leaf.csr' we just created in the above step, we will need to create `leaf_certificate.pem` following exactly the same way we used for the ECC example.

	- Generate device certificate (leaf certificate):
	```
	$ openssl x509 -req -in leaf.csr -CA rootCA.pem -CAkey rootCA.key -days 1024 -CAcreateserial -out leaf_certificate.pem
	```

	Now, following the next steps in same way as detailed in the ECC example and uploading this `leaf_certificate.pem`, the enrollment entity will be created with the name `InnoProvServiceRSA`.
	(as this is CN we gave in the RSA specific steps here.)

	Hence we will have to populate this name in `custom_hsm.c` now, as shown below :

	```
	static const char* const COMMON_NAME = "InnoProvServiceRSA";
	```
	We will have to use the content from `leaf_private_key.pem` and `leaf_certificate.pem` generated from RSA specific steps to populate the file--
	`<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/certs/certs.c`.
	(Similar to the way shown in the example file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/prov_dev_client_ll_sample/main/certs/rsa_example_certs.c`.)

	Please Note : All other steps not specifically detailed in this RSA specific section are exactly the same as already covered in the ECC example in great details.
	(for example populating `id_scope` in device config section, etc). Only the key and certificate generation and the names we use for examples are changed here.

	Eg, in this RSA example, in the enrollment step we can provide, `IoT Hub Device ID` filed: as, lets say,  `InnoProvServiceRSA_Device-001` reflecting the names we used specific to this RSA section.
	Then, all the logs will now reflect these changes when successful provisioning and device creation happens.

### Building the binaries for the Sample Apps

- For Provisioning builds
	- do a `make clean` and run `make build_type=prov_build_with_symm_key` for a provisioning build with HSM_TYPE_SYMM_KEY
	- do a `make clean` and run `make build_type=prov_build_with_x509` for a provisioning build with HSM_TYPE_X509
	- these 2 options create the binaries only for the `Azure IoT Hub Device Provisioning Service Sample`.

- Do a `make clean` and run `make` for the builds of `Azure IoT HUB Client Sample` and `Device Twin and Direct Method Sample`, which are NON Provisioning builds.

## Other Build time options

This sample code is made to enable trace and logs on runtime.
A build with no logging can be made enabling 'CFLAGS += -DNO_LOGGING' in Makefile. Disabling the logs this way will result in a smaller size binary.

In the sample application file, 'bool traceOn' can be set to 'false' to disable traces.

