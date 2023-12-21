# Azure IoT HUB Client Sample

This Sample Application demonstrates Device to Cloud (D2C) and Cloud to Device (C2D) functionality using Azure IoT Hub. Transport used is MQTT.


## Device Configuration
- Azure IoT device created in steps defined in the repo [README](../../../README.md#creating-an-azure-iot-device) document can be used here.
How to Make/build binaries for Talaria TWO Devices and how to install and use Azure CLI is also covered in this document already.

We have already noted down the connection string for the device.
Alternatively, the connection string for the device can be known using this command from Azure CLI:

``` bash
$ az iot hub device-identity show-connection-string -n [IoTHub Name] -d [Device ID]
```

Output will be similar to:
```
{
  "connectionString": "HostName=<azure-iot-hub-name>.azure-devices.net;DeviceId=<azure-iot-device-id>;SharedAccessKey=<base64-encoded-shared-access-key>"
}
```

- open the file `<sdk_path>/apps/talaria_two_azure/examples/inno_os/iothub_client_sample_mqtt/main/iothub_client_sample_mqtt.c`

- In this file, populate the macro 'EXAMPLE_IOTHUB_CONNECTION_STRING' (shown below) with the connection string of your device copied in previous steps.

```
/* This connection string needs to be changed according to the credentials of the user */
#define EXAMPLE_IOTHUB_CONNECTION_STRING "HostName=XXXXXXXXXXXXXXXX.azure-devices.net;DeviceId=YYYYYYYYYY;SharedAccessKey=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
```
With these changes in place, build the binaries as explained in the repo readme document.
Do a `make clean` and run `make` for generating the binaries for `Azure IoT HUB Client Sample`.

## Trying out the example

- Using Talaria TWO Download Tool, program the EVB-A with the example binary 'iothub_client_mqtt_sample.elf' giving the ssid and passphrase of your access point. No other boot arguments are needed to run this example. Details on how to use the Download Tool can be found in the repo [README](../../../README.md#creating-an-azure-iot-device) document.


- Azure CLI with IoT extension can be used for monitoring the events.

Name and connection string of your IoT Hub will be needed as parameters for Azure CLI command for monitoring the events of tha specific Hub.
(Please note that the connection string of the IoT Hub is different than the connection string of the device we used in previous step to configure in file 'iothub_client_sample_mqtt.c').

The connection string of your IoT Hub can be found from the Azure Portal as detailed below: 
Click on your IoT Hub > Shared access policies > iothubowner > connection string-primary key > Copy to clipboard

Then use your Hub name and this connection string from the above step, in the following Azure CLI command to start the monitoring:

```
$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'
```

- After the device gets the internet connectivity, publishing MQTT messages are published by the device. The Azure IoT monitor shell will capture it as below:
(Actual logs will reflect names of the Hub, devices you have actually used. Example logs provided here are just for reference.)

```
{
    "event": {
        "origin": "device1",
        "module": "",
        "interface": "",
        "component": "",
        "payload": "{\"deviceId\":\"myFirstDevice\",\"windSpeed\":15,\"temperature\":23,\"humidity\":69}"
    }
}
{
    "event": {
        "origin": "device1",
        "module": "",
        "interface": "",
        "component": "",
        "payload": "{\"deviceId\":\"myFirstDevice\",\"windSpeed\":13,\"temperature\":24,\"humidity\":64}"
    }
}
.
.
.

```

- MQTT messages to the device can also be sent using the following command:

```
$ az iot device c2d-message send -d [Device Id] -n [IoTHub Name] --data [Data_to_Send]
```
The Console output of the Download Tool will print the messages received by the Talaria TWO device as:

```
Received Message [1]
 Message ID: 635fd5a9-70a4-422f-9394-4cda9026c2e1
 Correlation ID: <null>
 Data: <<<Hello World>>> & Size=18
```
## Build time options

This sample code is made to enable trace and logs on runtime.
A build with no logging can be made enabling 'CFLAGS += -DNO_LOGGING' in Makefile. Disabling the logs this way will result in a smaller size binary.

In the sample application file, 'bool traceOn' can be set to 'false' to disable traces.

