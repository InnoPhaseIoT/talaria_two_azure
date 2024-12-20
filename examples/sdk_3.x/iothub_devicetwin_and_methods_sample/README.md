# Device Twin and Direct Method Sample

This Sample Application demonstrates Device Twin and Direct Methods functionalities of Azure IoT Hub. Transport used is MQTT.


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

- open the file `<sdk_path>/apps/talaria_two_azure/examples/sdk_3.x/iothub_devicetwin_and_methods_sample/main/iothub_client_device_twin_and_methods_sample.c`

- In this file, populate the macro 'CONFIG_IOTHUB_CONNECTION_STRING' (shown below) with the connection string of your device copied in previous steps.

```
/* Paste in your iothub device connection string  */

define CONFIG_IOTHUB_CONNECTION_STRING "HostName=XXXXXXXXXXXXXXXX.azure-devices.net;DeviceId=YYYYYYYYYY;SharedAccessKey=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
```
With these changes in place, build the binaries as explained in the repo readme document.

Do a `make clean` and run `make` for generating the binaries for `Device Twin and Direct Method Sample`.

## Trying out the example


- Using Talaria TWO Download Tool, program the EVB-A with the example binary 'iothub_devicetwin_and_methods_sample.elf' giving the ssid and passphrase of your access point. No other boot arguments are needed to run this example. Details on how to use the Download Tool can be found in the repo [README](../../../README.md#creating-an-azure-iot-device) document.


After running the application, you can check updated properties by navigating to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Device Twin`
This is explained in more detail in section "Confirming the Update to Device Twin Reported Properties".

If you change the above set 'desired field' and click on "Save", the Talaria TWO Console output will reflect the desired values changed.
This is explained in more detail in section "Setting Device Twin Desired Properties".


## Device Twin

A car object with desired and reported properties is used in this example, as described in the JSON blob below.

```
Car: {
	"lastOilChangeDate": "<value>",            \\ reported property
		"changeOilReminder": "<value>",	           \\ desired property
		"maker": {                                 \\ reported property 
			"makerName": "<value>",
				"style": "<value>",
				"year": <value>
		},
		"state": {                                 \\ reported property
			"reported_maxSpeed": <value>,
			"softwareVersion": <value>,
			"vanityPlate": "<value>"
		},
		"settings": {                              \\ desired property
			"desired_maxSpeed": <value>,
			"location": {
				"longitude": <value>,
				"latitude": <value>
			},
		},
}
```

### Confirming the Update to Device Twin Reported Properties

Azure IoT device created in steps defined in the repo [README](../../../README.md#creating-an-azure-iot-device) document can be used here.

Before running this Sample Application, navigate to `Azure Portal` -> `your IoT Hub` -> `IoT Devices` -> `your IoT device` -> `Device Twin` and you will notice a default TWIN JSON similar to as shown below -

```
{
    "deviceId": "device-008",
    "etag": "AAAAAAAAAAE=",
    "deviceEtag": "Nzk2MDY4NTQw",
    "status": "enabled",
    "statusUpdateTime": "0001-01-01T00:00:00Z",
    "connectionState": "Connected",
    "lastActivityTime": "2021-06-24T22:54:07.3058159Z",
    "cloudToDeviceMessageCount": 0,
    "authenticationType": "sas",
    "x509Thumbprint": {
        "primaryThumbprint": null,
        "secondaryThumbprint": null
    },
    "modelId": "",
    "version": 2,
    "properties": {
        "desired": {
            "$metadata": {
                "$lastUpdated": "2021-06-24T22:53:59.4054559Z"
            },
            "$version": 1
        },
        "reported": {
            "$metadata": {
                "$lastUpdated": "2021-06-24T22:53:59.4054559Z"
            },
            "$version": 1
        }
    },
    "capabilities": {
        "iotEdge": false
    }
}

```

Once the Sample App is run, please notice the logs in the Talaria TWO Console output -
(Actual logs will reflect names of the Hub, devices you have actually used. Example logs provided here are just for reference.)

```
Device Twin reported properties update completed with result: 204

```
This output confirms that all the reported values we set through the Sample App, are now updated to Device TWIN Json.
In Azure Portal, refreshing the Device TWIN Json, will show the updated Json with reported values updated, similar to as shown below --

```
{
    "deviceId": "device-008",
    "etag": "AAAAAAAAAAE=",
    "deviceEtag": "Nzk2MDY4NTQw",
    "status": "enabled",
    "statusUpdateTime": "0001-01-01T00:00:00Z",
    "connectionState": "Connected",
    "lastActivityTime": "2021-06-24T22:54:07.3058159Z",
    "cloudToDeviceMessageCount": 0,
    "authenticationType": "sas",
    "x509Thumbprint": {
        "primaryThumbprint": null,
        "secondaryThumbprint": null
    },
    "modelId": "",
    "version": 3,
    "properties": {
        "desired": {
            "$metadata": {
                "$lastUpdated": "2021-06-24T22:53:59.4054559Z"
            },
            "$version": 1
        },
        "reported": {
            "lastOilChangeDate": "2016",
            "maker": {
                "makerName": "Fabrikam",
                "style": "sedan",
                "year": 2014
            },
            "state": {
                "reported_maxSpeed": 100,
                "softwareVersion": 1,
                "vanityPlate": "1I1"
            },
            "$metadata": {
                "$lastUpdated": "2021-07-25T20:41:49.2530365Z",
                "lastOilChangeDate": {
                    "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                },
                "maker": {
                    "$lastUpdated": "2021-07-25T20:41:49.2530365Z",
                    "makerName": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    },
                    "style": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    },
                    "year": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    }
                },
                "state": {
                    "$lastUpdated": "2021-07-25T20:41:49.2530365Z",
                    "reported_maxSpeed": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    },
                    "softwareVersion": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    },
                    "vanityPlate": {
                        "$lastUpdated": "2021-07-25T20:41:49.2530365Z"
                    }
                }
            },
            "$version": 2
        }
    },
    "capabilities": {
        "iotEdge": false
    }
}

```

### Setting Device Twin Desired Properties

Again navigating to `Azure Portal` -> `your IoT Hub` -> `IoT Devices` -> `your IoT device` -> `Device Twin` and paste the parts from the following JSON blob under `desired` property, so that the final desired part looks something like shown below. 

Please note that the $metadata part does not need to be copied, this is just for reference as for how the final 'desired' section will look.
Once the changes are made, click the 'Save' option.

```
        "desired": {
            "changeOilReminder": "LOW_OIL",
            "settings": {
                "desired_maxSpeed": 126,
                "location": {
                    "longitude": 72000000,
                    "latitude": 26000000
                }
            },
            "$metadata": {
                "$lastUpdated": "2021-06-26T00:06:52.9307518Z"
            },
            "$version": 1
        },

```


On the device console the below logs should occur -

```
Received a new changeOilReminder = LOW_OIL
Received a new desired_maxSpeed = 126
Received a new latitude = 26000000
Received a new longitude = 72000000

```


### Direct Method Invocation

Navigate to `Azure Portal` -> `your IoT Hub` -> `IoT devices` -> `your IoT device` -> `Direct Method`

Set the `Method Name` as `getCarVIN` and add some payload. Consider an example payload as below:

```
{ "message": "Hello World" }
```

On invoking the method, the invocation request will be sent to the IoT device, which in turn will respond with a payload like below:

```
{ "Response": "1HGCM82633A004352" }
```

## Build time options

This sample code is made to enable trace and logs on runtime.
A build with no logging can be made enabling 'CFLAGS += -DNO_LOGGING' in Makefile. Disabling the logs this way will result in a smaller size binary.

In the sample application file, 'bool traceOn' can be set to 'false' to disable traces.

