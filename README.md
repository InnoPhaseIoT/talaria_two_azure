# Azure IoT SDK C on InnoPhase Talaria TWO Platform

## Table of Contents

- [Introduction](#introduction)
- [Getting Started with the SDK](#get-started)
- [Creating an Azure IoT Device](#create-device)
- [Monitoring Results](#monitoring)
- [Releases](#releases)

## Introduction

<a name="introduction"></a>

[Azure IoT SDK C](https://github.com/Azure/azure-iot-sdk-c) is ported on Talaria TWO Software Development Kit as per the porting guidelines provided by Azure IoT SDK C.

Using this, the users can now start developing exciting [ultra-low power IoT solutions on Talaria TWO family of devices](https://innophaseinc.com/talaria-technology-details/), utilizing the power of the Azure IoT hub and services.

Sample Application codes covering D2C, C2D, DeviceTwin, Direct Methods and Device Provisioning Services are provided.

## Getting Started with the SDK

<a name="get-started"></a>

### Hardware

For evaluation and development, the Talaria TWO INP301x Development Kits can be used.

The kits use InnoPhase’s award-winning Talaria TWO Multi-Protocol Platform with ultra-low power Wi-Fi + BLE5 for wireless data transfer, an embedded Arm Cortex-M3 for system control and user 
applications and advanced security features for device safeguards. These eval boards contain INP101x modules based on Talaria TWO INP2045 SoC.
The kits include an Arduino UNO format baseboard with a Talaria TWO module attached and a different antenna option per kit. 

The EVB-A can be used in stand-alone mode or attached to an Arduino UNO compatible host or shield board. The baseboard has all module GPIOs accessible through either an internal 20-pin header or the 
Arduino connectors. Power is supplied from USB, host Arduino board or battery connector.

Also mounted on the baseboard are environmental sensors for capturing temperature, humidity, pressure and light. It is an ideal platform for developing exciting new battery-based, ultra-low power cloud connected 
products such as smart locks, smart sensors, or security and health monitoring devices.

A PC with Talaria TWO SDK development environment setup will be required to start tinkering and creating solutions.

A User Guide for setting up Talaria TWO EVB-A can be found in this link : [User-Guide-for-Talaria-TWO-EVB-A-Evaluation-Board](https://innophaseinc.com/wp-content/uploads/modules/User-Guide-for-Talaria-TWO-EVB-A-Evaluation-Board.pdf).
This has all the details needed for a successful setup, including description of components, power supply requirements, details of jumpers and the driver needed etc.


For More details about Talaria TWO family of devices, please visit links [INP101x Modules and INP301x Dev-Kits](https://innophaseinc.com/talaria-two-modules/), [INP2045 SoC](https://innophaseinc.com/talaria-two/) and [additional documentation](https://innophaseinc.com/talaria-two-modules/#doc).

The INP301x Dev Kits can be procured from [Mouser](https://www.mouser.com/manufacturer/innophase/) and [RichardsonRFPD](https://www.richardsonrfpd.com/Products/Search?searchBox=innophase&instockonly=false).

### Development Host Setup

A comprehensive User Guide: 'UG_Environment_Setup_for_Linux.pdf' is available covering how to set up the development environment for using Talaria TWO SDK on an Ubuntu VirtualBox based environment with a Windows 10 host. This document details installing the toolchain and necessary software packages required for the development, CLI commands for building target executables, programming the target and debugging of the application.

Alternatively, Talaria TWO SDK also supports the development using an Eclipse based IDE in Windows OS based PC. The details of setting up the development environment in Windows OS using the IDE is provided in User Guide: 'UG_Eclipse_Setup_Windows.pdf'. 

Talaria TWO SDK comes with above mentioned User Guides, an SDK API reference manual: 'Talaria TWO SDK API Reference Guide.pdf', various example applications, application notes and many reference applications and solution-ready applications with documents for the user to start the development targeting different use-cases.

Talaria TWO SDK is available through InnoPhase Customer Portal Access and is available after portal registration, Mutual Non-Disclosure Agreement (MNDA) and Development Tools License Agreement (DTLA).
For detailed information on registering and getting the SDK access along with the dev-environment setup documents, please follow this [customer portal link](https://innophaseinc.com/portal/customer-registration/).

### Compiling the Sample Apps
After setting up the development environments following the above mentioned links and documents, please follow the steps below to get started with Azure IoT SDK C Sample Apps:
- Create a new folder in any place and clone the 'talaria_two_azure' repo using below command.

``` bash
$ git clone --recursive https://github.com/InnoPhaseInc/talaria_two_azure.git
```

This repo uses [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) for it's dependencies. The option '--recursive' is required to clone the various git submodule repos (and their own eventual submodule dependencies) needed by 'talaria_two_azure' repo.


Once the clone is complete, move the folder 'talaria_two_azure' to the path `<sdk_path>/apps/`.

Then go to the directory 'talaria_two_azure' and run the below script. This needs to be done only once, after the clone is successful.
``` bash
<sdk_path>/apps/talaria_two_azure$ sh apply_t2_libc_compatibility_patches.sh
```

Once the above command is run successfully, running Make from here will create binaries in the path 'talaria_two_azure/out', explained below.

### Building the binaries for the Sample Apps
How to use Make to build binaries for different sample applications, is explained below

- For Provisioning builds
	- do a `make clean` and run `make build_type=prov_build_with_symm_key` for a provisioning build with HSM_TYPE_SYMM_KEY
	- do a `make clean` and run `make build_type=prov_build_with_x509` for a provisioning build with HSM_TYPE_X509
	- these 2 options create the binaries only for the `Azure IoT Hub Device Provisioning Service Sample`.

- Do a `make clean` and run `make` for the builds of `Azure IoT HUB Client Sample` and `Device Twin and Direct Method Sample`, which are NON Provisioning builds.

### Programming the Dev-Kits
'Talaria TWO Download Tool' is used for programming the EVB-A and using the Debug Console.
This tool is available for Windows and Linux platforms.
User Guide for this tool is available here: [Talaria-TWO-Download-Tool-User-Guide](https://innophaseinc.com/wp-content/uploads/modules/Talaria-TWO-Download-Tool-User-Guide.pdf).

The download tool can be [downloaded from this link](https://innophaseinc.com/talaria-two-modules#eval-software).

The Download Tool is found in the following folder in the Evaluation Software downloaded from  above link: 
: I-CUBE-T2-STW.zip\STM32CubeExpansion_T2-HostAPI-lib_V1.0\Utilities\PC_Software\TalariaTwo_DownloadTool\Tool_GUI


Sample Applications covering D2C, C2D, DeviceTwin, Direct Methods and Device Provisioning Services are provided in path 'talaria_two_azure/examples'.
Please follow the README.md of each individual example for the further details regarding programming and running these Sample Applications.

##

### Setting up Azure IoT Hub

- Follow the documentation ['Create an IoT hub using the Azure portal'](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-create-through-portal) to create an Azure IoT Hub and Devices.


> *Note: There is an option to select , F1: Free tier, when choosing the "Pricing and scale tier". For evaluation purpose, this should be enough to use.*

- After the device is created, open the device from the list in the IoT devices pane. Copy the Primary Connection String. This connection string is used by device code to communicate with the hub. This is also explained with the screenshot in the above link.

- Connection string - primary key sample:

```
"HostName=XXXXXXXXXXXXXXXX.azure-devices.net;DeviceId=YYYYYYYYYY;SharedAccessKey=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
```

### Setting up Azure CLI

- How to install and setup Azure Command Line Interface with Azure IoT Extensions is documented [here](https://docs.microsoft.com/en-us/azure/iot-hub/quickstart-send-telemetry-cli)
- This also explains the commands which can be used to create the resources and interact with the device.


## Monitoring Results

<a name="monitoring"></a>

To monitor various events / data being exchanged between the Talaria TWO device and Azure IoT hub, from PC command line, run the following command:

 `$ az iot hub monitor-events -n [IoTHub Name] --login '[Connection string - primary key]'`

Name and connection string of your IoT Hub will be needed as parameters for Azure this CLI command for monitoring the events of tha specific Hub.

The connection string of your IoT Hub can be found from the Azure Portal as detailed below: 
Click on your IoT Hub > Shared access policies > iothubowner > connection string-primary key > Copy to clipboard

Then use your Hub name and this connection string from the above step, in the Azure CLI command to start the monitoring.

Now run any of the sample applications on Talaria TWO to see the events monitored on Azure CLI.


## Releases

<a name="releases"></a>

New features and bug fixes are offered by both the SDKs (Talaria TWO SDK and Azure IoT SDC C).

When a new SDK for Talaria TWO is released, a release from this Repo will be made to support that.

Also, when a new LTS version is ported from Azure IoT SDC C, a release from this Repo will be made to support that.

Releases made from this Repo will be 'tagged-releases' and each release-tag will have the relevant info about respective Talaria TWO SDK version and Azure IoT C SDK LTS version supported by that particular release from this Repo.

### For Example

Tag "v1.0.0_TalariaTWO_SDK_2.3" has the folloing description --
```
builds with - 'Talaria TWO SDK 2.3'

based on - azure-iot-sdk-c - LTS_07_2020_Ref02
```
and

Tag "v1.1.0_TalariaTWO_SDK_2.4" has the folloing description --
```
builds with - 'Talaria TWO SDK 2.4'

based on - azure-iot-sdk-c - LTS_07_2020_Ref02
```
The versioning `vx.y.z_TalariaTWO_SDK_m.n.o` follows semantic versioning, vx.y.z. or major.minor.patch.

Supported Talaria TWO SDK version is added with a `_TalariaTWO_SDK_m.n.o` to `vx.y.z`.

A port to a newer LTS version from Azure IoT SDC C will bump the major version `x` and reset the minor version `y` and patch version `z` to 0.

A new TalariaTWO SDK Release support will bump the minor version `y` and reset the patch version `z` to 0, while the majot version `x` remains the same.

A critical bug fix will bump the patch version `z` only.


