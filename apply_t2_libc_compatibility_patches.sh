#!/bin/bash
PLATFORM_TYPE=$(cat ../../build.mak | grep "INP_FREERTOS_SDK")
if [ "$PLATFORM_TYPE" = "BUILD_TYPE_FLAG = -DINP_FREERTOS_SDK" ]
then
    OS_TYPE=freertos
else
  OS_TYPE=inno_os
fi


PATCH_FILE_1_PATH=patches/$OS_TYPE/azure-iot-sdk-c.patch
PATCH_TARGET_1_PATH=azure-iot-sdk-c

PATCH_FILE_2_PATH=patches/$OS_TYPE/azure-iot-sdk-c_deps_parson.patch
PATCH_TARGET_2_PATH=azure-iot-sdk-c/deps/parson

PATCH_FILE_3_PATH=patches/$OS_TYPE/azure-iot-sdk-c_deps_uhttp.patch
PATCH_TARGET_3_PATH=azure-iot-sdk-c/deps/uhttp

PATCH_FILE_4_PATH=patches/$OS_TYPE/azure-iot-sdk-c_provisioning-client_deps_utpm_deps_c-utility.patch
PATCH_TARGET_4_PATH=azure-iot-sdk-c/provisioning_client/deps/utpm/deps/c-utility

PATCH_FILE_5_PATH=patches/$OS_TYPE/azure-iot-sdk-c_umqtt.patch
PATCH_TARGET_5_PATH=azure-iot-sdk-c/umqtt

PATCH_FILE_6_PATH=patches/$OS_TYPE/azure-iot-sdk-c_c-utility.patch
PATCH_TARGET_6_PATH=azure-iot-sdk-c/c-utility

PATCH_FILE_7_PATH=patches/$OS_TYPE/azure-iot-sdk-c_c-utility_deps_azure-macro-utils-c_inc_azure-macro-utils.patch
PATCH_TARGET_7_PATH=azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc/azure_macro_utils

ROOT_PATH="$PWD"
echo $ROOT_PATH

echo "...patching $ROOT_PATH/$PATCH_TARGET_1_PATH"
cd $ROOT_PATH/$PATCH_TARGET_1_PATH
git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_1_PATH

echo "...patching $ROOT_PATH/$PATCH_TARGET_2_PATH"
cd $ROOT_PATH/$PATCH_TARGET_2_PATH
git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_2_PATH

echo "...patching $ROOT_PATH/$PATCH_TARGET_3_PATH"
cd $ROOT_PATH/$PATCH_TARGET_3_PATH
git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_3_PATH

echo "...patching $ROOT_PATH/$PATCH_TARGET_4_PATH"
cd $ROOT_PATH/$PATCH_TARGET_4_PATH
git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_4_PATH

if [ "$PLATFORM_TYPE" != "BUILD_TYPE_FLAG = -DINP_FREERTOS_SDK" ]
then
    echo "...patching $ROOT_PATH/$PATCH_TARGET_5_PATH"
    cd $ROOT_PATH/$PATCH_TARGET_5_PATH
    git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_5_PATH
fi


echo "...patching $ROOT_PATH/$PATCH_TARGET_6_PATH"
cd $ROOT_PATH/$PATCH_TARGET_6_PATH
git apply --whitespace=nowarn  $ROOT_PATH/$PATCH_FILE_6_PATH

echo "...patching $ROOT_PATH/$PATCH_TARGET_7_PATH"
cd $ROOT_PATH/$PATCH_TARGET_7_PATH
git apply --whitespace=nowarn $ROOT_PATH/$PATCH_FILE_7_PATH

echo "...patching completed"
