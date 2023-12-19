TOP=../../../../..
TOP := $(abspath $(TOP))
-include $(TOP)/embedded_apps.mak
SDK_DIR ?= $(TOP)
ROOT_DIR := $(SDK_DIR)

# basic rules and variables
include $(ROOT_DIR)/build/rules.mak
include $(TOP)/build.mak

LIBS = -lwifi -lrfdrv -llwip2 -lmbedtls -lsupplicant -ldragonfly -lfreertos
LIBS += -lazure_iot_sdk_t2 -lazure_iot_sdk_t2_pal -lcomponents


all:
	$(MAKE) libcomponents
	$(MAKE) $(create_azure_iot_libs)
	$(MAKE) $(TARGETS)

create_azure_iot_libs= create_lib_folder $(addprefix $(OUTDIR)/,$(azure_iot_libs))

lib_azure_iot_sdk_t2_path=lib/azure_iot_sdk_t2/
lib_azure_iot_sdk_t2_pal_path=lib/azure_iot_sdk_t2_pal/

azure_iot_libs = \
        ${lib_azure_iot_sdk_t2_path}/libazure_iot_sdk_t2.a \
        ${lib_azure_iot_sdk_t2_pal_path}/libazure_iot_sdk_t2_pal.a

create_lib_folder:
	mkdir -p $(OUTDIR)/${lib_azure_iot_sdk_t2_path}
	mkdir -p $(OUTDIR)/${lib_azure_iot_sdk_t2_pal_path}


T2AZURE_LOC = $(TOP)/apps/talaria_two_azure
$(info T2AZURE_LOC=$(T2AZURE_LOC))
azure_sdk_c-utility_src=$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/src/
azure_sdk_c-utility_pal=$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/pal/
azure_sdk_c-utility_adapters=$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/adapters/
azure_sdk_iothub_client=$(T2AZURE_LOC)/azure-iot-sdk-c/iothub_client/src/
azure_sdk_serializer=$(T2AZURE_LOC)/azure-iot-sdk-c/serializer/src/
azure_sdk_parson=$(T2AZURE_LOC)/azure-iot-sdk-c/deps/parson/
azure_sdk_uhttp=$(T2AZURE_LOC)/azure-iot-sdk-c/deps/uhttp/src/
azure_sdk_umqtt=$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/src/
azure_sdk_provisioning_client_src=$(T2AZURE_LOC)/azure-iot-sdk-c/provisioning_client/src/
azure_sdk_provisioning_client_adapters=$(T2AZURE_LOC)/azure-iot-sdk-c/provisioning_client/adapters/
azure_sdk_provisioning_client_deps=$(T2AZURE_LOC)/azure-iot-sdk-c/provisioning_client/deps/utpm/deps/c-utility/src/

azure_sdk_pal=$(T2AZURE_LOC)/pal/freertos/src/

commonIncs = \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/pal/generic \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/umock-c/inc\
        -I$(T2AZURE_LOC)/pal/freertos/inc

iotclientIncs = \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/iothub_client/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/umock-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/deps/parson \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc/azure_umqtt_c

serializerIncs = \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/serializer/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/umock-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/iothub_client/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/deps/parson

umqttIncs = \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/umock-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc/azure_umqtt_c

provClientIncs = \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/provisioning_client/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/azure-macro-utils-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/c-utility/deps/umock-c/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/provisioning_client/adapters \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/uamqp/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/deps/parson \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/deps/uhttp/inc \
        -I$(T2AZURE_LOC)/azure-iot-sdk-c/umqtt/inc/azure_umqtt_c

sdk_include = \
        -I$(TOP)/components/utils/inc \
        -I$(SDK_DIR)/include \
        -I$(SDK_DIR)/include/arm \
        -I$(SDK_DIR)/include/libc/include \
        -I$(SDK_DIR)/FreeRTOS-Kernel/include \
        -I$(SDK_DIR)/FreeRTOS-Kernel/portable/GCC/ARM_CM3 \
        -I$(SDK_DIR)/include/innos_osal/inc \
        -I/usr/gcc-arm-none-eabi-10.3-2021.10/arm-none-eabi/include

CFLAGS +=${sdk_include}
CFLAGS +=${commonIncs}
CFLAGS +=${iotclientIncs}
CFLAGS +=${serializerIncs}
CFLAGS +=${umqttIncs}
CFLAGS +=${provClientIncs}
CFLAGS +=-Iazure-iot-sdk-c/c-utility/pal/generic

##### must use this option if http transport is not supported #####
##### bulding sdk for PC, the cmake build autoenables this if the http is disabled #####
CFLAGS += -DDONT_USE_UPLOADTOBLOB

##### enabling this will make a less sized release build and logging will be disabled #####
#CFLAGS += -DNO_LOGGING


#### CPPFLAGS provisioning section #####

ifeq ($(build_type),prov_build_with_symm_key)

CPPFLAGS += -DUSE_PROV_MODULE
CPPFLAGS += -DHSM_TYPE_SYMM_KEY
#CPPFLAGS += -DHSM_TYPE_X509
#CPPFLAGS += -DHSM_TYPE_SAS_TOKEN

else

    ifeq ($(build_type),prov_build_with_x509)
    CPPFLAGS += -DUSE_PROV_MODULE
    #CPPFLAGS += -DHSM_TYPE_SYMM_KEY
    CPPFLAGS += -DHSM_TYPE_X509
    #CPPFLAGS += -DHSM_TYPE_SAS_TOKEN

    else
    # any other flag specific to sample 1 and sample 2 can be kept here.
    endif
endif


CFLAGS += -Wno-maybe-uninitialized
$(info CFLAGS = $(CFLAGS))
#SRCS_C_UTIL
azure_iot_srcs_c_util = \
        ${azure_sdk_c-utility_src}azure_base32.o \
        ${azure_sdk_c-utility_src}azure_base64.o \
        ${azure_sdk_c-utility_src}buffer.o \
        ${azure_sdk_c-utility_src}consolelogger.o \
        ${azure_sdk_c-utility_src}constbuffer.o \
        ${azure_sdk_c-utility_src}crt_abstractions.o \
        ${azure_sdk_c-utility_src}doublylinkedlist.o \
        ${azure_sdk_c-utility_src}gballoc.o \
        ${azure_sdk_c-utility_src}constmap.o \
        ${azure_sdk_c-utility_src}gb_stdio.o \
        ${azure_sdk_c-utility_src}gb_time.o \
        ${azure_sdk_c-utility_src}hmac.o \
        ${azure_sdk_c-utility_src}hmacsha256.o \
        ${azure_sdk_c-utility_adapters}linux_time.o \
        ${azure_sdk_c-utility_pal}tlsio_options.o \
        ${azure_sdk_c-utility_src}map.o \
        ${azure_sdk_c-utility_src}map.o \
        ${azure_sdk_c-utility_src}optionhandler.o \
        ${azure_sdk_c-utility_src}sastoken.o \
        ${azure_sdk_c-utility_src}sha1.o \
        ${azure_sdk_c-utility_src}sha224.o \
        ${azure_sdk_c-utility_src}sha384-512.o \
        ${azure_sdk_c-utility_src}singlylinkedlist.o \
        ${azure_sdk_c-utility_src}strings.o \
        ${azure_sdk_c-utility_src}string_tokenizer.o \
        ${azure_sdk_c-utility_src}string_token.o \
        ${azure_sdk_c-utility_src}urlencode.o \
        ${azure_sdk_c-utility_src}usha.o \
        ${azure_sdk_c-utility_src}vector.o \
        ${azure_sdk_c-utility_src}xio.o \
        ${azure_sdk_c-utility_src}http_proxy_io.o \
        ${azure_sdk_c-utility_src}xlogging.o

#SRCS_AZURE_SDK_PAL
azure_iot_srcs_pal = \
        ${azure_sdk_pal}tickcounter_t2.o \
        ${azure_sdk_pal}threadapi_t2.o \
        ${azure_sdk_pal}lock_t2.o \
        ${azure_sdk_pal}agenttime_t2.o \
        ${azure_sdk_pal}tlsio_t2.o \
        ${azure_sdk_pal}platform_t2.o \
        ${azure_sdk_pal}sntp.o \
        ${azure_sdk_pal}certs.o \
        ${azure_sdk_pal}t2_ntp.o

#SRCS_IOTHUB_CLIENT
azure_iot_srcs_iothub_client = \
        ${azure_sdk_iothub_client}iothub.o \
        ${azure_sdk_iothub_client}iothub_client_ll_uploadtoblob.o \
        ${azure_sdk_iothub_client}iothub_client_authorization.o \
        ${azure_sdk_iothub_client}iothub_client_diagnostic.o \
        ${azure_sdk_iothub_client}iothub_client_ll.o \
        ${azure_sdk_iothub_client}iothub_client_core_ll.o \
        ${azure_sdk_iothub_client}iothub_client_retry_control.o \
        ${azure_sdk_iothub_client}iothub_message.o \
        ${azure_sdk_iothub_client}iothub_transport_ll_private.o \
        ${azure_sdk_iothub_client}iothubtransport.o \
        ${azure_sdk_iothub_client}iothubtransportmqtt.o \
        ${azure_sdk_iothub_client}iothubtransport_mqtt_common.o \
        ${azure_sdk_iothub_client}version.o \
        ${azure_sdk_iothub_client}iothub_device_client_ll.o \
        ${azure_sdk_parson}parson.o

#SRCS_SERIALIZER
azure_iot_srcs_serializer = \
        ${azure_sdk_serializer}agenttypesystem.o \
        ${azure_sdk_serializer}codefirst.o \
        ${azure_sdk_serializer}commanddecoder.o \
        ${azure_sdk_serializer}datamarshaller.o \
        ${azure_sdk_serializer}datapublisher.o \
        ${azure_sdk_serializer}dataserializer.o \
        ${azure_sdk_serializer}iotdevice.o \
        ${azure_sdk_serializer}jsondecoder.o \
        ${azure_sdk_serializer}jsonencoder.o \
        ${azure_sdk_serializer}multitree.o \
        ${azure_sdk_serializer}methodreturn.o \
        ${azure_sdk_serializer}schema.o \
        ${azure_sdk_serializer}schemalib.o \
        ${azure_sdk_serializer}schemaserializer.o

#SRCS_UMQTT
azure_iot_srcs_umqtt = \
        ${azure_sdk_umqtt}mqtt_client.o \
        ${azure_sdk_umqtt}mqtt_codec.o \
        ${azure_sdk_umqtt}mqtt_message.o

#SRCS_PROVISIONING_CLIENT
azure_iot_srcs_provisioning_client = \
        ${azure_sdk_provisioning_client_src}prov_auth_client.o \
        ${azure_sdk_provisioning_client_src}iothub_auth_client.o \
        ${azure_sdk_provisioning_client_src}prov_security_factory.o \
        ${azure_sdk_provisioning_client_src}iothub_security_factory.o \
        ${azure_sdk_provisioning_client_src}prov_device_client.o \
        ${azure_sdk_provisioning_client_src}prov_device_ll_client.o  \
        ${azure_sdk_provisioning_client_src}prov_transport_mqtt_client.o \
        ${azure_sdk_provisioning_client_src}prov_transport_mqtt_common.o \
        ${azure_sdk_provisioning_client_adapters}hsm_client_data.o

libazure_iot_sdk_t2_OBJS := \
        $(addprefix $(OUTDIR)/,${azure_iot_srcs_c_util}) \
    	$(addprefix $(OUTDIR)/,${azure_iot_srcs_iothub_client}) \
        $(addprefix $(OUTDIR)/,${azure_iot_srcs_serializer}) \
	    $(addprefix $(OUTDIR)/,${azure_iot_srcs_umqtt}) \
        $(addprefix $(OUTDIR)/,${azure_iot_srcs_provisioning_client})

$(OUTDIR)/${lib_azure_iot_sdk_t2_path}/libazure_iot_sdk_t2.a: $(libazure_iot_sdk_t2_OBJS)
$(OUTDIR)/${lib_azure_iot_sdk_t2_path}/libazure_iot_sdk_t2.a: lib_objs = $(libazure_iot_sdk_t2_OBJS)
 
libazure_iot_sdk_t2_pal_OBJS := \
        $(addprefix $(OUTDIR)/,${azure_iot_srcs_pal})
 
$(OUTDIR)/${lib_azure_iot_sdk_t2_pal_path}/libazure_iot_sdk_t2_pal.a: $(libazure_iot_sdk_t2_pal_OBJS)
$(OUTDIR)/${lib_azure_iot_sdk_t2_pal_path}/libazure_iot_sdk_t2_pal.a: lib_objs = $(libazure_iot_sdk_t2_pal_OBJS)

#------------------------------------------------------Application-Specific Section------    ----------------------------------------------------#

# Reference -- add the application's code paths here 

APP := prov_dev_client_ll_sample.elf

app_src=$(T2AZURE_LOC)/examples/freertos/prov_dev_client_ll_sample/main

CFLAGS += -I${app_src}

# Reference -- linker directives
LDFLAGS += -L$(OUTDIR)/${lib_azure_iot_sdk_t2_path}
LDFLAGS += -L$(OUTDIR)/${lib_azure_iot_sdk_t2_pal_path}
LDFLAGS += --no-gc-sections 

# prov dev client ll sample app code
PROV_DEV_CLIENT_LL_SAMPLE_SRC_FILES +=  \
        ${app_src}/azure_main.o \
        ${app_src}/custom_hsm.o \
        ${app_src}/certs/certs.o \
        ${app_src}/prov_dev_client_ll_sample.o
 
PROV_DEV_CLIENT_LL_SAMPLE_OBJ_FILES := $(addprefix $(OUTDIR), $(PROV_DEV_CLIENT_LL_SAMPLE_SRC_FILES:%.c=%.o))
$(OUTDIR)/$(APP)   :  $(PROV_DEV_CLIENT_LL_SAMPLE_OBJ_FILES)

ALL_APPS := $(APP)
ALL_APPS := $(ALL_APPS) $(ALL_APPS:%.elf=%.elf.strip)
TARGETS  := $(addprefix $(OUTDIR)/,$(ALL_APPS))
#--------------------------------------------------------------------------------------------------------------------------------------------#

clean:
	rm -rf $(OUTDIR)

include $(BUILD_DIR)/sdk.mak
