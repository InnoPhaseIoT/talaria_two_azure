build_type=prov_build_with_symm_key

all:
	cd iothub_client_sample_mqtt/                               && $(MAKE) all
	cd iothub_devicetwin_and_methods_sample/                    && $(MAKE) all
	cd prov_dev_client_ll_sample/                               && $(MAKE) build_type=$(build_type)

clean:
	cd iothub_client_sample_mqtt/                               && $(MAKE) clean
	cd iothub_devicetwin_and_methods_sample/                    && $(MAKE) clean
	cd prov_dev_client_ll_sample/                               && $(MAKE) clean
