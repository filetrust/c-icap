GW_SO_LOCATION=./Glasswall-Rebuild-SDK-Linux/SDK
GW_SO_FILE=libglasswall.classic.so
GW_SO_VERSION=1.61

gwinstall:
	@echo Copying Glasswall SDK to $(ICAP_LOCATION)/lib/c-icap/
	cp $(GW_SO_LOCATION)/$(GW_SO_FILE) $(ICAP_LOCATION)/lib/c_icap/$(GW_SO_FILE).$(GW_SO_VERSION)
	ln -s $(ICAP_LOCATION)/lib/c_icap/$(GW_SO_FILE).$(GW_SO_VERSION) $(ICAP_LOCATION)/lib/c_icap/$(GW_SO_FILE)