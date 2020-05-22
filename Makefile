GW_SO_LOCATION=./Glasswall-Rebuild-SDK-Linux/SDK
GW_SO_FILE=libglasswall.classic.so
GW_SO_VERSION=1.61

gwinstall:
	@echo Copying Glasswall SDK to /usr/lib/
	cp $(GW_SO_LOCATION)/$(GW_SO_FILE) /usr/lib/$(GW_SO_FILE).$(GW_SO_VERSION)
	ln -s /usr/lib/$(GW_SO_FILE).$(GW_SO_VERSION) /usr/lib/$(GW_SO_FILE)