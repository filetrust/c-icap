# ICAP Proof of Concept for Glasswall Developers
Glasswall Developers will have access to the private Glasswall Rebuild SDK. This allows the following steps to be used to install the Glasswall Rebuild SDK Shared library.

## Load the Glasswall SDK Submodule
```
git submodule init
git submodule update
```

## Install the SDK
To install the Glasswall SDK into the Linux run the Makefile in the repo's top level folder.
```
make gwinstall
```
This copies the Glasswall SDK into the `/user/lib` folder.