# ICAP Proof of Concept
A demonstration that the Glasswall Rebuild SDK can be used within an ICAP service to regenerate documents.

## Threat Model
[On-Premise Deployment](./Documentation/threat_model_onpremise.md)

## Creating Glasswall C-ICAP Docker Image
[How to create a Docker Image of the Glasswall ICAP Product](./Documentation/building_icap_docker_image.md)

## Getting started
The original baseline code has been cloned from the open source project
https://sourceforge.net/projects/c-icap/

## Installing ICAP PoC

These instructions guide the user through the steps involved in installing the Glasswall ICAP PoC on a Linux host.

Running the follow commands will ensure the necessary packages are installed.
```
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install git
sudo apt-get install gcc
sudo apt-get install -y doxygen
sudo apt-get install make
sudo apt-get install automake
sudo apt-get install automake1.11
```

To install, the repo needs to be cloned on to the host server.
```
git clone https://github.com/filetrust/c-icap.git
```

### Installing the Glasswall Rebuild SDK

Copy the `libglasswall.classic.so` shared library into the `/usr/lib` folder.
```
cp ./libglasswall.classic.so /usr/lib
```

![Alternative instructions for Glasswall Developers](./README_GW.md)


### Inform System about the Glasswall Rebuild SDK 
Once in place the library needs to be registered to make it accessible. Create a `glasswall.classic.conf` file, with the installed location
```
echo "/usr/lib" > glasswall.classic.conf
```
Update the `etc` directory
```
sudo cp glasswall.classic.conf /etc/ld.so.conf.d
```
Run `ldconfig` to configure the dynamic linker run-time bindings
```
sudo ldconfig
```

Check that the Glasswall library has been installed
```
sudo ldconfig -p | grep glasswall.classic
```
Remove the `.conf` file
```
rm glasswall.classic.conf
```

### Build the Server
From where the repo was cloned to, navigate into the `c-icap/c-icap` folder and run the scripts to setup the Makefiles.
```
aclocal
autoconf
automake --add-missing
```
Run the configure script, specifying where the server should be installed, through the `prefix` argument.
```
./configure --prefix=/usr/local/c-icap
```
After running the configuration script, build and install the server.
```
make 
sudo make install
```
The option is available to generate the documentation, if required
```
make doc
```

### Build the Modules

Navigate to the modules folder (`c-icap/c-icap-modules`) and run the scripts to setup the Makefiles.
```
aclocal
autoconf
automake --add-missing
```
Run the configure script, specifing where the server was installed, in both the `with-c-icap` and `prefix` arguments.
```
./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap
```
After running the configuration script, we can build and install
```
make 
sudo make install
```
> During the `make install` there will be some warnings about `libtools`, these can be ignored.

After installation, the configuration files for each module/service are available in the c-icap server configuration directory, `/usr/local/c-icap/etc/` using the location folder specified in the 'configure' commands above.  

For a module/service to be recognisd by the C-ICAP server its configuration file needs to be included into the main c-icap server configuration file. The following command adds the `gw_test.conf` file
```
sudo sh -c 'echo "Include gw_test.conf" >>  /usr/local/c-icap/etc/c-icap.conf'
```
Modules currently available for inclusion `gw_test.conf` or `gw_rebuild.conf`.

## Testing the Installation

On the host server run the ICAP Server with the following command
```
sudo /usr/local/c-icap/bin/c-icap -N -D -d 10
```

From a separate command prompt, run the client utility to send an options request. The module specified in the `-s` argument must have been `Included` into the `gw_test.conf` file in the step above.
```
/usr/local/c-icap/bin/c-icap-client -s gw_test
/usr/local/c-icap/bin/c-icap-client -s gw_rebuild
```

Run the client utility sending a file through the ICAP Server.
```
/usr/local/c-icap/bin/c-icap-client -f <full path to source file>  -o <full path to output file> -s gw_test
/usr/local/c-icap/bin/c-icap-client -f <full path to source file>  -o <full path to output file> -s gw_rebuild
```

A full list of the command line options available to the client utility are available from the application's `help` option.
```
/usr/local/c-icap/bin/c-icap-client  --help
```


