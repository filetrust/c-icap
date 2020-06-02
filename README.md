# ICAP Proof of Concept
A demonstration that the Glasswall Rebuild SKD can be used within an ICAP service to regenerate documents.

## Getting started
The original baseline code has been cloned from the open source project
https://sourceforge.net/projects/c-icap/


## Installing C-ICAP

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

To install, the repo needs to be cloned on to the host server, running Linux.
```
git clone https://github.com/filetrust/c-icap.git
```

### Glasswall SDK

Copy the `libglasswall.classic.so` shared library into the `/user/lib` folder.
```
cp ./libglasswall.classic.so /user/lib
```

![Alternative instructions for Glasswall Developers](./README_GW.md)


#### Inform System about the Glasswall Rebuild SDK 
Once in place the library needs to be registered to make it accessible.
Create a glasswall.classic.conf file, with the installed location
```
echo "/usr/lib" > glasswall.classic.conf
```
Update the etc directory
```
sudo cp glasswall.classic.conf /etc/ld.so.conf.d
```
Run ldconfig to configure dynamic linker run-time bindings
```
sudo ldconfig
```

Check that the Glasswall library has been installed
```
sudo ldconfig -p | grep glasswall.classic
```
Remove the .conf file
```
rm glasswall.classic.conf
```

### Build the Server
From where the repo was cloned to, navigate into the `c-icap/c-icap` folder and run the script to setup the Makefiles.
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
The option is available to generate the documentation if required
```
make doc
```

### Build the Modules

Navigate to the modules folder (`c-icap/c-icap-modules`) and run the script to setup the Makefiles.
```
aclocal
autoconf
automake --add-missing
```
Run the configure script, specifing where the server was installed, in both the `with-c-icap` and `prefix` arguments.
```
./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap
```
After running the configuration script has been processed, we can compile and install
```
make 
sudo make install
```
> During the `make install` there will be some warnings about `libtools`, these can be ignored.

After installation, the configuration files for each module/service are available in the c-icap server configuration directory, `/usr/local/c-icap/etc/` using the location folder specified in the 'configure' commands above.  
These configuration files need to be included into the main c-icap server configuration file. The following command adds the `gw_test.conf` file
```
sudo sh -c 'echo "Include gw_test.conf" >>  /usr/local/c-icap/etc/c-icap.conf'
```

## Testing the Installation

On the host server run the ICAP Server with the following command
```
sudo /usr/local/c-icap/bin/c-icap -N -D -d 10
```

From a separate command prompt, run the client utility to send an options request
```
/usr/local/c-icap/bin/c-icap-client -s gw_test
```

Run the client utility sending a file through the ICAP Server.
```
/usr/local/c-icap/bin/c-icap-client -f <full path to source file>  -o <full path to output file> -s gw_test
```

