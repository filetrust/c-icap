# Building a Docker Image of the Glasswall ICAP Product
 
The following instructions provide a step by step guide on how to create a Docker Image of the Glasswall ICAP Server.

> The created Docker Image may be pushed to a Container Registry for later access. Since the image contains the licensed Glasswall SDK access to the Image **must** be restricted and **must** be available only within the constraints of the licensing agreement.
 
## Prerequisites
- If carrying out these steps on Windows, then Docker Desktop is required. Docker Desktop for Windows can be downloaded from [here](https://docs.docker.com/docker-for-windows/install/).
- The Glasswall SDK shared library has been made available.

## Retrieve the Glasswall ICAP Code
 
- Navigate to  https://github.com/filetrust/c-icap. 
- Download the ZIP file of the repo.
- Extract the content to your chosen location.
 
## Add the Glasswall SDK
- Navigate into the top level folder of the previous step.
- Create a folder `Glasswall-Rebuild-SDK-Linux`
- Within this folder create a folder `SDK`
- Copy the provided `libglasswall.classic.so` into the folder `Glasswall-Rebuild-SDK-Linux/SDK`

## Build the Image
- Build the Docker container using the following command (don't forget the . character at the end)
```
docker build -t gw-icap:latest .
```

## Run the Container
```
docker run -d -p 1300:1344 --name gw-icap gw-icap:latest
```
This command will run the image in a detached mode, routing traffic from port 1300 of the host to port 1344 of the image. A different host port may be used, but it must be associated with port 1344 of the running image.

To stop the container
```
docker stop gw-icap 
``` 