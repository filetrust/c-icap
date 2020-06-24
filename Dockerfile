FROM ubuntu as base
RUN apt-get update && apt-get upgrade -y && apt-get install -y libfreetype6

FROM base as build
RUN apt-get install -y curl gcc make automake automake1.11 unzip && \
    curl -L https://github.com/filetrust/c-icap/archive/master.zip --output /tmp/c-icap-master.zip
   
RUN cd /tmp && unzip -o c-icap-master.zip && cd /tmp && cd c-icap-master    
    
COPY ./Glasswall-Rebuild-SDK-Linux/SDK/libglasswall.classic.so /usr/lib
RUN echo "/usr/lib" > /etc/ld.so.conf.d/glasswall.classic.conf && ldconfig
    
RUN cd /tmp/c-icap-master/c-icap &&  \
    aclocal && autoconf && automake --add-missing && \
    ./configure --prefix=/usr/local/c-icap && make && make install
    
RUN cd /tmp/c-icap-master/c-icap-modules && \
    aclocal && autoconf && automake --add-missing && \
    ./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap && make && make install && \
    echo >> /usr/local/c-icap/etc/c-icap.conf && echo "Include gw_rebuild.conf" >> /usr/local/c-icap/etc/c-icap.conf
    
FROM base
COPY --from=build /usr/local/c-icap /usr/local/c-icap
COPY --from=build /run/c-icap /run/c-icap
COPY --from=build /usr/lib/libglasswall.classic.so /usr/lib/libglasswall.classic.so
COPY --from=build /etc/ld.so.conf.d/glasswall.classic.conf /etc/ld.so.conf.d/glasswall.classic.conf
EXPOSE 1344
#ENTRYPOINT ["/usr/local/c-icap/bin/c-icap"]
#CMD ["-N","-D"]
CMD ["/usr/local/c-icap/bin/c-icap","-N","-D"]