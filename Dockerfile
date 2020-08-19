FROM ubuntu as base
RUN apt-get update && apt-get upgrade -y && apt-get install -y libfreetype6

FROM base as source
RUN apt-get install -y curl gcc make automake automake1.11 unzip && \
    cd /tmp && mkdir c-icap
COPY ./c-icap/ /tmp/c-icap/c-icap/
COPY ./c-icap-modules /tmp/c-icap/c-icap-modules  
COPY ./Glasswall-Rebuild-SDK-Evaluation/Linux/Library/libglasswall.classic.so /usr/lib
RUN echo "/usr/lib" > /etc/ld.so.conf.d/glasswall.classic.conf && ldconfig

FROM source as build    
RUN cd /tmp/c-icap/c-icap &&  \
    aclocal && autoconf && automake --add-missing && \
    ./configure --prefix=/usr/local/c-icap && make && make install
    
RUN cd /tmp/c-icap/c-icap-modules && \
    aclocal && autoconf && automake --add-missing && \
    ./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap && make && make install && \
    echo >> /usr/local/c-icap/etc/c-icap.conf && echo "Include gw_rebuild.conf" >> /usr/local/c-icap/etc/c-icap.conf
    
FROM base
COPY --from=build /usr/local/c-icap /usr/local/c-icap
COPY --from=build /run/c-icap /run/c-icap
COPY --from=build /usr/lib/libglasswall.classic.so /usr/lib/libglasswall.classic.so
COPY --from=build /etc/ld.so.conf.d/glasswall.classic.conf /etc/ld.so.conf.d/glasswall.classic.conf
EXPOSE 1344
CMD ["/usr/local/c-icap/bin/c-icap","-N","-D"]
