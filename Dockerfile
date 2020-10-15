FROM glasswallsolutions/k8-centos7:latest as base
RUN yum update && yum upgrade -y && yum install -y freetype*

FROM base as gwlib
COPY ./Glasswall-Rebuild-SDK-Evaluation/Linux/Library/libglasswall.classic.so /usr/lib
RUN echo "/usr/lib" > /etc/ld.so.conf.d/glasswall.classic.conf && ldconfig

FROM gwlib as source
RUN yum install -y curl gcc make libtool automake automake1.11 unzip && \
    cd /tmp && mkdir c-icap
COPY ./c-icap/ /tmp/c-icap/c-icap/
COPY ./c-icap-modules /tmp/c-icap/c-icap-modules  

FROM source as build    
RUN cd /tmp/c-icap/c-icap &&  \
    autoreconf -i -f && \
    ./configure --prefix=/usr/local/c-icap && make && make install
RUN cd /tmp/c-icap/c-icap-modules && \
    autoreconf -i -f && \
    ./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap && make && make install && \
    echo >> /usr/local/c-icap/etc/c-icap.conf && echo "Include gw_rebuild.conf" >> /usr/local/c-icap/etc/c-icap.conf

FROM gwlib
COPY --from=build /usr/local/c-icap /usr/local/c-icap
COPY --from=build /run/c-icap /run/c-icap
COPY --from=build /usr/lib/libglasswall.classic.so /usr/lib/libglasswall.classic.so
COPY --from=build /etc/ld.so.conf.d/glasswall.classic.conf /etc/ld.so.conf.d/glasswall.classic.conf
EXPOSE 1344
CMD ["/usr/local/c-icap/bin/c-icap","-N","-D"]
