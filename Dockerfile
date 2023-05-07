FROM busybox:1.36

ARG BIN_FILE
ADD ${BIN_FILE} /

RUN mkdir -p /usr/local/share/busybox && echo "/bin/busybox sh" > /usr/local/share/busybox/sh && chmod +x /usr/local/share/busybox/sh
RUN addgroup -S bcrypt && adduser -S bcrypt -G bcrypt -s /usr/local/share/busybox/sh

USER bcrypt

VOLUME /home/bcrypt

ENTRYPOINT ["/bcrypt"]
