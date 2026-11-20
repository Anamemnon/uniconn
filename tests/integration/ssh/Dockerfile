FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server \
    && adduser -D -s /bin/sh testuser \
    && echo "testuser:testpass" | chpasswd \
    && ssh-keygen -A

COPY sshd_config /etc/ssh/sshd_config
RUN /usr/sbin/sshd -t

EXPOSE 2222

CMD ["/usr/sbin/sshd", "-D", "-e"]
