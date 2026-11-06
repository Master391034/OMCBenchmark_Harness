FROM alpine:3.23
RUN apk add --no-cache socat \
    && addgroup -S relay \
    && adduser -S -D -H -u 10002 -G relay relay
USER 10002:10002
EXPOSE 1234
ENTRYPOINT ["socat"]
CMD ["TCP-LISTEN:1234,bind=0.0.0.0,reuseaddr,fork", "TCP:host.docker.internal:1234"]
