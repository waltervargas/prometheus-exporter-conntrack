# prometheus-exporter-conntrack

## Dependencies

sudo apt-get install libnetfilter-conntrack-dev libmicrohttpd-dev libjson-c-dev libmicrohttpd-dev

## Build

```
cc -o tcp_exporter tcp_exporter.c -lnetfilter_conntrack -ljson-c -lmicrohttpd
```

## Run

```
sudo setcap cap_net_admin,cap_net_raw=eip ./tcp_exporter
```

```
./tcp_exporter 
```

```
./tcp_exporter --log-json
```