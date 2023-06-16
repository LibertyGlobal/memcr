# memory checkpoint and restore
memcr was written as a PoC to demonstrate that it is possible to temporarily reduce RSS of a target process without killing it. This is achieved by freezing the process, checkpointing its memory to a file and restoring it later when needed.

The idea is based on concepts seen in ptrace-parasite and early CRIU versions. The key difference is that the target process is kept alive and memcr manipulates its memory with `madvise()` `MADV_DONTNEED` syscall to reduce RSS. VM mappings are not changed.

#### building

```
make
```
##### copmpilation options
You can enable support for compression and checksumming of memory dump file:
 - `COMPRESS_LZ4=1` - requires liblz4
 - `CHECKSUM_MD5=1` - requires libcrypto and openssl headers

Ubuntu 22.04:
```
sudo apt-get install liblz4-dev liblz4-1
sudo apt-get install libssl-dev libssl3
```

 ```
 make COMPRESS_LZ4=1 CHECKSUM_MD5=1
 ```

##### cross compilation
Currently supported architectures are x86_64, arm and arm64. You can cross compile memcr by providing CROSS_COMPILE prefix. i.e.:
```
make CROSS_COMPILE=arm-linux-gnueabihf-
make CROSS_COMPILE=aarch64-linux-gnu-
```
##### yocto
There is a generic `memcr.bb` file provided that you can copy into your yocto layer and build memcr as any other packet with bitbake.
```
bitbake memcr
```

#### how to use memcr
Basic usage to tinker with memcr is:
```
memcr -p <target pid>
```
For the list of available options check memcr help:
```
memcr [-p PID] [-d DIR] [-S DIR] [-l PORT|PATH] [-n] [-f] [-c]
options:
  -h --help             help
  -p --pid              target processs pid
  -d --dir              dir where memory dump is stored (defaults to /tmp)
  -S --parasite-socket-dir dirwhere socket to communicate with parasite is created
        (abstract socket will be used if no path specified)
  -l --listen           work as a service waiting for requests on a socket
        -l PORT: TCP port number to listen for requests on
        -l PATH: filesystem path for UNIX domain socket file (will be created)
  -n --no-wait          no wait for key press
  -m --proc-mem get pages from /proc/pid/mem
  -f --rss-file include file mapped memory
  -z --compress compress memory dump
  -c --checksum enable md5 checksum for memory dump
```
There is also support for client / server scenario where memcr runs as a deamon and listens for commands from a client process. The main reason for supporting this is that memcr needs rather high privileges to hijack target process and it's a good idea to keep it separate from client that can run in a container with low privileges.

memcr daemon:
```
sudo memcr -l 9000 -zc
```
memcr client:
```
memcr-client -l 9000 -p 1234567 --checkpoint
memcr-client -l 9000 -p 1234567 --restore
```
