# memory checkpoint and restore

[![Build status](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-x86_64.yml/badge.svg)](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-x86_64.yml)
[![Build status](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-arm.yml/badge.svg)](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-arm.yml)
[![Build status](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-arm64.yml/badge.svg)](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-arm64.yml)
[![Build status](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-riscv64.yml/badge.svg)](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-riscv64.yml)
[![Build status](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-clang.yml/badge.svg)](https://github.com/LibertyGlobal/memcr/actions/workflows/ci-clang.yml)

memcr was written as a PoC to demonstrate that it is possible to temporarily reduce RSS of a target process without killing it. This is achieved by freezing the process, checkpointing its memory to a file and restoring it later when needed.

The idea is based on concepts seen in ptrace-parasite and early [CRIU](https://github.com/checkpoint-restore/criu) versions. The key difference is that the target process is kept alive and memcr manipulates its memory with `madvise()` `MADV_DONTNEED` syscall to reduce RSS. VM mappings are not changed.

#### building

```
make
```
##### compilation options
You can enable support for compression and checksumming of memory dump file:
 - `COMPRESS_LZ4=1` - requires liblz4
 - `CHECKSUM_MD5=1` - requires libcrypto and openssl headers

 There is also `ENCRYPT` option for building `libencrypt.so` that provides sample implementation of encryption layer based on libcrypto API. memcr is not linked with libencrypt.so, but it can be preloaded with `LD_PRELOAD`.
 - `ENCRYPT=1` - requires libcrypto and openssl headers

##### compilation on Ubuntu 22.04:
```
sudo apt-get install liblz4-dev liblz4-1
sudo apt-get install libssl-dev libssl3
```

```
make COMPRESS_LZ4=1 CHECKSUM_MD5=1 ENCRYPT=1
```

##### cross compilation
Currently, supported architectures are x86_64, arm, arm64 and riscv64. You can cross compile memcr by providing `CROSS_COMPILE` prefix. i.e.:
```
make CROSS_COMPILE=arm-linux-gnueabihf-
make CROSS_COMPILE=aarch64-linux-gnu-
```
##### yocto
There is a generic `memcr.bb` recipe provided that you can copy into your yocto layer and build memcr as any other packet with bitbake.
```
bitbake memcr
```

#### how to use memcr
Basic usage to tinker with memcr is:
```
memcr -p <target pid>
```
For the list of available options, check memcr help:
```
memcr [-h] [-p PID] [-d DIR] [-S DIR] [-l PORT|PATH] [-n] [-m] [-f] [-z] [-c] [-e] [-V]
options:
  -h --help             help
  -p --pid              target process pid
  -d --dir              dir where memory dump is stored (defaults to /tmp)
  -S --parasite-socket-dir      dir where socket to communicate with parasite is created
        (abstract socket will be used if no path specified)
  -G --parasite-socket-gid     group ID for parasite UNIX domain socket file, valid only for if --parasite-socket-dir provided,
                               note: the group ID provided need to be common for: the user running memcr daemon and the user running suspended process
  -N --parasite-socket-netns    use network namespace of parasite when connecting to socket
        (useful if parasite is running in a container with netns)
  -l --listen           work as a service waiting for requests on a socket
        -l PORT: TCP port number to listen for requests on
        -l PATH: filesystem path for UNIX domain socket file (will be created)
  -g --listen-gid       group ID for listen UNIX domain socket file, valid only in service mode for UNIX domain socket
  -n --no-wait          no wait for key press
  -m --proc-mem         get pages from /proc/pid/mem
  -f --rss-file         include file mapped memory
  -z --compress         compress memory dump
  -c --checksum         enable md5 checksum for memory dump
  -e --encrypt          enable encryption of memory dump
  -t --timeout          timeout in seconds for checkpoint/restore execution in service mode
  -V --version          print version and exit

```
memcr also supports client / server scenario where memcr runs as a daemon and listens for commands from a client process. The main reason for supporting this is that memcr needs rather high privileges to hijack target process and it's a good idea to keep it separate from memcr-client that can run in a container with low privileges.

memcr daemon:
```
sudo memcr -l 9000 -zc
```
memcr client:
```
memcr-client -l 9000 -p 1234567 --checkpoint
memcr-client -l 9000 -p 1234567 --restore
```
Due to high priviledges of the memcr daemon it is recommended to run memcr daemon process as non-root user with elevated Linux capabilities and permissions, the details are described in: [doc/security_considerations.md](doc/security_considerations.md)
