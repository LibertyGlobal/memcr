# memory checkpoint and restore
memcr was written as a PoC to demonstrate that it is possible to temporarily reduce RSS of a target process without killing it. This is achieved by freezing the process, checkpointing its memory to a file and restoring it later when needed.

The idea is based on concepts seen in ptrace-parasite and early CRIU versions. The key difference is that the target process is kept alive and memcr manipulates its memory with madvise() MADV_DONTNEED syscall to reduce RSS. VM mappings are not changed.

#### how to use memcr
```
# memcr -p <target pid>
```
