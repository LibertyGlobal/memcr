# Security considerations

## socket communication

### parasite socket

The memcr uses a UNIX domain socket for communication between the parasite (code injected to the suspended process) and memcr utility/daemon, let's call it parasite_socket.
The parasaite_socket is a UNIX domain socket, and depends on the memcr options (`-S --parasite-socket-dir`) can be a named UNIX domain socket created in the pointed directory, or abstract UNIX domain socket.

Using abstract UNIX domain socket is more straightforward as do not require any option to memcr, or take care of the socket ownership and permissions, but it is less secure, as:
- the name/ID of the created socket is generated as: ***memcr\<pid of the suspended process\>*** so it is easy to guess,
- there is no user/permissions-based access control to abstract UNIX domain sockets, any user in the system can list them and connect to them if know the socket name.
It is recommended to not use abstract UNIX domain socket in a systems where security measures should be applied.

Access to UNIX domain socket file can be controlled by socket file node permissions and ownership. 
By default parasaite_socket is created as owned by the user  runnig the suspended process, with RW rights only for the owner. It is enough if memcr is run as root (so it can access any file).
If the system is configured to be more secure `-G --parasite-socket-gid` option may be specified for memcr to provide group ID which will own the parasite_socket with RW access to it. This is useful for the possible solutions where memcr is run as a non-root user with elevated Linux capabilities.

### restore socket

The restore socket is a UNIX domain socket used internally by memcr to communicate between main process and forked process watching the suspended process (one instance created per suspended process).
Analogically to the parasite_socket it is created as named UNIX domain socket (named ***memcrRestore\<pid of the suspended process\>***), or abstract UNIX domain socket depends on `-S --parasite-socket-dir` option.
The owner of the named UNIX domain socket is memcr effective user, permissions are set to RW for owner only.

### daemon socket

The second socket is created when memcr is run as a daemon (`-l --listen option`) and is used to send the commands to memcr daemon by memcr-client utility, let's call it daemon_socket.
The daemon_socket can be a UNIX domain socket created as a file node pointed by `-l` option, or TCP socket listening on port number defined with `-l` option.

For TCP socket, the access to the provided port can be controlled by a network access control mechanism (iptables).

For UNIX domain socket: it is named socket node, by default owned by effective UID and gid of the user running memcr, and having access permissions based on the umask set for the memcr process. (Note, that in most cases it means that running memcr daemon as root will require running memcr-client as root as well.)
Setting the chosen group ID with `-g --listen-gid` memcr option, the file group ownership is changed to the provided gid, and file node permission is set to RW for the owner and the group.
This way one can limit access to memcr daemon to the user(s) being part of the selected group. It is recommended to create a separate group for that purpose to strictly limit the access.

### examples

1. memcr daemon running as root with TCP daemon socket (port 9000), abstract UNIX domain sockets used for parasite and restore sockets:

```
sudo memcr -zc -l 9000
```

memcr client, run as non-root user, connects to TCP socket:

```
memcr-client -l 9000 -p <pid> --checkpoint
memcr-client -l 9000 -p <pid> --restore
```

> [!NOTE]
> no memcr daemon access control, no memcr internal sockets protection.

2. memcr daemon running as root with UNIX domain daemon socket, abstract UNIX domain sockets used for parasite and restore sockets:

```
sudo memcr -zc -l /tmp/memcr/memcr.sock

/tmp/memcr$ ls -l
total 0
srwxr-xr-x 1 root root 0 gru 31 19:35 memcr.sock
```

memcr client, run as root (to be able to connect to daemon), connects to UNIX domain socket:

```
sudo memcr-client -l /tmp/memcr/memcr.sock -p <pid> --checkpoint
sudo memcr-client -l /tmp/memcr/memcr.sock -p <pid> --restore
```

> [!NOTE]
> memcr daemon access control by /tmp/memcr/memcr.sock owner/permissions, no memcr internal sockets protection.

3. memcr daemon running as root with with UNIX domain daemon socket, UNIX domain sockets used for parasite and restore sockets, gid 1000 set for daemon and parasite sockets:

```
sudo memcr -zc -l /tmp/memcr/memcr.sock -g 1000 -S /tmp/memcr -G 1000

/tmp/memcr$ ls -l
total 0
srw-rw---- 1 root user 0 gru 31 19:38 memcr.sock
```

memcr client, run as non-root user, connects to UNIX domain socket (suspended process pid: 33239)

```
memcr-client -l /tmp/memcr/memcr.sock -p 33239 --checkpoint

/tmp/memcr$ ls -l
total 0
srw-rw---- 1 user user 0 gru 31 19:40 memcr33239
srw------- 1 root root 0 gru 31 19:40 memcrRestore33239
srw-rw---- 1 root user 0 gru 31 19:39 memcr.sock

memcr-client -l /tmp/memcr/memcr.sock -p 33239 --restore
```

> [!NOTE]
> memcr daemon access control by /tmp/memcr/memcr.sock owner/permissions, memcr parasite and restore sockets (memcr33239, memcrRestore33239) access control by sockets file node owner/permissions

## Linux capabilities/filesystem permissions required by memcr to operate

In order to run memcr as a non-root user it is required to grant to memcr process/user Linux capabilities and filesystem nodes permissions required for memcr operation. Information provided in this section should allow to run memcr (as daemon as well) as non-root, and make your system more secure. Another step recommended for even better security is to run memcr as a daemon in a sandbox, for example using switch root or Linux Container (LXC).

> [!CAUTION]
> Linux capabilities required to effectively freeze the process and dump its memory are real security threats - granting them to a non-root user running the memcr daemon process should be done carefully with a full understanding of the required changes and their consequences. It is recommended to create a separate user and group for memcr daemon, and selectively grant access to the /proc data of the suspended process by a dedicated group.

### CAP_SYS_PTRACE

memcr process does require Linux capability CAP_SYS_PTRACE to be able to call ptrace() in order to attach and control suspeneded process (see ptrace(2) and capabilities(7) for more infromation).

setcap command line utility can be used to set a memcr executable file capabilities attribute to the specified capability. This way the capability is granted by the OS to the process created by running such a file. (see setcap(8) / getcap(8) for more details).

```
$ sudo setcap 'cap_sys_ptrace=ep' ./memcr

$ getcap ./memcr
memcr cap_sys_ptrace=ep
```

### /proc access

memcr does require access to data in /proc

1. Read access to /proc/kpageflags node.

In most systems, by default it is allowed only: for root to read /proc/kpageflags.
The recommended solution here would be to add read (only) access for a dedicated group, and add only the user running memcr to this group.

2. Read/Write access to data in /proc/\<suspended process pid\>/:

* /proc/\<suspended process pid\>/maps
* /proc/\<suspended process pid\>/mem
* /proc/\<suspended process pid\>/ns/net
* /proc/\<suspended process pid\>/pagemap
* /proc/\<suspended process pid\>/status
* /proc/\<suspended process pid\>/task

This access is granted to the user running the particular process and its default group. The quickest solution would be to add the user running the memcr to the suspended process default group. Sometimes such a solution could be too "wide", for example when this group grants access to some other resources owned by this process, which are not suppoused to be available for memcr daemon. The generation of dedicated groups for this purpose could be a better solution. A careful analysis of each case is recommended.

> [!NOTE]
> To quickly test the memcr daemon working as non-root user memcr can be run as the same user as a process which will be suspended. In such a case it will be enough to grant the capability to the memcr file and access to /proc/kpageflags for the user used in the test.

