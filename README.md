BOFs
==========

Build all BOFs:

```console
~$ curl -sS https://download.cobaltstrike.com/downloads/beacon.h -o beacon.h
~$ ./make_all.sh
```

## [SubscribeWNF](/SubscribeWNF)

Subscribes to WNF notifications for a number of seconds.

### Help

```
usage:    subscribe-wnf <NUMBER_OF_SECONDS_TO_LISTEN>
example:  subscribe-wnf 10
```

### References

- https://github.com/gtworek/PSBits/tree/master/WNF
- https://www.youtube.com/watch?v=oyshXuCH__w

## [BackdoorSCManager](/BackdoorSCManager)

Backdoors SCManager SDDL.

### Help

```
usage:    backdoor-scmanager <SDDL_TO_SET>
example:  backdoor-scmanager D:(A;;KA;;;WD)
```

### References

- https://twitter.com/0gtweet/status/1628720819537936386
