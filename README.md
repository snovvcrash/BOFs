BOFs
==========

Get `beacon.h`:

```console
~$ curl -sS https://download.cobaltstrike.com/downloads/beacon.h -o beacon.h
```

Build all the BOFs:

```console
~$ ./make_all.sh
```

Build a single BOF:

```console
~$ cp beacon.h <BOF_DIR> && cd <BOF_DIR>
~$ make
```

> **DISCLAIMER.** All information contained in this repository is provided for educational and research purposes only. The owner is not responsible for any illegal use of included code snippets.

## [BackdoorSCManager](/BackdoorSCManager)

Backdoors SCManager SDDL.

### Help

```
usage:    backdoor-scmanager <TARGET_HOST> <SDDL_TO_SET>
example:  backdoor-scmanager SRV01.megacorp.local D:(A;;KA;;;WD)
```

### References

- https://twitter.com/0gtweet/status/1628720819537936386

## [SubscribeWNF](/SubscribeWNF) (No Profit, Training Only)

Subscribes to [WNF notifications](https://www.youtube.com/watch?v=MybmgE95weo) for a number of seconds.

### Help

```
usage:    subscribe-wnf <NUMBER_OF_SECONDS_TO_LISTEN>
example:  subscribe-wnf 10
```

### References

- https://github.com/gtworek/PSBits/tree/master/WNF
- https://www.youtube.com/watch?v=oyshXuCH__w
