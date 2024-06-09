# filter-reputation

**DO NOT USE, WORK IN PROGRESS, REPUTATION COMPUTATIONS ARE INCORRECT**

## Description
This filter implements a reputation mechanism for incoming SMTP sessions.


## Features
The filter currently supports:

- nothing


## Dependencies
The filter is written in Golang and doesn't have any dependencies beyond the Go extended standard library.

It requires OpenSMTPD 7.5.0 or higher, might work for earlier versions but they are not supported.


## How to install
Install using Go:
```
$ GO111MODULE=on go get github.com/poolpOrg/filter-reputation
$ doas install -m 0555 ~/go/bin/filter-reputation /usr/local/libexec/smtpd/filter-reputation
```

Alternatively, clone the repository, build and install the filter:
```
$ cd filter-reputation/
$ go build
$ doas install -m 0555 filter-reputation /usr/local/libexec/smtpd/filter-reputation
```

On Ubuntu the directory to install to is different:
```
$ sudo install -m 0555 filter-reputation /usr/libexec/opensmtpd/filter-reputation
```


## How to configure
The filter itself requires no configuration.

It must be declared in smtpd.conf and attached to a listener for sessions to go through the kicker:
```
filter "reputation" proc-exec "filter-reputation"

listen on all filter "reputation"
```
