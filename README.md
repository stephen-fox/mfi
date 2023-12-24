# mfi

mfi controls the power state of an Ubiquiti mFi Power outlet.

## Features

- Enable or disable mFi device outlets by ID

## Usage

```
mfi -a <addr>:<port> -k <ssh-host-key> [options] <on|off|status>
```

## Examples

#### Turn the outlet on:

```
$ read -s MFI_DEVICE_PASSWORD
(.. type / paste device password)
$ export MFI_DEVICE_PASSWORD
$ mfi -a 192.168.3.200:22 -k 'mfi ssh-rsa AAAAB3...' on
```

#### Turn the outlet off:

```
$ mfi -a 192.168.3.200:22 -k 'mfi ssh-rsa AAAAB3...' off
```

#### Check outlet status:

```
$ mfi -a 192.168.3.200:22 -k 'mfi ssh-rsa AAAAB3...' status
```

## Installation

The preferred method of installation is using `go install` (as this is
a Golang application). This automates downloading and building Go
applications from source in a secure manner. By default, applications
are copied into `~/go/bin/`.

You must first [install Go](https://golang.org/doc/install). After installing
Go, run the following commands to install the application:

```sh
go install gitlab.com/stephen-fox/mfi@latest
```
