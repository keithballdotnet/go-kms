# GO - Key Management Service

A REST based Key Management Service written in GO.

[![GoDoc](https://godoc.org/github.com/Inflatablewoman/go-kms?status.svg)](https://godoc.org/github.com/Inflatablewoman/go-kms)
[![Build Status](https://travis-ci.org/Inflatablewoman/go-kms.svg)](https://travis-ci.org/Inflatablewoman/go-kms)
[![Coverage Status](https://coveralls.io/repos/Inflatablewoman/go-kms/badge.svg)](https://coveralls.io/r/Inflatablewoman/go-kms)

## Install notes:

Add some missing things needed to build, pkcs11

```
sudo yum install libtool-ltdl-devel
```

Install softhsm2
```
sudo yum-config-manager --add-repo http://copr-fe.cloud.fedoraproject.org/coprs/pspacek/softhsm2/
sudo yum install softhsm2
```

Create a place to store the tokens

```
mkdir /home/keithball/Documents/tokens
```

Create/change config file to reflect new token location

```
# SoftHSM v2 configuration file

directories.tokendir = /home/keithball/Documents/tokens
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG
```

Create initial token...

```
export SOFTHSM2_CONF=$PWD/softhsm2.conf
softhsm2-util --init-token --slot 0 --label "My token 1"
```

Check it worked ok

```
softhsm2-util --show-slots
```


## Good resources:

### PKCS#11
https://github.com/miekg/pkcs11

http://www-01.ibm.com/support/knowledgecenter/linuxonibm/com.ibm.linux.z.lxce/lxce_linklib_object_samples.html

### HMS
https://www.opendnssec.org/
SofthHsm2 only supports RSA encryption: https://wiki.opendnssec.org/display/SoftHSM/v2+Requirements

https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2.0
http://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html
