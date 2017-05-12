# uNet for Linux

This document explains how to configure and run uNet on Linux.

This release supports:

* uNet entities and protocol as defined in the whitepaper "uNET: An Autonomous Network Architecture and Protocol For Modern Networks" version 19.
* Number of local and remote entities is only limited by available memory.
* Ethernet media type with a uNet specific protocol type.
* X.509 public key certificates and pcks8 private key format used.
* Certificate validation against trust chain.
* Encryption per link supported, AES + GCM for data transfer.
* Fragmentation per hop when packet size exceeds MTU.
* Configuration via file based configfs interface and netlink socket interface for IP bridging configuration.
* Inspection of system state via file based sysfs attributes
* Userspace AF_UNET socket supported for direct uNet communication.
* Extensive debugging facilities, selected on runtime.

