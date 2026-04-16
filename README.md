# Packet Logger using SDN Controller (Ryu)

This project implements a packet logger using the Ryu SDN controller. It captures packets from a Mininet network, extracts header information, identifies protocol types (ARP, ICMP, TCP, UDP), logs them to a file, and displays them in real time.

## Requirements

* Python **3.10**
* Ryu SDN Controller
* Mininet
* netcat (for TCP/UDP testing)

## Setup

### 1. Activate virtual environment

```bash
source ryu-env/bin/activate
```

### 2. Exempt GREENDNS
In the file ```~/ryu-env/bin/activate```, add ```export EVENTLET_NO_GREENDNS=yes```.
> using GREENDNS causes AttributeError: module 'collections' has no attribute 'MutableMapping' - compatibility issues with Python 3.10

### 3. Run the controller

```bash
ryu-manager packet_logger.py
```

### 4. Start Mininet (in a new terminal)

```bash
sudo mn --topo single,3 --controller=remote
```
> Single-switch topology (s1), 3 hosts (h1,h2,h3), --controller instructs mininet to use an external controller (which is Ryu!)

## Notes

* ARP packets are used for IP-to-MAC resolution
* Some IPv6 or multicast packets may appear as OTHER
* This was made for a Computer Networks project
