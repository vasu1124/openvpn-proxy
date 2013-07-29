
OpenVPN Intercepting Multiplexer/Proxy
============================================================

1. Installation
* Install Python,

    apt-get install python
	
* Install M2Crypto, 

    apt-get install python-m2crypto
	
* An Ubuntu System V type init script example is provided as oenvpn-proxy. Customize the script to your environment, place under /etc/init.d and activate.

2. Configuration
Keep an ovpnproxy.cfg file in the working directory with the following content:
```python
[Logging]
#Optionally, write to a rotating logfile:
# file = ovpnproxy.log
# maxBytes = 102400
# backupCount = 5
loglevel = DEBUG
#    The logging levels, in decreasing order of importance, are:
# CRITICAL = 50
# FATAL = CRITICAL
# ERROR = 40
# WARNING = 30
# WARN = WARNING
# INFO = 20
# DEBUG = 10
# DDEBUG = 5
# DDDEBUG = 4

[proxy]
# listen for incoming requests here 
ip = 0.0.0.0
port = 9999

[sinkvpn]
# this is your default vpn sink
ip = 172.19.136.144
port = 443 

# the follwoing sections represent the multiplexed VPN endpoints, 
# based on the subject.CN in the client certificate
# the subject.CN is specified as [section header]

[client1]
ip = 172.19.139.156
port = 443 

[client2]
ip = 172.19.139.157
port = 443 

# the config file is dynamic
```

3. License
Copyright (C) 2013 Vasu Chandrasekhara. All Rights Reserved.

