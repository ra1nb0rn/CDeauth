# CDeauth: A WiFi deauthentication tool written in C
Some time ago I a wrote a small tool in C for WiFi deauthentication that uses the libpcap library as a means to inject packets. Because it may be useful to someone, I published it on GitHub.

## Installation
Simply run the automated installation script ``./install.sh`` or look at the commands inside and run them manually. The script works on macOS and Linux distributions that use the package manager *apt*. On macOS, [Homebrew](https://brew.sh) has to be installed.

## Usage
```
CDeauth (WiFi deauthentication in C) - (C) by Dustin Born 2016-2019 :

Usage: ./CDeauth [-c client] [-a access_point] [-n number]
                 [-i interface] [-h]

-a access point   :  MAC address of access point
-c client         :  MAC address or target client
-h                :  Print this help screen
-i interface      :  The interface on which to send the packets on
-n number         :  A integer specifying how many packets to send
                     (-1 for unlimited)
A client MAC, an access point MAC and an interface has to be specified.

Example: ./CDeauth -c AA:BB:CC:DD:EE:FF -a FF:EE:DD:CC:BB:AA -i wlan0
```

**Note:** The specified interface has to be in *monitor mode* and CDeauth may have to be run as *root* user.

## Putting a Managed Interface into Monitor Mode
Let ``<interface>`` be your WiFi interface. To put it into monitor mode, run:
```
sudo ifconfig <interface> down
sudo iwconfig <interface> mode monitor
sudo ifconfig <interface> up
```
**Important:** In case this does not work, you may have to make sure that the interface is not connected to a network prior to running these commands.

Alternatively you can use ``airmon-ng`` from the [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) suite.

## License
CDeauth is licensed under the MIT license, see [here](https://github.com/DustinBorn/CDeauth/blob/master/LICENSE).
