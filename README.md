# Python Speedport Hybrid Api
An unofficial python-api for the Speedport Hybrid CPE sold by Deutsche Telekom. The router is manufactured by Huawei and is used to bond LTE and DSL WAN-interfaces forming a hybrid access path.

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/The-Master777/HybridApi/master/LICENSE)

## Usage Example

**You can find more examples like [the one below](Examples/lteinfo.py) one in the [Examples](Examples) directory!**

  * Create a `SpeedportHybridApi`-instance and login using your *router web-ui password*.
  * Use an instance of the `BoxEndpointScraper` to access your favoured router-information resource

```python
from HybridApi import SpeedportHybridApi, BoxEndpointScraper

def getLteInfo():
    # api is your SpeedportHybridApi-instance
    # success determines whether the login has been successful or not
    # r contains extra information:
    #  - the session on success
    #  - failure information otherwise
    api, success, r = SpeedportHybridApi().login('* router web-ui password *')
    
    if not success:
        return 'Login failed'
    
    return BoxEndpointScraper(api).lteinfo.scrape()
```

## Supported Information-Resources
The following information resources (endpoint descriptors) are supported in the default configuration and can easily be accessed using the `BoxEndpointScraper`:

| Endpoint-Name  | Description                          | Session |
| -------------- | ------------------------------------ |:-------:|
| dsl            | DSL Connection and Line Status       |    ✔    |
| interfaces     | Network Interfaces                   |    ✔    |
| arp            | ARP Table                            |    ✔    |
| session        | PPPoE Session                        |    ✔    |
| dhcp_client    | DHCP Client status                   |    ✔    |
| dhcp_server    | DHCP Server and existing DHCP-Leases |    ✔    |
| ipv6           | IPv6 Router Advertisement            |    ✔    |
| dns            | DNS Information                      |    ✔    |
| routing        | Routing Table                        |    ✔    |
| igmp_proxy     | IGMP Proxy                           |    ✔    |
| igmp_snooping  | IGMP Snooping Table                  |    ✔    |
| wlan           | WLAN Information                     |    ✔    |
| module         | Software Version Information         |    ✔    |
| memory         | Memory and CPU Utilization           |    ✔    |
| speed          | Speed dial                           |    ✔    |
| webdav         | WebDAV URL                           |    ✔    |
| bonding_client | Bonding HA Client                    |    ✔    |
| bonding_tunnel | Bonding Tunnel                       |    ✔    |
| filterlist     | Filter List Table                    |    ✔    |
| bonding_tr181  | Bonding TR-181                       |    ✔    |
| lteinfo        | LTE Information                      |    ✔    |
| status         | Systemstatus                         |    ✘    |

