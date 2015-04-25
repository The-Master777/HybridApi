# Python Speedport Hybrid Api
An unofficial python-api for the Speedport Hybrid CPE sold by Deutsche Telekom. The router is manufactured by Huawei and is used to bond LTE and DSL WAN-interfaces forming a hybrid access path.

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/The-Master777/HybridApi/master/LICENSE)

## Usage Example
  * Create a `SpeedportHybridApi`-instance and login using your *router web-ui password*.
  * Use an instance of the `BoxEndpointScraper` to access your favoured router-information resource

```python
from EndpointScraper import BoxEndpointScraper
from HybridApi import SpeedportHybridApi

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
| -------------  | ------------------------------------ | -------:|
| dsl            | DSL Connection and Line Status       |    True |
| interfaces     | Network Interfaces                   |    True |
| arp            | ARP Table                            |    True |
| session        | PPPoE Session                        |    True |
| dhcp_client    | DHCP Client status                   |    True |
| dhcp_server    | DHCP Server and existing DHCP-Leases |    True |
| ipv6           | IPv6 Router Advertisement            |    True |
| dns            | DNS Information                      |    True |
| routing        | Routing Table                        |    True |
| igmp_proxy     | IGMP Proxy                           |    True |
| igmp_snooping  | IGMP Snooping Table                  |    True |
| wlan           | WLAN Information                     |    True |
| module         | Software Version Information         |    True |
| memory         | Memory and CPU Utilization           |    True |
| speed          | Speed dial                           |    True |
| webdav         | WebDAV URL                           |    True |
| bonding_client | Bonding HA Client                    |    True |
| bonding_tunnel | Bonding Tunnel                       |    True |
| filterlist     | Filter List Table                    |    True |
| bonding_tr181  | Bonding TR-181                       |    True |
| lteinfo        | LTE Information                      |    True |
| status         | Systemstatus                         |   False |

