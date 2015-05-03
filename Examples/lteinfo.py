#!/usr/bin/env python
# -*- coding: utf-8 -*-

from HybridApi import SpeedportHybridApi, BoxEndpointScraper
import sys
import pprint

def getLteInfo(host='speedport.ip', password='* router web-ui password *'):
    print(host, password)
    # `api` is your SpeedportHybridApi-instance,
    # `success` determines whether the login has been successful or not,
    # `r` contains extra information:
    #   - the session on success
    #   - failure information otherwise
    api, success, r = SpeedportHybridApi(host).login(password)

    if not success:
        return ' 💥  | Login failed!'

    return BoxEndpointScraper(api).lteinfo.scrape()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('''Usage: ./HybridApi/Examples/lteinfo.py host password

Load LTE related information that is provided by the router.

* host:     The ip or hostname used to reach the CPE
* password: The password of the router\'s web-ui

Example Output:
‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
{
    'antenna_mode': 'Automatically select antenna, both antenna selete to external',
    'card_status': 'SIM OK',
    'cellid': '123',
    'device_status': 'Attached',
    'imei': '012345678901234',
    'imsi': '432109876543210',
    'rsrp': '-86',
    'rsrq': '-8',
    'service_status': 'Effective service',
    'tac': '1234'
}

''')
        sys.exit(1)

    data = getLteInfo(*sys.argv[1:])

    print(data)