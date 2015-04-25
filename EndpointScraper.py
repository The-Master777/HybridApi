#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The BoxEndpointScraper is used to load and parse resources provided by the web-api of the box.
The predefined default-resources access endpoints of router's the hidden engineer-menu as well as box-status
information resources."""


class BoxEndpointScraper(object):
	"""The BoxEndpointScraper is capable of loading information resources provied by the router's web-interface.
	After initialization the endpoints can be accessed using their name either via the Resources-property of an
	scraper-instance, or directly by accessing the endpoint's name.

	To load the resource `lteinfo` of an instance `scraper` you can either perform the scrape()-operation
	on the scrapers 'lteinfo'-property: scraper.lteinfo.scrape()
	or you access it's Resources-dictionary (scraper.Resources['lteinfo'].scrape()). In the same way you can
	iterate over known (or default) resources."""

	def __init__(self, api, uri = None, endpoints = None):
		super(BoxEndpointScraper, self).__init__()

		# An api instance is required
		assert api is not None

		self.Api = api
		self.Uri = uri

		# If uri is given, initialization is finished
		if uri is not None:
			return

		# Initialize resource descriptors
		# Use known endpoints as default value
		endpoints = endpoints or BoxEndpointScraper._endpoints

		# Split resource- and plain endpoint descriptors
		epdef = [e for e in endpoints if isinstance(e, dict)]
		epres = [e for e in endpoints if isinstance(e, BoxEndpointScraper.ResourceDescriptor)]

		# Convert endpoint descriptors
		d = BoxEndpointScraper.ResourceDescriptor.make(self, epdef)

		# Append existing resource descriptors
		for ep in epres:
			d[ep.EndpointName] = ep

		# Make resources accessible:
		#  either using Resources-dictionary, 
		#  or as property of the scraper instance.
		#
		#  E.g. access `lteinfo`-resource via scraper.Resources['lteinfo']
		#   or scraper.lteinfo where `scraper` is an instance of this class.
		self.Resources = d
		self.__dict__.update(d)

	def __repr__(self):
		return '%s' % self.Api.Host

	class ResourceDescriptor(object):
		"""The ResourceDescriptor defines an endpoint that is accessed for scraping"""

		def __init__(self, scraper, epdict):
			super(BoxEndpointScraper.ResourceDescriptor, self).__init__()

			self.Scraper = scraper
			self.EndpointName = epdict['file']
			self.Description = epdict['description'] if 'description' in epdict else None
			self.RequiresLogin = epdict['login'] if 'login' in epdict else True
			self.IsJsonVar = epdict['jsonvar'] if 'jsonvar' in epdict else False

		def scrape(self):
			"""Scrapes the resource and returns parsed JSON object"""
			uri = 'data/%s.json' % self.EndpointName

			return self.Scraper.scrape(uri, jsonvar = self.IsJsonVar, requiresLogin = self.RequiresLogin)

		def __repr__(self):
			return '[%s: (%s,%s,%s) @%s]' % (self.EndpointName, self.RequiresLogin, self.IsJsonVar, self.Description[:20], self.Scraper)

		@staticmethod
		def make(scraper, arr):
			"""Converts an endpoint description to a ResourceDescriptor,
			Expects a list of dictionaries containing the fields al follows:
			  * file: File-Name of the endpoint
			  * description: A descriptive text (optional, default None)
			  * login: Whether an active session is required or not (optional, default True)
			  * jsonvar: Whether the response is encoded as JsonVar or plain JSON (optional, default False)"""

			return {key: value for (key, value) in [(f['file'], BoxEndpointScraper.ResourceDescriptor(scraper, f)) for f in arr]}

	def scrape(self, uri = None, jsonvar=False, requiresLogin=True):
		"""Perform a request to the resource and parse response"""

		# Get uri to load
		uri = uri or self.Uri

		# Ensure it is not none
		assert uri is not None

		# Check if there must be a valid session
		if requiresLogin:
			self.Api.enforceSession()

		# Load and parse json-response
		json, r = self.Api.loadJson(uri, jsonvar=jsonvar)

		return json

	# A list of known endpoint descriptors
	_endpoints = [
		{ 'file': "dsl",            'description': "DSL Connection and Line Status",       'login': True,  'jsonvar': False },
		{ 'file': "interfaces",     'description': "Network Interfaces",                   'login': True,  'jsonvar': False },
		{ 'file': "arp",            'description': "ARP Table",                            'login': True,  'jsonvar': False },
		{ 'file': "session",        'description': "PPPoE Session",                        'login': True,  'jsonvar': False },
		{ 'file': "dhcp_client",    'description': "DHCP Client status",                   'login': True,  'jsonvar': False },
		{ 'file': "dhcp_server",    'description': "DHCP Server and existing DHCP-Leases", 'login': True,  'jsonvar': False },
		{ 'file': "ipv6",           'description': "IPv6 Router Advertisement",            'login': True,  'jsonvar': False },
		{ 'file': "dns",            'description': "DNS Information",                      'login': True,  'jsonvar': False },
		# 'routing'-endpoint jsonvar is broken: Mixed response content
		{ 'file': "routing",        'description': "Routing Table",                        'login': True,  'jsonvar': False }, 
		{ 'file': "igmp_proxy",     'description': "IGMP Proxy",                           'login': True,  'jsonvar': False },
		{ 'file': "igmp_snooping",  'description': "IGMP Snooping Table",                  'login': True,  'jsonvar': False },
		{ 'file': "wlan",           'description': "WLAN Information",                     'login': True,  'jsonvar': False },
		{ 'file': "module",         'description': "Software Version Information",         'login': True,  'jsonvar': False },
		{ 'file': "memory",         'description': "Memory and CPU Utilization",           'login': True,  'jsonvar': False },
		{ 'file': "speed",          'description': "Speed dial",                           'login': True,  'jsonvar': False },
		{ 'file': "webdav",         'description': "WebDAV URL",                           'login': True,  'jsonvar': False },
		{ 'file': "bonding_client", 'description': "Bonding HA Client",                    'login': True,  'jsonvar': False },
		{ 'file': "bonding_tunnel", 'description': "Bonding Tunnel",                       'login': True,  'jsonvar': False },
		{ 'file': "filterlist",     'description': "Filter List Table",                    'login': True,  'jsonvar': False },
		{ 'file': "bonding_tr181",  'description': "Bonding TR-181",                       'login': True,  'jsonvar': False },
		{ 'file': "lteinfo",        'description': "LTE Information",                      'login': True,  'jsonvar': False },
		{ 'file': "status",         'description': "Systemstatus",                         'login': False, 'jsonvar': True  },
	]
