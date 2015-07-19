#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The BoxEndpointScraper is used to load and parse resources provided by the web-api of the box.
The predefined default-resources access endpoints of router's the hidden engineer-menu as well as box-status
information resources."""


class BoxEndpointScraper(object):
	"""The BoxEndpointScraper is capable of loading information resources provided by the router's web-interface.
	After initialization the endpoints can be accessed using their name either via the Resources-property of an
	scraper-instance, or directly by accessing the endpoint's name.

	To load the resource `lteinfo` of an instance `scraper` you can either perform the scrape()-operation
	on the scrapers 'lteinfo'-property: scraper.lteinfo.scrape()
	or you access it's Resources-dictionary (scraper.Resources['lteinfo'].scrape()). In the same way you can
	iterate over known (or default) resources."""

	def __init__(self, api, uri = None, endpoints = None):
		"""Instantiate a new BoxEndpointScraper

		:param api: The api-instance to use
		:param uri: The endpoint-uri to bind to, or None if no bind target (default None)
		:param endpoints: The list of custom endpoint descriptors, or None if default endpoints should be used (default None)
		"""

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
			"""Instantiate a new ResourceDescriptor of a scraper using an endpoint descriptor

			:param scraper: The scraper to use
			:param epdict: The endpoint descriptor dictionary
			"""

			super(BoxEndpointScraper.ResourceDescriptor, self).__init__()

			self.Scraper       = scraper
			self.EndpointName  = epdict['file']
			self.Description   = epdict['description'] if 'description' in epdict else None
			self.RequiresLogin = epdict['login'] if 'login' in epdict else True
			self.IsJsonVar     = epdict['jsonvar'] if 'jsonvar' in epdict else False

		def scrape(self):
			"""Scrapes the resource and returns parsed JSON object"""

			uri = 'data/%s.json' % self.EndpointName

			return self.Scraper.scrape(uri, jsonvar = self.IsJsonVar, requiresLogin = self.RequiresLogin)

		@staticmethod
		def make(scraper, arr):
			"""Converts endpoint descriptors to a dictionary of ResourceDescriptors,
			Expects a list of dictionaries containing the fields al follows:
			* file: File-Name of the endpoint
			* description: A descriptive text (optional, default None)
			* login: Whether an active session is required or not (optional, default True)
			* jsonvar: Whether the response is encoded as JsonVar or plain JSON (optional, default False)

			:param scraper: The scraper to reference
			:param arr: The list of endpoint descriptors
			"""

			return {key: value for (key, value) in [(f['file'], BoxEndpointScraper.ResourceDescriptor(scraper, f)) for f in arr]}

		def __repr__(self):
			return '[%s: (%s,%s,%s) @%s]' % (self.EndpointName, self.RequiresLogin, self.IsJsonVar, self.Description[:20], self.Scraper)

	def scrape(self, uri=None, jsonvar=False, requiresLogin=True):
		"""Perform a request to the resource and parse response

		:param uri: The uri of the resource to scrape or None if bound uri should be used (default None)
		:param jsonvar: Whether to treat the response as JsonVar or not (default False)
		:param requiresLogin: Whether the resource requires an active session (default True)
		"""

		# Get uri to load
		uri = uri or self.Uri

		# Ensure it is not none
		assert uri is not None

		# Load and parse json-response
		json, r = self.Api.loadJson(uri, jsonvar=jsonvar, noSession=(not requiresLogin))

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
		# 'routing'-endpoint jsonvar may be broken: Mixed response content
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
		{ 'file': "overview",       'description': "Übersicht",                            'login': True,  'jsonvar': True  },
		{ 'file': "status",         'description': "Systemstatus",                         'login': False, 'jsonvar': True  },
		{ 'file': "securestatus",   'description': "Sicherheitsübersicht",                 'login': False, 'jsonvar': True  },
	]
