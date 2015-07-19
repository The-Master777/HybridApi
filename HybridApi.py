#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unofficial python-api for the Speedport Hybrid CPE"""

import requests
import json
import hashlib
import re
from datetime import timedelta, datetime
# from pbkdf2 import PBKDF2 # Moved to SpeedportHybridApi._getDerivedKey()


class SpeedportHybridApi(object):
	"""An Api for the Speedport Hybrid's web interface"""

	def __init__(self, host=None, session=None):
		super(SpeedportHybridApi, self).__init__()

		# Initialize default values
		self.Host = host or 'speedport.ip'
		self.RequestParams = { 
			'timeout': 5, # Time out after 5s
		}
		self.Session = None

		if session is not None:
			# Session overwrites host
			if host is not None and host != session.Host:
				raise SpeedportHybridApi.ApiException('Cannot instantiate Api with diverging host and session configuration')

			session.apply(self)

	class ApiException(Exception):
		"""The baseclass for exceptions raised by SpeedportHybridApi"""

		def __init__(self, message, cause = None):
			super(SpeedportHybridApi.ApiException, self).__init__(message)

			self.Cause = cause

		def __repr__(self):
			s = str(super(SpeedportHybridApi.ApiException, self))

			return '%s' % s if self.Cause is None else '%s - Cause: %s' % (s, str(self.Cause))

		def __str__(self):
			if self.Cause is not None:
				return '%s > %s' % (self.message, self.Cause.message)

			return self.message

	class RequestException(ApiException):
		"""An exception to be risen if case of request-related problems"""
		def __init__(self, message, cause):
			super(SpeedportHybridApi.RequestException, self).__init__(message, cause)

	class SessionException(ApiException):
		"""An exception for session-related problems"""
		def __init__(self, message):
			super(SpeedportHybridApi.SessionException, self).__init__(message)

	class MissingSessionException(SessionException):
		"""An exception in case of a missing session"""
		def __init__(self):
			super(SpeedportHybridApi.MissingSessionException, self).__init__('The session has not been set and thus is missing')

	class JsonParserException(ApiException):
		"""An exception in case of parsing an invalid JSON string"""
		JsonString = None

		def __init__(self, jsonString, cause):
			super(SpeedportHybridApi.JsonParserException, self).__init__('Failed parsing JSON string', cause)
			self.JsonString = jsonString

	class ApiSession(object):
		"""A container for SpeedportHybridApi sessions"""

		def __init__(self, host, challenge, dk, sid, checktime=datetime.min):
			"""Instantiate a new session

			:param host: The host this session is bound to
			:param challenge: The challenge retrieved at login
			:param dk: The derived key
			:param sid: The session-id
			"""
			super(SpeedportHybridApi.ApiSession, self).__init__()

			self.Host = host
			self.Challenge = challenge
			self.DerivedKey = dk
			self.ID = sid

			# Validity check properties
			self.LastCheckTime = checktime

		def apply(self, api):
			"""Configure api-instance to use this session

			:param api: The api-instance that should be configured
			"""

			api.Host = self.Host
			api.Session = self

		def getNewApi(self):
			"""Create a new SpeedportHybridApi instance based on this session

			:rtype : SpeedportHybridApi
			"""
			return SpeedportHybridApi(session=self)

		def asList(self):
			"""Return session parameters in a list"""
			return [self.Host, self.Challenge, self.DerivedKey, self.ID]

		@staticmethod
		def _isTimedOut(reference, timeout):
			"""Check if there is more time than timeout (given in seconds) elapsed since reference

			:param reference: The reference point in time
			:param timeout: The number of seconds until timeout
			:rtype : Boolean
			"""

			delta = timedelta(seconds = timeout)

			# Prevent overflow if reference is > ( datetime.max - delta)
			if datetime.max - delta < reference:
				return False

			# Check timeout: If now is later than (last-time + delta), then there is an timeout!
			return datetime.utcnow() > reference + delta

		def isValid(self, api=None, timeout=5):
			"""Determine if the current session is still valid and cache result for specified number of seconds

			:param api: The api-instance to operate on, or None if api should be created on-the-fly
			:param timeout: The timeout in seconds used to cache old check-results
			"""

			# Check if last check is still valid and return True if it is
			if timeout > 0 and not SpeedportHybridApi.ApiSession._isTimedOut(self.LastCheckTime, timeout):
				return True

			# Get api-instance to work on
			api = api or self.getNewApi()

			# Check if logged in
			try:
				loginState, r = api.loadJson('data/login.json', jsonvar=True, noEnforceSession=True, expectMimeType=None)
				login = str(loginState['login'].Value).lower() in ['true']
			except Exception as e:
				#print(e)
				return False

			if not login:
				return False

			# Store time of check
			self.LastCheckTime = datetime.utcnow()

			return True

		def __str__(self):
			return 'Session at %s: SessionID_R3=%s; challengev=%s; derivedk=%s' % (self.Host, self.ID, self.Challenge, self.DerivedKey)

		def __repr(self):
			return '<%s>' % str(self)

	class JsonVar(object):
		"""A container for json-variables returned by the router-api"""
		def __init__(self, jsonVarObject):
			"""
			Instantiate a new JsonVar object. A container for JsonVar-variables.
			:param jsonVarObject: The JSON dictionary object used to create this container, having 'varid', 'varvalue', and 'vartype'
			"""
			super(SpeedportHybridApi.JsonVar, self).__init__()

			self.ID = jsonVarObject['varid']
			self.Value = jsonVarObject['varvalue']
			self.Type = jsonVarObject['vartype']

		def __str__(self):
			return self.Value

		def __repr__(self):
			return '[(JsonVar) "%s" [%s]: (%d) %s%s]' % (self.ID, self.Type, len(self.Value), self.Value[:20].__repr__(), ('..' if len(self.Value) > 20 else ''))

	@property
	def hasSession(self):
		"""Checks if there is a session-object associated"""
		return self.Session is not None

	def enforceSession(self, noSession=False, timeout=5.0):
		"""Checks if there is a valid session or raises an exception if not

		:param timeout: The timeout in seconds of the validity-cache
		"""

		# Don't care about session-existance if there is no need
		if noSession:
			return True

		# Check if there is a session associated
		if not self.hasSession:
			raise SpeedportHybridApi.MissingSessionException()

		# Check if the session is valid, cache result for `timeout`-seconds
		if not self.Session.isValid(api=self, timeout=timeout):
			raise SpeedportHybridApi.SessionException('The session is outdated and thus invalid')

		return True

	def _makeUrl(self, path, protocol='http'):
		"""Format a request url based on current Host and requested path

		:param path: The path of the url
		:param protocol: The protocol of the url
		"""
		return '%s://%s/%s' % (protocol, self.Host, path)
	
	_jsonMimeTypes = ['application/javascript', 'application/json']

	def loadJson(self, uri, jsonvar=False, expectCode=200, noSession=False, noEnforceSession=False, fix=True, expectMimeType=_jsonMimeTypes):
		"""Load JSON via a GET-request from given path. The HTTP-Status-Code expectCode is asserted. By default invalid json responses are fixed.

		:param uri: The url to load
		:param jsonvar: Whether the response should be treated as JsonVar or not (default False)
		:param expectCode: The expected HTTP-Status-Code (default 200)
		:param fix: Whether to fix the json-string or not (default True)
		:param expectMimeType: The expected response mime-type (default: application/javascript, application/json)
		"""

		# Construct params-dictionary
		params = {}
		headers = None

		# Add accept-header if needed
		if expectMimeType is not None:
			headers = {'Accept': ','.join(expectMimeType)}

		# Use default-parameters
		params.update(self.RequestParams)

		# Add headers to params if needed
		if headers is not None:
			params.update({'headers': headers})

		# Perform request
		try:
			r = self._getRequest(uri, expectCode=expectCode, noSession=noSession, noEnforceSession=noEnforceSession, ownParams=params)
		except Exception as e:
			raise SpeedportHybridApi.RequestException('failed to perform json-request', e)

		# Expect proper response type
		# Todo: Implement generic expectation-handler
		if expectMimeType is not None and r.headers['content-type'] not in expectMimeType:
			raise SpeedportHybridApi.RequestException('response contained unexpected mime-type', None)

		# Parse response
		try: 
			res = self._parseJsonResponse(r.text, fix=fix, isJsonVars=jsonvar)
		except Exception as e:
			raise SpeedportHybridApi.ApiException('parsing json response failed', e)

		return res, r # res is dict of JsonVar, r is request object

	def _performRequest(self, method, uri, params, expectCode, noSession, noEnforceSession):
		"""Perform a http request with specified characteristics"""

		if not noEnforceSession:
			self.enforceSession(noSession)

		url = self._makeUrl(uri)

		# Set cookie-header if needed
		if 'cookies' not in params and not noSession:
			params['cookies'] = {'challengev': self.Session.Challenge, 'derivedk': self.Session.DerivedKey, 'SessionID_R3': self.Session.ID}

		r = method(url, **params)

		# Assert http status code expectation (200 OK default)
		if expectCode is not None:
			assert r.status_code == expectCode # Expect proper status code in response

		return r

	def _getRequest(self, uri, expectCode=200, noSession=False, noEnforceSession=False, ownParams=None):
		"""Perform http-get request with specified characteristics"""
		params = ownParams or self.RequestParams.copy()

		return self._performRequest(requests.get, uri, params, expectCode, noSession, noEnforceSession)

	def _postRequest(self, uri, data, expectCode=200, noSession=False, noEnforceSession=False, ownParams=None):
		"""Perform http-post request with specified characteristics and data"""
		params = (ownParams or self.RequestParams).copy()

		params['data'] = data

		return self._performRequest(requests.post, uri, params, expectCode, noSession, noEnforceSession)

	def _sanitizeJsonNestingLexer(self, str):
		"""Sanitize wrong nestings of json elements by adding missing closing parentheses (brackets & braces)"""

		# The relevant json terminals
		CHR_BACKSLASH     = '\\' # \ Starts escape sequences in json-strings
		CHR_QUOTE         = '"'  # " Starts and terminates json-strings if not escaped
		CHR_BRACKET_OPEN  = '['  # [ Starts json-arrays
		CHR_BRACKET_CLOSE = ']'  # ] Terminates json-arrays
		CHR_BRACE_OPEN    = '{'  # { Starts json-objects
		CHR_BRACE_CLOSE   = '}'  # } Terminates json-objects

		stack = []  # The stack for terminal-symbols
		m = []      # The list of symbol insertions
		esc = False # Whether the cursor is inside of an escape sequence

		# Iterate over all characters
		for p in xrange(len(str)):
			c = str[p]

			# Access the stack's topmost element without popping it
			peek = stack[-1] if len(stack) > 0 else None

			# Escape sequences begin with a 'Backslash' character
			if c == CHR_BACKSLASH:
				# Handle Escape sequence
				esc = not esc
				continue

			elif c == CHR_QUOTE: # Handle quote characters to detect json-strings
				if peek == CHR_QUOTE: # Check if the stacks current state is 'STRING'
					if esc: # LEAVE ESC AFTER ESCAPED QUOTE
						# Ignore escaped quote
						esc = False
						continue

					# We leave the String
					stack.pop()
				else:
					# We enter a String
					stack.append(CHR_QUOTE) # State = 'STRING'

			elif peek == CHR_QUOTE: # Currently the state is 'STRING'
				if esc: # ESCAPED NONQUOTE
					esc = False
					continue

				# Ignore the character, as we are in a String
				continue

			else: # Process non-string terminals
				# Handle json-arrays and json-objects
				if c == CHR_BRACKET_OPEN: # Opening Array Symbol
					stack.append(CHR_BRACKET_CLOSE)

				elif c == CHR_BRACE_OPEN: # Opening Object Symbol
					stack.append(CHR_BRACE_CLOSE)

				elif c in [CHR_BRACKET_CLOSE, CHR_BRACE_CLOSE]:
					# Closing of the array / object if the symbol is on top of the stack
					if peek == c:
						stack.pop()

					elif peek is not None: # If there is a different symbol, the nesting must be fixed
						# Remember the missing symbol for fixing later:
						#  - Copy current position p and the stack's topmost item
						#  - Pop the item off the stack
						m.append((p,peek))
						stack.pop()

						# Peek the new topmost item
						peek = stack[-1] if len(stack) > 0 else None

						# Pop the next item if it is equal to the current one (TODO: Handle advanced nestings ?!)
						if c == peek:
							stack.pop()
					#else: # Unfixable nesting has been detected
					# raise Exception('Invalid nesting')

				else: # Unhandled literals
					#print('LITERAL')
					pass

			# Ignore escape sequence if there wasn't a quote
			#if esc:
			#	print('LEAVE ESC')
			esc = False

		# Add spare items to the string in the right order
		for _ in xrange(len(stack)):
			str += stack.pop()

		# Process (fix) the detected nesting-errors right-to-left
		for _ in xrange(len(m)):
			# The current tuple
			q = m.pop()
			
			# Insert the symbol q[1] at the position p of the string
			p = q[0]
			str = str[:p] + q[1] + str[p:]

		# Return the processed String
		return str

	def _parseJsonResponse(self, jsonString, isJsonVars=False, fix=True):
		"""Parse JSON-String. Invalid json is sanitized per default. If requested the json is parsed as JsonVar-dict."""
		s = jsonString

		# Fix invalid json
		if fix:
			# Single Quotes to Double Quotes
			s = s.replace("'", '"')

			# Sanitize nesting errors and insert missing closing quotes
			s = self._sanitizeJsonNestingLexer(s)

			# Remove redundant trailing ',' 
			s = re.sub(r',(?=[\n\s]*[\]\}])|,(?=[\n\s]*$)', '', s)

			# Embed in an array
			if (re.match(r'^[\n\s]*\[', s) is None) and (re.match(r'\][\n\s]*$', s) is None):
				s = '[%s]' % s

		o = None

		try:
			# Parse JSON String
			o = json.loads(s)
		except Exception as e:
			#print(jsonString)
			raise SpeedportHybridApi.JsonParserException(jsonString, e)
		
		# Fix response
		if fix:
			if isinstance(o, list) and len(o) == 1:
				o = o[0]

		try:
			# Parse vars if needed
			if isJsonVars:
				vx  = [SpeedportHybridApi.JsonVar(j) for j in o]

				o =	{key: value for (key, value) in ((v.ID, v) for v in vx)}

				#print(o)
		except Exception as e:
			raise SpeedportHybridApi.JsonParserException(jsonString, e)

		return o

	def _getChallengeResponse(self, pw, challenge):
		"""Calculate authentication response based on challenge and password"""
		response = hashlib.sha256(('%s:%s' % (challenge, pw)).encode('utf-8')).hexdigest()
		salt = challenge[:16]

		return (response, salt)

	def _getDerivedKey(self, pw, salt):
		"""Derive authentication key based on password and shortened challenge (16 character 'salt') using PBKDF2"""
		from pbkdf2 import PBKDF2
		pwhash = hashlib.sha256(pw.encode('utf-8')).hexdigest().encode('utf-8')
		dk = PBKDF2(pwhash, salt, iterations=1000).hexread(16)
		
		return dk

	def login(self, pw):
		"""Perform login operation using password

		:param pw: The web-ui password
		"""
		loginJsonUri = 'data/Login.json'

		# 1) Get challenge
		# POST 'challengev=' to login.json
		try:
			r = self._postRequest(loginJsonUri, data={'challengev': ''}, noSession=True)
		except Exception as e:
			raise SpeedportHybridApi.RequestException('requesting login challenge failed', e)

		# Parse response for challenge
		try: 
			res = self._parseJsonResponse(r.text, True)
		except Exception as e:
			raise SpeedportHybridApi.ApiException('parsing login challenge failed', e)

		# Retrieve challenge value
		try:
			challenge = res['challengev'].Value
		except Exception as e:
			raise SpeedportHybridApi.ApiException('retrieving login challenge value failed', e)

		# 2) Calculate response
		response, salt = self._getChallengeResponse(pw, challenge)

		loginReqData = {'showpw': 0, 'password': response}  # if 'showpw' = '1' then 'password_shadowed' = password

		# 3) Send response
		try:
			r = self._postRequest(loginJsonUri, data=loginReqData, noSession=True)
		except Exception as e:
			raise SpeedportHybridApi.RequestException('posting login response failed', e)

		# Parse response
		try: 
			res = self._parseJsonResponse(r.text, True)
		except Exception as e:
			#print(r.text)
			raise SpeedportHybridApi.ApiException('parsing login response failed', e)

		# 4) Evaluate response
		login_status = res['login'].Value  # Values: 'success' or 'failed'

		# Check for success
		if login_status != 'success':
			r = { 'locked': res['login_locked'].Value, 
			      'other': res['login_other'].Value if 'login_other' in res else None }

			return self, False, r # Login failed

		# Load cookies
		try:
			sid = r.cookies['SessionID_R3']
		except Exception as e:
			raise SpeedportHybridApi.ApiException('retrieving session id failed', e)

		# 5) Derive key and create session-object
		dk = self._getDerivedKey(pw, salt)

		session = SpeedportHybridApi.ApiSession(self.Host, challenge, dk, sid, checktime=datetime.utcnow())

		self.Session = session

		return self, True, session  # Login success, no advanced parameters

	def logout(self):
		"""Perform logout operation"""

		loginJsonUri = 'data/Login.json'

		try:
			r = self._postRequest(loginJsonUri, data={'logout': ''})
		except SpeedportHybridApi.MissingSessionException:
			raise
		except Exception as e:
			raise SpeedportHybridApi.RequestException('logout failed', e)

		self.Session = None

def main():
	"""Initiate a new session and print session parameters"""
	
	import sys
	import os

	if len(sys.argv) != 3:
		print('Usage: ./%s host password\n\n%s' % (os.path.basename(sys.argv[0]), __doc__))
		sys.exit(0)

	host = sys.argv[1]
	pw   = sys.argv[2]

	api, s, r = SpeedportHybridApi(host).login(pw)

	if not s:
		print('Login failed, wait %s seconds until retry' % r['locked'])

		if r['other'] is not None:
			print('Other user logged in at %s' % r['other'])

		return

	print(r)

	return api.Session.asList()

if __name__ == "__main__":
	main()
