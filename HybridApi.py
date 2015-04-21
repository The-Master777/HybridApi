#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unofficial python-api for the Speedport Hybrid CPE"""

import requests
import json
import hashlib
import re
# from pbkdf2 import PBKDF2 # Moved to SpeedportHybridApi._getDerivedKey()


class SpeedportHybridApi:
	"""An Api for the Speedport Hybrid's web interface"""

	Host = 'speedport.ip'
	Session = None
	RequestParams = { 
		'timeout': 5, # Time out after 5s
	}

	def __init__(self, host=None, session=None):
		if host is not None:
			self.Host = host

		if session is not None:
			# Session overwrites host
			if host is not None and host != session.Host:
				raise SpeedportHybridApi.ApiException('Cannot instantiate Api with diverging host and session configuration')

			session.apply(self)

	class ApiException(Exception):
		"""The baseclass for exceptions raised by SpeedportHybridApi"""

		Cause = None

		def __init__(self, message, cause = None):
			super(SpeedportHybridApi.ApiException, self).__init__(message)

			self.Cause = cause

		def __repr__(self):
			s = str(super(SpeedportHybridApi.ApiException, self))

			return '%s' % s if self.Cause is None else '%s - Cause: %s' % (s, str(self.Cause))

		def __str__(self):
			if self.Cause is not None and self.Cause.hasattr('message'):
				return '%s > %s' % (self.message, self.Cause.message)\

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
		Host = None
		Challenge = None
		DerivedKey = None
		ID = None

		def __init__(self, host, challenge, dk, sid):
			super(SpeedportHybridApi.ApiSession, self).__init__()

			self.Host = host
			self.Challenge = challenge
			self.DerivedKey = dk
			self.ID = sid

		def apply(self, api):
			api.Host = self.Host
			api.Session = self

		def __str__(self):
			return 'Session at %s: SessionID_R3=%s; challengev=%s; derivedk=%s' % (self.Host, self.ID, self.Challenge, self.DerivedKey)

		def __repr(self):
			return '<%s>' % str(self)

		def getNewApi(self):
			"""Create a new SpeedportHybridApi instance based on this session"""
			return SpeedportHybridApi(session=self)

		def asList(self):
			"""Return session parameters in a list"""
			return [self.Host, self.Challenge, self.DerivedKey, self.ID]

		def isValid(self, api=None):
			"""Determine if the current session is still valid

			* NOT IMPLEMENTED YET *"""
			api = api or self.getNewApi()

			raise NotImplementedError()

	class JsonVar(object):
		"""A container for json-variables returned by the router-api"""
		def __init__(self, jsonVarObject):
			super(SpeedportHybridApi.JsonVar, self).__init__()

			self.ID = jsonVarObject['varid']
			self.Value = jsonVarObject['varvalue']
			self.Type = jsonVarObject['vartype']
			#self.Source = jsonVarObject # Store reference to jsonVarObject

		def __str__(self):
			return 'JsonVar "%s" [%s]: (%d) %s%s' % (self.ID, self.Type, len(self.Value), self.Value[:20].__repr__(), ('..' if len(self.Value) > 20 else ''))

		def __repr__(self):
			return '<%s>' % str(self)

	def _makeUri(self, path):
		"""Format a request uri based on current Host and requested path"""
		return 'http://%s/%s' % (self.Host, path)

	def loadJson(self, uri, expectCode=200, fix=True):
		"""Load JSON via a GET-request from given path. The http-status-code expectCode is asserted. By default invalid json responses are fixed."""
		
		# Perform request
		try:
			r = self._getRequest(uri, expectCode=expectCode)
		except Exception as e:
			raise SpeedportHybridApi.RequestException('failed to perform json-request', e)

		# Expect JSON response, not HTML
		# Todo: Implement generic expectation-handler
		assert r.headers['content-type'] != 'text/html'

		# Parse response
		try: 
			res = self._parseJsonResponse(r.text, fix=fix)
		except Exception as e:
			raise SpeedportHybridApi.ApiException('parsing json response failed', e)

		return res, r # res is dict of JsonVar, r is request object

	def _performRequest(self, method, uri, params, expectCode, noSession):
		"""Perform a http request with specified characteristics"""
		uri = self._makeUri(uri)

		# Check is session used and existing
		if (not noSession) and (self.Session is None):
			raise SpeedportHybridApi.MissingSessionException()

		# Set cookie-header if needed
		if 'cookies' not in params and not noSession:
			params['cookies'] = { 'challengev': self.Session.Challenge, 'derivedk': self.Session.DerivedKey, 'SessionID_R3': self.Session.ID }

		r = method(uri, **params)

		# Assert http status code expectation (200 OK default)
		if expectCode is not None:
			assert r.status_code == expectCode # Expect proper status code in response

		return r

	def _getRequest(self, uri, expectCode=200, noSession=False, ownParams=None):
		"""Perform http-get request with specified characteristics"""
		params = ownParams or self.RequestParams.copy()

		return self._performRequest(requests.get, uri, params, expectCode, noSession)

	def _postRequest(self, uri, data, expectCode=200, noSession=False, ownParams=None):
		"""Perform http-post request with specified characteristics and data"""
		params = (ownParams or self.RequestParams).copy()

		params['data'] = data

		return self._performRequest(requests.post, uri, params, expectCode, noSession)

	def _parseJsonResponse(self, jsonString, isJsonVars=False, fix=True):
		"""Parse JSON-String. Invalid json is sanified per default. If requested the json is parsed as JsonVar-dict."""
		s = jsonString

		# Fix invalid json
		if fix:
			# Single Quotes to Double Quotes
			s = s.replace("'", '"')

			# Remove redundant trailing ',' 
			s = re.sub(r',(?=[\n\s]*[\]\}])|,(?=[\n\s]*$)', '', s)

			# Embed in an array
			if (re.match(r'^[\n\s]*\[', s) is None) and (re.match(r'\][\n\s]*$', s) is None):
				s = '[%s]' % s

		try:
			# Parse JSON String
			o = json.loads(s)

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
		"""Perform login operation using password"""
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
			challenge = res['challengev'].Value
		except Exception as e:
			raise SpeedportHybridApi.ApiException('parsing login challenge failed', e)

		# 2) Calculate response
		response, salt = self._getChallengeResponse(pw, challenge)

		loginReqData = {'showpw': 0, 'password': response}  # if 'showpw' = '1' then 'password_shaddowed' = password

		# 3) Send response
		try:
			r = self._postRequest(loginJsonUri, data=loginReqData, noSession=True)
		except Exception as e:
			raise SpeedportHybridApi.RequestException('posting login response failed', e)

		# Parse response
		try: 
			res = self._parseJsonResponse(r.text, True)

			sid = r.cookies['SessionID_R3']
		except Exception as e:
			raise SpeedportHybridApi.ApiException('parsing login response failed', e)

		# 4) Evaluate response
		login_status = res['login'].Value  # Values: 'success' or 'failed'

		# Check for success
		if login_status != 'success':
			return False, {'locked': res['login_locked'].Value, 'other': res['login_other'].Value if 'login_other' in res else None} # Login failed

		# 5)
		dk = self._getDerivedKey(pw, salt)

		session = SpeedportHybridApi.ApiSession(self.Host, challenge, dk, sid)

		self.Session = session

		return True, session  # Login success, no advanced parameters

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

	api = SpeedportHybridApi(host)
	s,r = api.login(pw)

	if not s:
		print('Login failed, wait %s seconds until retry' % r['locked'])

		if r['other'] is not None:
			print('Other user logged in at %s' % r['other'])

		return

	print(r)

	#print(api.loadJson('data/lteinfo.json'))

	return api.Session.asList()

if __name__ == "__main__":
	main()
