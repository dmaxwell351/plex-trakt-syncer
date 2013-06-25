#!/usr/bin/env python
# -*- coding: utf-8 -*-

from optparse import OptionParser
from pprint import pformat
from xml.dom.minidom import parseString
from uuid import getnode as get_mac
from xml.dom import minidom
import hashlib
import json
import logging
import os
import sys
import urllib
import urllib2
import requests
import pprint
import string
import re
import sqlite3

VERSION = '1.0'

DESCRIPTION = ''''''

LOG_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)),
						'syncer.log')

logging.basicConfig(
		filename=LOG_FILE,
		datefmt='%Y-%m-%dT%H:%M:%S',
		format='%(asctime)s %(levelname)s [%(name)s] %(message)s')


LOG = logging.getLogger('plex-trakt-syncer')
LOG.addHandler(logging.StreamHandler())
LOG.setLevel(logging.INFO)

class Syncer(object):

	def __call__(self, args=None):
		if args is None:
			args = sys.argv[1:]

		self.parse_arguments(args)
		
		self._prepareCacheDB()

		if self.options.getPlexXToken:
			print self._get_plex_xtoken(self.options.trakt_username, self.options.trakt_password)
			sys.exit(1)
		
		if self.options.testTrakt:
			self.test_trakt_secure_connection()
			sys.exit(1)

		if self.options.passwordtohash:
			self.export_trakt_password_hash(self.options.passwordtohash)
			sys.exit(1)

		if self.options.filename:
			self.export_plex_imdbids(self.options.filename, '_')
			sys.exit(1)

		if self.options.compareuser:
			self.compare_library_with_another()
			sys.exit(1)

		if self.options.compare:
			self.find_missing_from_trakt_2()
			sys.exit(1)
			
		if not self.options.episodesonly:
			self.sync_movies()

		if not self.options.moviesonly:
			self.sync_shows()

	def quit_with_error(self, message):
		LOG.error(message)
		sys.exit(1)

	def parse_arguments(self, args):
		"""Parses the passed arguments.
		"""

		parser = OptionParser(version=VERSION, description=DESCRIPTION)

		parser.add_option(
				'-H', '--host', dest='plex_host', default='localhost',
				metavar='HOST',
				help='Hostname or IP of plex server (default: localhost)')

		parser.add_option(
				'-P', '--port', dest='plex_port', default=32400,
				metavar='PORT',
				help='Port of the plex server (default: 32400)')

		parser.add_option(
				'-u', '--username', dest='trakt_username',
				metavar='USERNAME',
				help='trakt.tv username')

		parser.add_option(
				'-p', '--password', dest='trakt_password',
				metavar='PASSWORD',
				help='trakt.tv password')
		
		parser.add_option(
		                '-s', '--secure-password', dest='trakt_password_hash',
		                metavar='PASSWORDHASH',
		                help='hash of trakt.tv password')
		
		parser.add_option(
				'-k', '--key', dest='trakt_key',
				metavar='API-KEY',
				help='trakt.tv API key')

		parser.add_option(
				'-v', '--verbose', dest='verbose', action='store_true',
				help='Print more verbose debugging informations.')
		
		parser.add_option(
				'-d', '--debug', dest='debug', action='store_true',
				help='Prints the JSON instead of actually submitting to trakt.')
		
		parser.add_option(
				'-m', '--movies-only', dest='moviesonly', action='store_true', 
				help='Only sync the movie sections of Plex.')
		
		parser.add_option(
				'-e', '--episodes-only', dest='episodesonly', action='store_true', 
				help='Only sync the TV sections of Plex.')
		
		parser.add_option(
				'-c', '--compare', dest='compare', action='store_true', 
				help='Find missing items in trakt.')
		
		parser.add_option(
				'-x', '--compare-user', dest='compareuser',
				metavar='COMPAREUSER',
				help='Compare your trakt movie library with another user\'s.')
				
		parser.add_option(
				'-f', '--file-export', dest='filename', 
				metavar='FILENAME',
				help='Export Plex IMDB IDs to a file')
		
		parser.add_option(
				'-o', '--output-hash', dest='passwordtohash',
				metavar='PASSWORD',
				help='Export trakt password as a hash')

		parser.add_option(
				'-t', '--test', dest='testTrakt', action='store_true',
				help='Test trakt connection')
		
		parser.add_option(
				'-l', '--plex-token', dest='getPlexXToken', action='store_true',
				help='Get and Export Plex Token')
		
		parser.add_option(
				'-a', '--plex-authentication', dest='plexXtoken',
				metavar='X-TOKEN',
				help='Plex authentication token')

		self.options, self.arguments = parser.parse_args(args)

		if self.options.verbose:
			LOG.setLevel(logging.DEBUG)

		# validate options
		if not self.options.passwordtohash and not self.options.filename:
			if not self.options.trakt_username:
				self.quit_with_error('Please define a username (-u).')

			if not self.options.trakt_key and not self.options.getPlexXToken:
				self.quit_with_error('Please define an API key (-k).')
		
			if not self.options.compareuser and not self.options.compare:
				if not self.options.trakt_password and not self.options.trakt_password_hash:
					self.quit_with_error('Please define a trakt password (-p) or secure password (-s).')
					
		if self.options.plex_host:
			if not self.options.plexXtoken:
				self.quit_with_error('Please define a Plex authentication token (-a).')
	
	def test_trakt_secure_connection(self):
		url = 'http://api.trakt.tv/movie/library/%s' % self.options.trakt_key
		postdata = {'username': self.options.trakt_username, 'password': self.options.trakt_password_hash}
		
		movies = []
		movie1 = {"imdb_id":"tt1111422", "title":"The Taking of Pelham 1 2 3", "year":"2009"}
		movies.append(movie1)
		
		data = {'movies': movies}

		postdata.update(data)
	
		LOG.info(pformat(data))
		try:
			r = requests.post(url, data=json.dumps(postdata))
		except urllib2.URLError, e:
			LOG.error(e)
			raise
	
		resp_json = r.json()
		if resp_json.get('status') == 'success':
	
			if LOG.isEnabledFor(logging.DEBUG):
				LOG.debug('Trakt request success: %s' % pformat(resp_json))
	
			else:
				filtered_data = dict([(key, value) for (key, value) in resp_json.items()
					                                  if not key.endswith('_movies')])
				LOG.info('Trakt request success: %s' % pformat(filtered_data))
	
			return True
	
		else:
			self.quit_with_error('Trakt request failed with %s' % resp_json)

	def compare_library_with_another(self):
		LOG.info('     Downloading %s\'s Trakt metadata...' % self.options.trakt_username)
		own_trakt_movie_nodes = tuple(self._trakt_get('user/library/movies/all.json'))
		
		LOG.info('     Downloading %s\'s Trakt metadata...' % self.options.compareuser)
		other_trakt_movie_nodes = tuple(self._trakt_get('user/library/movies/all.json', self.options.compareuser))
		
		found_nodes = []
		found = False;
		
		if own_trakt_movie_nodes != None and other_trakt_movie_nodes != None:
			LOG.info('Comparing movie metadata between the two users...')
			LOG.info('')
			LOG.info('     Comparing %s\'s library to %s\'s...' % (self.options.trakt_username, self.options.compareuser))			
			for ownMovieNode in own_trakt_movie_nodes:
				for otherMovieNode in other_trakt_movie_nodes:
					if ownMovieNode['imdb_id'] == otherMovieNode['imdb_id'] and otherMovieNode not in found_nodes:						
						found_nodes.append(otherMovieNode)
						found = True
						break
					else:
						continue

				if not found:
					LOG.info("     *****%s (%s) is missing from %s\'s library..." % (ownMovieNode['title'], ownMovieNode['year'], self.options.compareuser))
				else:
					found = False
					continue
			
			found_nodes = []
			found = False;
			
			LOG.info('')
			LOG.info('     Comparing %s\'s library to %s\'s...' % (self.options.compareuser, self.options.trakt_username))
			for otherMovieNode in other_trakt_movie_nodes:
				for ownMovieNode in own_trakt_movie_nodes:
					if ownMovieNode['imdb_id'] == otherMovieNode['imdb_id'] and ownMovieNode not in found_nodes:						
						found_nodes.append(ownMovieNode)
						found = True
						break
					else:
						continue
			
				if not found:
					LOG.info("     *****%s (%s) is missing from %s\'s library..." % (otherMovieNode['title'], otherMovieNode['year'], self.options.trakt_username))
				else:
					found = False
					continue			
		else:
			LOG.info('No movies found.')		

	def find_missing_from_trakt(self):
		LOG.info('     Downloading Plex metadata...')
		plex_movie_nodes = tuple(self.plex_get_all_movies())
		LOG.info('     Downloading Trakt metadata...')
		trakt_movie_nodes = tuple(self._trakt_get('user/library/movies/all.json'))
		found_nodes = []
		
		found = False;
		
		LOG.info('Comparing movie metadata from Plex to Trakt...')
		
		if trakt_movie_nodes != None and plex_movie_nodes != None:
			for plexMovieNode in plex_movie_nodes:
				for traktMovieNode in trakt_movie_nodes:
					if self.plex_get_imdb_id(plexMovieNode.getAttribute('key')) == traktMovieNode['imdb_id'] and traktMovieNode not in found_nodes:						
						found_nodes.append(traktMovieNode)
						found = True
						break
					else:
						continue

				if not found:
					LOG.info("     *****%s (%s) is missing from Trakt..." % (plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year')))
				else:
					found = False
					continue
			
			LOG.info('Comparing movie metadata from Trakt to Plex...')
			found_nodes = []
			found = False;
			
			for traktMovieNode in trakt_movie_nodes:
				for plexMovieNode in plex_movie_nodes:
					if self.plex_get_imdb_id(plexMovieNode.getAttribute('key')) == traktMovieNode['imdb_id'] and plexMovieNode not in found_nodes:
						found_nodes.append(plexMovieNode)
						found = True
						break
					else:
						continue

				if not found:
					LOG.info("     *****%s (%s) is missing from Plex..." % (traktMovieNode['title'], traktMovieNode['year']))
				else:
					found = False
					continue
		else:
			LOG.info('No movies found.')
	
	def find_missing_from_trakt_2(self):
		LOG.info('     Downloading Plex metadata...')
		plex_movie_nodes = tuple(self.plex_get_all_movies())
		
		LOG.info('     Downloading Trakt metadata...')
		trakt_movie_nodes = tuple(self._trakt_get('user/library/movies/all.json'))
		
		if trakt_movie_nodes != None and plex_movie_nodes != None:
			plexSet = set()
			traktSet = set()
	
			moviesMissingFromPlex = None
			moviesMissingFromTrakt = None
			
			LOG.info('     Building the two sets of IMDB ID\'s...')
			
			for plexMovieNode in plex_movie_nodes:
				plexSet.add(str(self.plex_get_imdb_id(plexMovieNode.getAttribute('key'))))
			
			for traktMovieNode in trakt_movie_nodes:
				traktSet.add(str(traktMovieNode['imdb_id']))
			
			LOG.info('     Discovering the differences...')
			
			moviesMissingFromPlex = traktSet.difference(plexSet)
			moviesMissingFromTrakt = plexSet.difference(traktSet)
			
			LOG.info('Movies missing from Plex...')
			print moviesMissingFromPlex
			
			LOG.info('Movies missing from trakt...')
			print moviesMissingFromTrakt
		else:
			LOG.info('No movies found.')

	def export_plex_imdbids(self, filename, delimeter = '\n'):
		LOG.info('Downloading Plex metadata...')
		plex_movie_nodes = tuple(self.plex_get_all_movies())
		
		LOG.info('Exporting data to file...')
		f = open(filename, 'w')
		f2 = open('%s_errors' % filename, 'w')
		
		imdbid = '0000000'
		first = True
		
		for plexMovieNode in plex_movie_nodes:
			imdbid = self.plex_get_imdb_id(plexMovieNode.getAttribute('key'))
			
			if imdbid != '0000000':
				if first:
					f.write('%s' % imdbid)
					first = False
				else:
					f.write('%s%s' % (delimeter, imdbid))
			else:
				f2.write('%s (%s) - %s\n' % (plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year'), plexMovieNode.getAttribute('key')))
		
		f.close()
		f2.close()

	def export_trakt_password_hash(self, password):
		LOG.info('Exporting password to file traktpasswd.hash...')

		f = open('traktpasswd.hash', 'w')
		f.write('%s' % hashlib.sha1(password).hexdigest())
		f.close()

	def sync_movies(self):
		LOG.info('Downloading movie metadata from Plex...')
		
		movie_nodes = tuple(self.plex_get_all_movies())

		if movie_nodes:
			self.trakt_report_movies(movie_nodes)
		else:
			LOG.warning('No movies could be found in your '
						'plex server.')

	def plex_get_all_movies(self):
		for section_path in self._get_plex_section_paths('movie'):
			for node in self._plex_request(section_path + 'all'):
 					yield node

	def plex_get_imdb_id(self, path):
		imdb_id = None
		
		imdb_id = self._getcachedIMDBID(path)
		
		if not imdb_id == None:
			return imdb_id

		metadata = []
		guid = ''
		imdb_id = '0000000'
		
		for node in self._plex_request(path):
			metadata.append(node)

		if len(metadata) > 0:
			guid = node.getAttribute('guid')
			try:
				imdb_id = re.search('imdb://(tt[0-9]{7})', guid).groups(1)[0]
			except:
				return '0000000'
			
		if imdb_id != '0000000':
			LOG.debug('Caching %s: %s' %(path, str(imdb_id)))
			self._cacheIMDBID(path, str(imdb_id))

		return str(imdb_id)

	def sync_shows(self):
		LOG.info('Downloading TV show metadata from Plex...')
		
		episode_data = self.plex_get_all_episodes()

		if episode_data:
			self.trakt_report_episodes(episode_data)
		else:
			LOG.warning('No episodes could be found on your '
						'plex server.')

	def plex_get_shows(self, section_path):
		return self._plex_request('%sall' % section_path, nodename='Directory')

	def plex_get_seasons(self):
		for section_path in self._get_plex_section_paths('show'):
			for show in self.plex_get_shows(section_path):
				seasons = []
				show_key = show.getAttribute('key')

				for season in self._plex_request(show_key, nodename='Directory'):
					seasons.append(season)
					
				yield show, seasons

	def plex_get_all_episodes(self):
		shows = []

		for show, seasons in self.plex_get_seasons():
			episodes = []

			for season in seasons:
				season_key = season.getAttribute('key')

				for episode in self._plex_request(season_key):
					episodes.append((season, episode))

			if len(episodes) > 0:
				shows.append((show, episodes))

		return shows

	def get_movie_data(self, node):
		"""Returns movie data from a XML node, prepared to post to trakt.
		"""
		return {'title': node.getAttribute('title'),
				'year': node.getAttribute('year'),
				'plays': node.getAttribute('viewCount'),
				'last_played': node.getAttribute('updatedAt'),
				'imdb_id': self.plex_get_imdb_id(node.getAttribute('key'))}

	def get_show_data(self, show):
		return {'title': show.getAttribute('title'),
				'year': show.getAttribute('year')}

	def trakt_report_movies(self, nodes):
		password = ''

		if self.options.trakt_password_hash:
			password = self.options.trakt_password_hash
		else:
			password = self.options.trakt_password

		movies = []
		seen = []
		unseen = []

		LOG.info('Building submission to trakt...')

		for node in nodes:
			movie = self.get_movie_data(node)

			if node.getAttribute('viewCount'):
#				LOG.info('     "%s (%s)" as seen' % (
#						movie['title'], movie['year']))
				seen.append(movie)
			else:
#				LOG.info('     "%s (%s)" as unseen' % (
#						movie['title'], movie['year']))
				unseen.append(movie)
			
			movies.append(movie)
		
		LOG.info('Adding all movies to the trakt library...')
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': movies}))
			else:
				self._trakt_post('movie/library', {'movies': movies}, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
		except:
			LOG.info('Error submitting all movies to trakt library')
		
		LOG.info('Marking watched movies as seen...')
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': seen}))
			else:			
				self._trakt_post('movie/seen', {'movies': seen}, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
		except:
			LOG.info('Error submitting seen movies to trakt')
		
		LOG.info('Marking unwatched movies as unseen...')
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': unseen}))
			else:			
				self._trakt_post('movie/unseen', {'movies': unseen}, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
		except:
			LOG.info('Error submitting unseen movies to trakt')

	def trakt_report_episodes(self, episode_data):
		password = ''

		if self.options.trakt_password_hash:
			password = self.options.trakt_password_hash
		else:
			password = self.options.trakt_password

		LOG.info('Building submission to trakt:')
		
		for show, episodes in episode_data:
			show_data = self.get_show_data(show)
			
			allepisodes = show_data.copy()
			allepisodes['episodes'] = []
			
			unseenepisodes = show_data.copy()
			unseenepisodes['episodes'] = []
			
			seenepisodes = show_data.copy()
			seenepisodes['episodes'] = []
			
			for season, episode in episodes:
				allepisodes['episodes'].append({'season': season.getAttribute('index'), 'episode': episode.getAttribute('index')})
				
				if episode.getAttribute('viewCount'):
					seenepisodes['episodes'].append({'season': season.getAttribute('index'), 'episode': episode.getAttribute('index')})
				else:
					unseenepisodes['episodes'].append({'season': season.getAttribute('index'), 'episode': episode.getAttribute('index')})
		
			LOG.info('Submitting %s to trakt...' % show_data['title'])
			if self.options.debug:
				LOG.info(pformat(allepisodes))
			else:
				try:
					self._trakt_post('show/episode/library', allepisodes, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
				except:
					LOG.info('Error submitting all episodes to trakt library')

			if self.options.debug:
				LOG.info(pformat(unseenepisodes))
			else:
				try:
					self._trakt_post('show/episode/unseen', unseenepisodes, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
				except:
					LOG.info('Error submitting unseen episodes to trakt library')

			if self.options.debug:
				LOG.info(pformat(seenepisodes))
			else:
				try:
					self._trakt_post('show/episode/seen', seenepisodes, self.options.trakt_username, password, True if self.options.trakt_password_hash else False)
				except:
					LOG.info('Error submitting seen episodes to trakt library')
		

	def _get_plex_section_paths(self, type_):
		#https://my.plexapp.com/pms/system/library/sections?auth_token=[token]
		#[key] ----> http://98.180.85.64:32400/library/sections/1?auth_token=[token]
		"""Returns all paths to sections of a particular type.
		_get_plex_section_paths('movie') => ['/library/sections/1/']
		"""

		sections_path = '/library/sections'
		paths = []

		for node in self._plex_request(sections_path,
									   nodename='Directory'):
			if node.getAttribute('type') == type_:
				paths.append('%s/%s/' % (
						sections_path,
						node.getAttribute('key')))

		return paths

	def _plex_request(self, path, nodename='Video'):
		"""Makes a request to plex and parses the XML with minidom.
		"""
		url = 'http://%s:%s%s' % (
				self.options.plex_host,
				self.options.plex_port,
				path)

		LOG.debug('Plex request to %s' % url)

		response = urllib.urlopen(url)
		data = response.read()
		doc = parseString(data)

		LOG.debug('Plex request success')

		return doc.getElementsByTagName(nodename)

	def _trakt_post(self, path, data, username, password, usePasswordHash = False):
		"""Posts informations to trakt. Data should be a dict which will
		be updated with user credentials.
		"""
		url = 'http://api.trakt.tv/%s/%s' % (path, self.options.trakt_key)
		
		if not usePasswordHash:
			password = hashlib.sha1(password).hexdigest()

		postdata = {'username': username,
					'password': password}
		postdata.update(data)

		LOG.debug('POST to %s ...' % url)
		LOG.debug(pformat(data))
		try:
			r = requests.post(url, data=json.dumps(postdata))
		except urllib2.URLError, e:
			LOG.error(e)
			raise

		resp_json = r.json()
		if resp_json.get('status') == 'success':
			if LOG.isEnabledFor(logging.DEBUG):
				LOG.debug('Trakt request success: %s' % pformat(resp_json))

			else:
				filtered_data = dict([(key, value) for (key, value) in resp_json.items()
									  if not key.endswith('_movies')])
				LOG.info('Trakt request success: %s' % pformat(filtered_data))

			return True

		else:
			self.quit_with_error('Trakt request failed with %s' % resp_json)

	def _trakt_get(self, path, username = ''):
		"""Gets information from trakt.
		"""

		if username == '':
			username = self.options.trakt_username;
		
		url = 'http://api.trakt.tv/%s/%s/%s' % (path, self.options.trakt_key, username)

		try:
			response = requests.get(url)
		except urllib2.URLError, e:
			LOG.error(e)
			raise

		if response.status_code == requests.codes.ok:
			return response.json()
		else:
			LOG.info('Status code: %s' % response.status_code)
			return None

	def _levenshtein(self, a, b):
		n, m = len(a), len(b)
		if n > m:
			# Make sure n <= m, to use O(min(n,m)) space
			a,b = b,a
			n,m = m,n
			
		current = range(n+1)
		for i in range(1,m+1):
			previous, current = current, [i]+[0]*n
			for j in range(1,n+1):
				add, delete = previous[j]+1, current[j-1]+1
				change = previous[j-1]
				if a[j-1] != b[i-1]:
					change = change + 1
				current[j] = min(add, delete, change)
		return current[n]

	def _prepareCacheDB(self):
		con = None
		
		try:
			con = sqlite3.connect('cache.db')
			c = con.cursor()
			
			sql = 'create table if not exists Plex_IMDB_IDs (key TEXT NOT NULL, imdbid TEXT NOT NULL, PRIMARY KEY (key))'
			c.execute(sql)
			con.commit()
		except sqlite3.Error, e:
			LOG.error('Error creating database: %s' % e.args[0])
		finally:
			if con:
				con.close()	

	def _cacheIMDBID(self, key, imdbid):
		con = None
		
		try:
			con = sqlite3.connect('cache.db')
			c = con.cursor()
			
			c.execute('INSERT INTO Plex_IMDB_IDs VALUES (?, ?)', (key, imdbid))
			con.commit()
		except sqlite3.Error, e:
			LOG.error('Error caching IMDB: %s' % e.args[0])
		finally:
			if con:
				con.close()

	def _getcachedIMDBID(self, key):
		imdbid = None
		con = None
		
		try:
			con = sqlite3.connect('cache.db')
			c = con.cursor()
			
			c.execute('SELECT imdbid FROM Plex_IMDB_IDs WHERE key = \'' + key + '\'')
			
			row = c.fetchone()
			
			if row:
				imdbid = row[0]
		except sqlite3.Error, e:
			LOG.error('Error retrieving cached IMDB: %s' % e.args[0])
		finally:
			if con:
				con.close()
		
		return imdbid

	def _get_plex_xtoken(self, username, password):
		url = 'https://my.plexapp.com/users/sign_in.xml'
		
		mac = get_mac()
		uid = hashlib.sha1(str(mac)).hexdigest()
		
		LOG.debug('UID: %s' %uid)
		
		plexheaders = {'X-Plex-Platform':'MacOSX',
					'X-Plex-Platform-Version':'10.8.4',
					'X-Plex-Provides':'server',
					'X-Plex-Product':'plex-trakt-sync.py',
					'X-Plex-Version':'1.0.0',
					'X-Plex-Device':'python',
					'X-Plex-Client-Identifier':uid}
		
		try:
			r = requests.post(url, headers=plexheaders, auth=(username, password))
		except urllib2.URLError, e:
			LOG.error(e)
			raise

		try:		
			xmldoc = minidom.parseString(r.text)
			tokens = xmldoc.getElementsByTagName('authentication-token')
			token  = tokens[0]
		
			return token.childNodes[0].data
		except e:
			LOG.error(e)
			return None

if __name__ == '__main__':
	try:
		Syncer()()
	except Exception, e:
		LOG.error(str(e))
		raise
