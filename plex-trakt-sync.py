#!/usr/bin/env python
# -*- coding: utf-8 -*-

from optparse import OptionParser
from pprint import pformat
from xml.dom.minidom import parseString
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

		if self.options.compare:
			self.find_missing_from_trakt()
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

		self.options, self.arguments = parser.parse_args(args)

		if self.options.verbose:
			LOG.setLevel(logging.DEBUG)

		# validate options
		if not self.options.trakt_username:
			self.quit_with_error('Please define a trakt username (-u).')

		if not self.options.trakt_key:
			self.quit_with_error('Please define a trakt API key (-k).')

		if not self.options.trakt_password:
			self.quit_with_error('Please define a trakt password (-p).')

	def find_missing_from_trakt(self):
		LOG.info('Comparing movie metadata from Plex to Trakt...')

		progress = 0
		LOG.info('     Downloading Plex metadata...')
		plex_movie_nodes = tuple(self.plex_get_all_movies())
		LOG.info('     Downloading Trakt metadata...')
		trakt_movie_nodes = tuple(self._trakt_get('user/library/movies/all.json'))
		found_nodes = []
		
#		LOG.info('Plex Count: %s' % len(plex_movie_nodes))
#		LOG.info('Trakt Count: %s' % len(trakt_movie_nodes))
		
		found = False;
		
		if trakt_movie_nodes != None and plex_movie_nodes != None:
			for plexMovieNode in plex_movie_nodes:
				LOG.info('Searching Trakt for %s (%s) - %s' % (plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year'), self.plex_get_imdb_id(plexMovieNode.getAttribute('key'))))
				for traktMovieNode in trakt_movie_nodes:
#					if self._levenshtein(plexMovieNode.getAttribute('title').lower(), traktMovieNode['title'].lower()) <= 2 and int(plexMovieNode.getAttribute('year')) == int(traktMovieNode['year']) and traktMovieNode not in found_nodes:
					if self.plex_get_imdb_id(plexMovieNode.getAttribute('key')) == traktMovieNode['imdb_id'] and traktMovieNode not in found_nodes:
#						if self._levenshtein(plexMovieNode.getAttribute('title').lower(), traktMovieNode['title'].lower()) > 0:
#							LOG.info("     %s (%s) was matched with a distance of %s to %s (%s)" % (plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year'), self._levenshtein(plexMovieNode.getAttribute('title'), traktMovieNode['title']), traktMovieNode['title'], traktMovieNode['year']))
						
						found_nodes.append(traktMovieNode)
						found = True
						break
					else:
						continue

				if not found:
					LOG.info("     *****%s (%s) is missing from trakt..." % (plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year')))
				else:
#					progress += 1
#					sys.stdout.write('\r[{0}] {1}/{2}'.format('#'*((progress/len(plex_movie_nodes))*100), progress, len(plex_movie_nodes)))
#					sys.stdout.flush()
					found = False
					continue

			progress = 0
			sys.stdout.write('\r')
			sys.stdout.flush()
			
			LOG.info('Comparing movie metadata from Trakt to Plex...')
			sys.stdout.write('\r')
			sys.stdout.flush()			
			
			found_nodes = []
			
			for traktMovieNode in trakt_movie_nodes:
				for plexMovieNode in plex_movie_nodes:
					if self._levenshtein(plexMovieNode.getAttribute('title').lower(), traktMovieNode['title'].lower()) <= 2 and int(plexMovieNode.getAttribute('year')) == int(traktMovieNode['year'] and plexMovieNode not in found_nodes):
						if self._levenshtein(plexMovieNode.getAttribute('title').lower(), traktMovieNode['title'].lower()) > 0:
							LOG.info("     %s (%s) was matched with a distance of %s to %s (%s)" % (traktMovieNode['title'], traktMovieNode['year'], self._levenshtein(plexMovieNode.getAttribute('title'), traktMovieNode['title']), plexMovieNode.getAttribute('title'), plexMovieNode.getAttribute('year')))
							
						found_nodes.append(plexMovieNode)
						found = True
						break
					else:
						continue

				if not found:
					LOG.info("*****%s (%s) is missing from Plex..." % (traktMovieNode['title'], traktMovieNode['year']))
				else:
#					progress += 1
#					sys.stdout.write('\r[{0}] {1}/{2}'.format('#'*((progress/len(plex_movie_nodes))*100), progress, len(plex_movie_nodes)))
#					sys.stdout.flush()
					found = False
					continue	
		else:
			LOG.info('No movies found.')

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
		metadata = []
		guid = ''
		imdb_id = '0000000'
		
		for node in self._plex_request(path):
			metadata.append(node)

		if len(metadata) > 0:
			guid = node.getAttribute('guid')
			try:
				imdb_id = re.search('imdb://(tt[0-9]{7})', guid).groups(1)
			except:
				return '0000000'
			
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
				'last_played': node.getAttribute('updatedAt')}

	def get_show_data(self, show):
		return {'title': show.getAttribute('title'),
				'year': show.getAttribute('year')}

	def trakt_report_movies(self, nodes):
		movies = []
		seen = []
		unseen = []

		LOG.info('Building submission to trakt:')

		for node in nodes:
			movie = self.get_movie_data(node)

			if node.getAttribute('viewCount'):
				LOG.info('     "%s (%s)" as seen' % (
						movie['title'], movie['year']))
				seen.append(movie)
			else:
				LOG.info('     "%s (%s)" as unseen' % (
						movie['title'], movie['year']))
				unseen.append(movie)
			
			movies.append(movie)
		
		LOG.info('Adding all movies to the trakt library...')
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': movies}))
			else:
				self._trakt_post('movie/library', {'movies': movies})
		except:
			LOG.info('Error submitting all movies to trakt library')
		
		LOG.info('Marking watched movies as seen...')
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': seen}))
			else:			
				self._trakt_post('movie/seen', {'movies': seen})
		except:
			LOG.info('Error submitting seen movies to trakt')
		
		LOG.info('Marking unwatched movies as unseen...')	
		try:
			if self.options.debug:
				LOG.info(pformat({'movies': unseen}))
			else:			
				self._trakt_post('movie/unseen', {'movies': unseen})
		except:
			LOG.info('Error submitting unseen movies to trakt')

	def trakt_report_episodes(self, episode_data):
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
					self._trakt_post('show/episode/library', allepisodes)
				except:
					LOG.info('Error submitting all episodes to trakt library')

			if self.options.debug:
				LOG.info(pformat(unseenepisodes))
			else:
				try:
					self._trakt_post('show/episode/unseen', unseenepisodes)
				except:
					LOG.info('Error submitting unseen episodes to trakt library')

			if self.options.debug:
				LOG.info(pformat(seenepisodes))
			else:
				try:
					self._trakt_post('show/episode/seen', seenepisodes)
				except:
					LOG.info('Error submitting seen episodes to trakt library')
		

	def _get_plex_section_paths(self, type_):
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

	def _trakt_post(self, path, data):
		"""Posts informations to trakt. Data should be a dict which will
		be updated with user credentials.
		"""
		url = 'http://api.trakt.tv/%s/%s' % (path, self.options.trakt_key)
		passwd = hashlib.sha1(self.options.trakt_password).hexdigest()

		postdata = {'username': self.options.trakt_username,
					'password': passwd}
		postdata.update(data)

		LOG.debug('POST to %s ...' % url)
		LOG.debug(pformat(data))
		try:
			# data = urllib.urlencode(postdata)
			request = urllib2.Request(url, json.dumps(postdata))
			response = urllib2.urlopen(request)

		except urllib2.URLError, e:
			LOG.error(e)
			raise

		resp_data = response.read()
		resp_json = json.loads(resp_data)
		if resp_json.get('status') == 'success':

			if LOG.isEnabledFor(logging.DEBUG):
				LOG.debug('Trakt request success: %s' % pformat(resp_json))

			else:
				filtered_data = dict([(key, value) for (key, value) in resp_json.items()
									  if not key.endswith('_movies')])
				LOG.info('Trakt request success: %s' % pformat(filtered_data))

			return True

		else:
			self.quit_with_error('Trakt request failed with %s' % resp_data)

	def _trakt_get(self, path):
		"""Gets information from trakt.
		"""
		url = 'http://api.trakt.tv/%s/%s/%s' % (path, self.options.trakt_key, self.options.trakt_username)

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

if __name__ == '__main__':
	try:
		Syncer()()
	except Exception, e:
		LOG.error(str(e))
		raise
