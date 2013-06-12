===================
 Plex Trakt syncer
===================

A simple console script for updating your Trakt_ profile with the infos from your Plex_ media center.

Features
========

- Adds entire Plex library to trakt, then marks movies and episodes as seen or unseen.

Scrobbling
==========

At the current state this script does not scrobble. Feel free to modify the script and start a pull-request.

Prerequisites
=======

Requests is required (http://docs.python-requests.org/en/latest/).

See http://docs.python-requests.org/en/latest/user/install/ for installation instructions.

Install
=======

Either download the script from https://github.com/dmaxwell351/plex-trakt-syncer/downloads or
clone the repository with git:

::

    $ git clone https://github.com/dmaxwell351/plex-trakt-syncer.git
    $ cd plex-trakt-syncer
    $ plex-trakt-sync.py --help

You may also want to set up a cronjob_ for starting the script.


Usage
=====

.. %usage-start%

::

    Usage: plex-trakt-sync.py [options]

    This script connects to a Plex media center server and reports the watched
    movies to a trakt.tv user profile. Optionally it also flags the movies at the
    trakt profile with "love" or "hate" according to ratings in Plex.

    Options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -H HOST, --host=HOST  Hostname or IP of plex server (default: localhost)
      -P PORT, --port=PORT  Port of the plex server (default: 32400)
      -u USERNAME, --username=USERNAME
                            trakt.tv username
      -p PASSWORD, --password=PASSWORD
                            trakt.tv password
      -k API-KEY, --key=API-KEY
                            trakt.tv API key
      -v, --verbose         Print more verbose debugging informations.

.. %usage-end%

License
=======

jone wrote the original plex-trakt-syncer script, which can be found at https://github.com/jone/plex-trakt-syncer.

This version may be used for any purpose.

Source
======

The source is located at https://github.com/dmaxwell351/plex-trakt-syncer


.. _Trakt: http://trakt.tv/
.. _Plex: http://www.plexapp.com/
.. _jone: http://github.com/jone
.. _dmaxwell351: http://github.com/dmaxwell351
.. _cronjob: http://de.wikipedia.org/wiki/Cron
