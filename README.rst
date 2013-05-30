===================
 Plex Trakt syncer
===================

A simple console script for updating your Trakt_ profile with the infos from your Plex_ media center.

Features
========

- Marks **movies** and **show episodes** watched in Plex_ when watched in your Trakt_ profile.
- Optionally flages the movies and show episodes in Trakt_ with "love" or "hate" according to the rating in Plex_.
- Optionally adds unwatched movies and show episodes to your trakt library.

Scrobbling
==========

At the current state this script does not scrobble. Feel free to modify the script and start a pull-request.

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
      --no-movies           Do not sync watched movies.
      --no-shows            Do not sync watched shows.
      -k API-KEY, --key=API-KEY
                            trakt.tv API key
      -r, --rate            Submit plex movie ratings to trakt.
      -a, --all             Adds unwatched movies and show episodes to trakt library.
      --max-hate=1-10       Maxmimum plex rating for flagging a movie with "hate"
                            (In combination with -r option, defaults to 3).
      --min-love=1-10       Minimum plex rating for flagging a movie with "love"
                            (In combination with -r option, defaults to 8).
      -v, --verbose         Print more verbose debugging informations.

     ** Rating **           The plex rating allows to give up to 5 stars for a
    movie, but you can also give half stars, so there are 10 steps for the rating.
    The configurable --min-hate and --max-love options take a value between 1 and
    10. Movies which are not yet rated in plex are not flagged at all.

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
