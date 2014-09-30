stix-ramrod
===========

A Python library for upgrading STIX and CybOX XML content.

:Source: https://github.com/STIXProject/stix-ramrod
:Documentation: http://stix-ramrod.readthedocs.org
:Information: http://stixproject.github.io


|travis badge| |version badge| |downloads badge|

.. |travis badge| image:: https://api.travis-ci.org/STIXProject/stix-ramrodi.png?branch=master
   :target: https://travis-ci.org/STIXProject/stix-ramrod
   :alt: Build Status
.. |version badge| image:: https://pypip.in/v/ramrod/badge.png
   :target: https://pypi.python.org/pypi/ramrod/
.. |downloads badge| image:: https://pypip.in/d/ramrod/badge.png
   :target: https://pypi.python.org/pypi/ramrod/

Overview
--------

The stix-ramrod package provides APIs and scripts for upgrading STIX and CybOX
content. STIX content can be upgraded from 1.0 to 1.1.1 (the current release)
and anwhere in between. CybOX content can be upgraded from 2.0 to 2.1 (the
current release).

Our goal is to make it easy for developers, content authors, and content
consumers to upgrade content from within code or the command line.


Installation
------------

Use pip to install or upgrade stix-ramrod:

.. code-block::

    $ pip install ramrod [--upgrade]

For more information, see the `Installation instructions
<http://stix-ramrod.readthedocs.org/en/latest/installation.html>`_.


Getting Started
---------------

Read the `Getting Started guide
<http://stix-ramrod.readthedocs.org/en/latest/getting_started.html>`_.


Layout
------

The stix-ramrod repository has the following layout:

* ``docs/`` - Used to build the `documentation
  <http://stix-ramrod.readthedocs.org>`_.
* ``ramrod/`` - The main stix-ramrod source.
* ``samples/`` - Sample STIX/CybOX XML documents


Versioning
----------

Releases of stix-ramrod are given ``major.minor.patch`` version numbers and
follow `semantic versioning
<http://semver.org/>`_ guidelines.


Feedback
--------

You are encouraged to provide feedback by commenting on open issues or signing
up for the `STIX discussion list
<http://stix.mitre.org/community/registration.html>`_ and posting your
questions.
