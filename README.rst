stix-ramrod
===========

A Python library for upgrading Structured Threat Information eXpression (STIX) and Cyber Observable eXpression (CybOX) XML content.

:Source: https://github.com/STIXProject/stix-ramrod
:Documentation: http://stix-ramrod.readthedocs.org
:Information: https://stixproject.github.io | https://cyboxproject.github.io/

|travis badge| |health badge| |version badge| |downloads badge|

.. |travis badge| image:: https://travis-ci.org/STIXProject/stix-ramrod.svg?branch=master
   :target: https://travis-ci.org/STIXProject/stix-ramrod
   :alt: Build Status
.. |health badge| image:: https://landscape.io/github/STIXProject/stix-ramrod/master/landscape.svg
   :target: https://landscape.io/github/STIXProject/stix-ramrod/master
   :alt: Code Health
.. |version badge| image:: https://img.shields.io/pypi/v/stix-ramrod.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix-ramrod/
.. |downloads badge| image:: https://img.shields.io/pypi/dm/stix-ramrod.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix-ramrod/

Overview
--------

The stix-ramrod package provides APIs and scripts for upgrading STIX and CybOX
content. STIX content can be upgraded from ``1.0`` to ``1.2`` (the current release)
and anywhere in between. CybOX content can be upgraded from ``2.0`` to ``2.1`` (the
current release) and anywhere in between.

Our goal is to make it easy for developers, content authors, and content
consumers to upgrade content from within code or the command line.


Installation
------------

Use pip to install or upgrade stix-ramrod:

::

    $ pip install stix-ramrod

For more information, see the `Installation instructions
<http://stix-ramrod.readthedocs.org/en/latest/installation.html>`_.

Dependencies
------------

The stix-ramrod library depends on the presence of certain packages/libraries
to function. Please refer to their installation documentation for installation
instructions.

-  `lxml <http://lxml.de/>`_


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
follow `semantic versioning <http://semver.org/>`_ guidelines.


Feedback
--------

Please provide feedback to stix@mitre.org.


Terms
-----

BY USING STIX-RAMROD YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND CONDITIONS
OF USE. IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE STIX-RAMROD.

For more information, please refer to the LICENSE.txt file
