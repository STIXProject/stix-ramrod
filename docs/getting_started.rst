Getting Started
===============

This page gives an introduction to **stix-ramrod** and how to use it.  Please
note that this page is being actively worked on and feedback is welcome! If
you have a suggestion or something doesn't look right, let us know:
(stix@mitre.org).

Note that the GitHub repository is named :code:`stix-ramrod`, but
once installed, the library is imported using the :code:`import ramrod`
statement.

Installation
------------
There are two options for installation:  

#. :code:`pip install stix-ramrod --upgrade`
#. Download the latest zip from https://pypi.python.org/pypi/stix-ramrod

Scripts
-------

These instructions tell you how to upgrade STIX or CybOX content using the
scripts bundled with **stix-ramrod**.


Ramrod Update
~~~~~~~~~~~~~

Currently, the only script bundled with **stix-ramrod** is the
``ramrod_update.py`` script, which can be found on your ``PATH`` after
installing **stix-ramrod**.

Options
^^^^^^^

Running :code:`ramrod_update.py -h` displays the following:

.. code-block:: bash

    $ ramrod_update.py -h
    usage: ramrod_update.py [-h] --infile INFILE [--outfile OUTFILE]
                            [--from VERSION IN] [--to VERSION OUT]
                            [--disable-vocab-update] [--disable-remove-optionals]
                            [-f]

    Ramrod Updater v1.0a1: Updates STIX and CybOX documents.

    optional arguments:
      -h, --help            show this help message and exit
      --infile INFILE       Input STIX/CybOX document filename.
      --outfile OUTFILE     Output XML document filename. Prints to stdout if no
                            filename is provided.
      --from VERSION IN     The version of the input document. If not supplied,
                            RAMROD will try to determine the version of the input
                            document.
      --to VERSION OUT      Update document to this version. If no version is
                            supplied, the document will be updated to the latest
                            version.
      --disable-vocab-update
                            Controlled vocabulary strings will not be updated.
      --disable-remove-optionals
                            Do not remove empty elements and attributes which were
                            required in previous language versions but became
                            optional in later releases.
      -f, --force           Removes untranslatable fields, remaps non-unique IDs,
                            and attempts to force the update process.


Updating STIX And CybOX Content
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``ramrod_update.py`` script can accept either STIX ``STIX_Package`` or
CybOX ``Observables`` documents as input. You don't need to tell it that you're
updaing STIX or CybOX content--it'll figure it out for you!

Basics
,,,,,,

To update content, just provide ``--infile`` and ``--outfile`` arguments which
specify the input filename and output filename. If ``--outfile`` is not
specified, the updated document will be printed to ``stdout``.

.. code-block:: bash

    $ ramrod_update.py --infile stix_doc.xml --outfile update_stix_doc.xml



Specifying Input And Output Versions
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,

By default, ``ramrod_update.py`` will inspect the input document for a version
number and assume that it wants to be updated to the latest version. However,
you can pass in ``--from`` and/or ``--to`` arguments to override this behavior.

To specify the output version, use the ``--to`` argument. The following example
shows how to translate a STIX v1.0 document to STIX v1.0.1:

.. code-block:: bash

    $ ramrod_update.py --infile stix_1.0_doc.xml --to 1.0.1


If the input document does not have a version number specified (it should!),
you can use the ``--from`` argument to declare the version of the document.
The following example shows how you might declare the input document to be
version STIX v1.1:

.. code-block:: bash

    $ ramrod_update.py --infile stix_unversioned_doc.xml --from 1.1


Handling Untranslatable Elements And Attributes
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,

Some STIX and CybOX constructs have changed a lot between revisions because of
growing requirements from community members, or bugfixes where the incorrect
data type was assigned to a field initially and needed to be corrected. Because
of this, sometimes a lossless update isn't possible.

By default, ``ramrod_update.py`` will inspect the input document for
untranslatable fields or ID collisions, and alert the user of their presence:

.. code-block:: bash

    $ ramrod_update.py --infile samples/stix_1.0_forcible.xml
    [!] Update Error: Found untranslatable fields in source document.
    [!] Found the following untranslatable items:
        Line 88: {http://stix.mitre.org/TTP-1}Attack_Pattern
        Line 71: {http://stix.mitre.org/TTP-1}Malware_Instance

At this point, users can decide to force the update process by using the
``--force`` or ``-f`` argument. This will remove the untranslatable items from
the document during the update process and attempt to render a schema-valid
document in the process.

.. note::

    STIX v1.1 and CybOX v2.1 introduced schema-enforced ID uniqueness
    constraints. If updating content that is older than STIX v1.1 or CybOX 2.1,
    non-unique IDs will halt an update process. Using ``--force`` will cause
    new, unique IDs to be generated and assigned to colliding nodes.