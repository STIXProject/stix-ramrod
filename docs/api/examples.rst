Example Code
============

The following sections demonstrate how to use the **stix-ramrod** library to
update STIX content. For more details about the **stix-ramrod** API, see the
:doc:`/api/index` page.

Import stix-ramrod
^^^^^^^^^^^^^^^^^^

To use **stix-ramrod** for updating STIX and CybOX content, you must import
the ``ramrod`` module There are lots of functions, classes, and submodules
under ``ramrod``, but the top-level module is all you need for most updates!

.. code-block:: python

    import ramrod  # That's it!

Calling the ramrod.update() Function
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the imports are taken care of you only need to call the
:meth:`ramrod.update` method, which parses the content, updates it, and
returns an instance of :class:`ramrod.UpdateResults`.

.. code-block:: python

    import ramrod

    # Update the 'stix-content.xml' STIX document.
    updated = ramrod.update('stix-content.xml')

.. note::

    The example above passes the ``stix-content.xml`` filename into
    :meth:`ramrod.update`, but :meth:`ramrod.update` accepts file-like objects
    (such as files on disk or ``StringIO`` instances), ``etree._Element``
    instances, or ``etree._ElementTree`` instances. Neato!


Retrieving Updated Content
^^^^^^^^^^^^^^^^^^^^^^^^^^

After successfully calling :meth:`ramrod.update`, the update document can be
retrieved from the returned :class:`ramrod.UpdateResults` object instance via
the ``document`` attribute. The ``document`` attribute is an instance of
:class:`ramrod.ResultDocument`.

.. code-block:: python

    import ramrod
    from lxml import etree  # Used for printing the updated XML document

    # Update the document
    updated = ramrod.update('stix-content.xml')

    # Print the resulting document to stdout
    print updated

    # Retrieve the updated document from the returned UpdateResults object
    new_stix_doc = updated.document

    # Or retrieve the etree._Element root
    root = new_stix_doc.as_element()


Forcing An Update
^^^^^^^^^^^^^^^^^

Sometimes an update doesn't go smoothly and a :class:`ramrod.UpdateError`
is raised because untranslatable data or non-unique IDs are discovered in the
source document. The following code and output demonstrates how to force the
update and retrieve the data that is lost in the process.

.. testcode::

    import ramrod

    # Attempt to update an untranslatable document
    updated = ramrod.update('untranslatable-stix-content.xml')

The ``untranslatable-stix-content.xml`` contains untranslatable data, so a
:class:`ramrod.UpdateError` gets raised:

.. testoutput::

    ramrod.UpdateError: Update Error: Found untranslatable fields in source document.


To find out *exactly* what couldn't be translated, you can inspect the
``disallowed`` and ``duplicates`` attributes on the :class:`ramrod.UpdateError`
instance:

.. code-block:: python

    import ramrod

    try:
        # Attempt to update an untranslatable document
        updated = ramrod.update('untranslatable-stix-content.xml')
    except ramrod.UpdateError as ex:
        # Print untranslatable items
        for node in ex.disallowed:
            print "TAG: %s, LINE: %s" % (node.tag, node.sourceline)  # etree API

        # Print non-unique IDs and each line they're found on
        for id_, nodes in ex.duplicates.iteritems():
            print "ID: %s, LINES: %s" % (id_, [x.sourceline for x in nodes])

To force the update, pass in ``force=True`` to the :meth:`ramrod.update` method:

.. code-block:: python

    import ramrod

    # Force-update the document
    updated = ramrod.update('untranslatable-stix-content.xml', force=True)

After successfully force-updating the document, items that had IDs remapped
or that were lost in translation can be retrieved from the returned
:class:`ramrod.UpdateResults` object instance.

.. code-block:: python

    import ramrod

    # Force-update the document
    updated = ramrod.update('untranslatable-stix-content.xml', force=True)

    # Iterate over the items which were lost in translation
    for node in updated.removed:
        do_something_with_the_removed_item(node)

    # Iterate over the {id: [nodes]} dictionary containing nodes
    # with remapped IDs
    for original_id, node_list in updated.remapped_ids.iteritems():
        do_something_with_remapped_items(original_id, node_list)

Using the UpdateOptions Class
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Instances of the :class:`ramrod.UpdateOptions` class can be passed into the
:meth:`ramrod.update` method to tweak what gets updated in a STIX or CybOX
document.

The following example shows how to use the :class:`ramrod.UpdateOptions` class
to let the update code know **not** to update controlled vocabulary instances:

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    # Create the UpdateOptions instance
    options = ramrod.UpdateOptions()
    options.update_vocabularies = False  # Don't Update Vocabs!

    # Update the content
    updated = ramrod.update('stix-content.xml', options=options)

    # Print the results!
    print updated


Working with python-stix
^^^^^^^^^^^^^^^^^^^^^^^^

The `python-stix <http://stix.readthedocs.org>`_ library provides an API for
developing and consuming STIX content. The python-stix library is designed to
consume and produce specific versions of STIX, as detailed
`here <http://stix.readthedocs.org/en/latest/#versions>`_.

Because python-stix consumes specific versions of STIX content, older content
needs to be updated before it can be parsed. Luckily, updating old versions of
STIX content is easy with **stix-ramrod**!.

Example
~~~~~~~

The following example demonstrates one way of updating content so that
python-stix can parse it. This code works with python-stix v1.1.1.1.

.. code-block:: python

    import ramrod
    from stix.core import STIXPackage
    from stix.utils.parser import UnsupportedVersionError

    stix_filename = "stix-upgradable-content.xml"

    try:
        package = STIXPackage.from_xml(stix_filename)
    except UnsupportedVersionError as ex:
        updated  = ramrod.update(stix_filename)
        document = updated.document.as_stringio()
        package  = STIXPackage.from_xml(document)

    # Work with the parsed STIXPackage instance.
    print package.id_

.. note::

    The example above assumes that the input content can be upgraded without
    raising a :class:`ramrod.UpdateError` or any other exceptions.
