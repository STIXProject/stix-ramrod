Example Code
============

The following steps demonstrate how to use the **stix-ramrod** library to
update STIX content.

Import stix-ramrod
^^^^^^^^^^^^^^^^^^

To use **stix-ramrod** for basic updates, all you need to import is the
:mod:`ramrod` module.

.. code-block:: python

    import ramrod  # That's it!

Calling the ramrod.update() Function
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the imports are taken care of and the content is parsed, you only need to
call the :meth:`ramrod.update` method, which returns an instance of
:class:`ramrod.UpdateResults`, a ``namedtuple`` instance.

.. note::

    The example below passes the ``stix-content.xml`` filename into
    :meth:`ramrod.update`, but :meth:`ramrod.update` accepts file-like objects
    like files on disk or ``StringIO`` instances, ``etree._Element`` instances,
    or ``etree._ElementTree`` instances!

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    updated = ramrod.update('stix-content.xml')

Forcing An Update
^^^^^^^^^^^^^^^^^

Sometimes an update doesn't go smoothly and a :class:`ramrod.UpdateError`,
:class:`ramrod.InvalidVersionError`, or :class:`ramrod.UnknownVersionError` is
raised. The following code and output demonstrates how to force the update and
retrieve the lost data.

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

Once the :meth:`ramrod.update` call has been forced, we can collect the updated
document from the ``updated.document`` attribute.

.. code-block:: python

    import ramrod
    from lxml import etree  # Used for printing the updated XML document

    # Force-update the document
    updated = ramrod.update('untranslatable-stix-content.xml', force=True)

    # Retrieve the updated document from the returned UpdateResults object
    new_stix_doc = updated.document

    # Print the results
    print etree.tostring(new_stix_doc)

And inspect the removed and remapped items:

.. code-block:: python

    import ramrod

    # Force-update the document
    updated = ramrod.update('untranslatable-stix_content.xml', force=True)

    # Iterate over the items which were lost in translation
    for node in updated.removed:
        do_something_with_the_removed_item(node)

    # Iterate over the {id: [nodes]} dictionary containing nodes
    # with remapped IDs
    for original_id, node_list in updated.remapped.iteritems():
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
    print etree.tostring(updated.document)