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

    updated = ramrod.update('stix-content.xml')

The ``stix-content.xml`` contains untranslatable data, so a
:class:`ramrod.UpdateError` gets raised:

.. testoutput::

    ramrod.UpdateError: Update Error: Found untranslatable fields in source
    document.


So we pass in ``force=True`` to the :meth:`ramrod.update` method:

.. code-block:: python

    import ramrod

    updated = ramrod.update('stix-content.xml', force=True)

Once the :meth:`ramrod.update` call has been forced, we can collect the updated
document from the ``updated.document`` attribute.

.. code-block:: python

    import ramrod
    from lxml import etree  # used for printing the updated XML document

    updated = ramrod.update('stix-content.xml', force=True)

    new_stix_doc = updated.document
    print etree.tostring(new_stix_doc)

And inspect the removed and remapped items:

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    updated = ramrod.update('stix_content.xml', force=True)

    for node in updated.removed:
        do_something_with_the_removed_item(node)

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