Example Code
============

The following steps demonstrate how to use the **stix-ramrod** library to
update STIX content.

Import stix-ramrod
^^^^^^^^^^^^^^^^^^

To use **stix-ramrod** for basic updates, all you need to import are the
:mod:`ramrod` and ``lxml.etree`` modules:

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')

Calling the ramrod.update() Function
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once the imports are taken care of and the content is parsed, you only need to
call the :meth:`ramrod.update` method, which returns an instance of
:class:`ramrod.UpdateResults`, a ``namedtuple`` instance.

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')
    updated = ramrod.update(stix_content)

Forcing An Update
^^^^^^^^^^^^^^^^^

Sometimes an update doesn't go smoothly and a :class:`ramrod.UpdateError`,
:class:`ramrod.InvalidVersionError`, or :class:`ramrod.UnknownVersionError` is
raised. The following code and output demonstrates how to force the update and
retrieve the lost data.

.. testcode::

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')
    updated = ramrod.update(stix_content)

The ``stix_filename.xml`` contains untranslatable data, so a
:class:`ramrod.UpdateError` gets raised:

.. testoutput::

    ramrod.UpdateError: Update Error: Found untranslatable fields in source document.


So we pass in ``force=True`` to the :meth:`ramrod.update` method:

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')
    updated = ramrod.update(stix_content, force=True)

Once the :meth:`ramrod.update` call has been forced, we can collect the updated
document from the ``updated.document`` attribute.

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')
    updated = ramrod.update(stix_content, force=True)

    new_stix_doc = updated.document
    print etree.tostring(new_stix_doc)

And inspect the removed and remapped items:

.. code-block:: python

    import ramrod
    from lxml import etree  # used for parsing XML

    stix_content = etree.parse('stix_filename.xml')
    updated = ramrod.update(stix_content, force=True)

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

    # Parse the STIX content using lxml etree
    stix_content = etree.parse('stix_filename.xml')

    # Create the UpdateOptions instance
    options = ramrod.UpdateOptions()
    options.update_vocabularies = False  # Don't Update Vocabs!

    # Update the content
    updated = ramrod.update(stix_content, options=options)

    # Print the results!
    print etree.tostring(updated.document)