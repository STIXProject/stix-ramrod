# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from . import utils


class UpdateOptions(object):
    """Defines configurable options for STIX/CybOX updates.

    Attributes:
        check_versions: If ``True``, input document version information
            will be collected and checked against what the Updater class
            expects. If ``False`` no version check operations will be performed.
            Default value is ``True``.
        new_id_func: A function for setting new IDs on an ``etree._Element``
            node. The function must accept one ``etree._Element`` instance
            argument and assign it a new, unique ``id`` attribute value.
            Default value is :meth:`ramrod.utils.new_id` function.

            Example:
                >>> def my_id_func(node):
                >>>     new_id = my_generate_unique_id()
                >>>     node.attrib['id'] = new_id
                >>>
                >>> options = ramrod.UpdateOptions()
                >>> options.new_id_func = my_id_func

        update_vocabularies: If ``True``, default controlled vocabulary
            instances will be updated and typos will be fixed. If ``False``,
            no updates will be performed against controlled vocabulary
            instances. Default is ``True``.
        remove_optionals: Between revisions of language, some elements which
            were required are made optional. If ``True``, an attempt is made
            to find and remove empty instances of once required
            elements/attributes. Default is ``True``.

    """
    def __init__(self):
        self.check_versions = True
        self.new_id_func = utils.new_id
        self.update_vocabularies = True
        self.remove_optionals = True


DEFAULT_UPDATE_OPTIONS = UpdateOptions()


__all__ = [
    'UpdateOptions',
    'DEFAULT_UPDATE_OPTIONS'
]
