# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import collections

# external
from lxml import etree

# relative
from . import errors, utils, xmlconst, results
from .options import DEFAULT_UPDATE_OPTIONS


# Constants
TAG_VOCAB_REFERENCE = "vocab_reference"
TAG_VOCAB_NAME = 'vocab_name'


class Vocab(object):
    """Controlled Vocabulary update class. This is used on conjunction with a
    dictionary which maps found controlled vocabulary instance names to _Vocab
    implementation classes.

    Attributes:
        VOCAB_NAMESPACE: The namespace which contains the controlled vocabulary
            definition.
        OLD_TYPES: A tuple of XSD type names which when discovered will be
            upgraded.
        NEW_TYPE: The XSD type name for the updated controlled vocabulary
        VOCAB_REFERENCE: The ``vocab_reference`` xml attribute text.
        VOCAB_NAME: The ``vocab_name`` xml attribute text.
        TERMS (dict): A dictionary of vocabulary term mappings. This is useful
            for typo corrections between controlled vocabulary revisions.

    """
    VOCAB_NAMESPACE = None
    OLD_TYPES = ()
    NEW_TYPE = None
    VOCAB_REFERENCE = None
    VOCAB_NAME = None
    TERMS = {}

    @classmethod
    def find(cls, root, typed=None):
        """Finds and returns a list of nodes that are instances of old
        controlled vocabularies.

        """
        if typed is None:
            typed = utils.get_typed_nodes(root)

        found = []
        for node in typed:
            _, typename = utils.get_type_info(node)
            ext_ns = utils.get_ext_namespace(node)

            if ext_ns != cls.VOCAB_NAMESPACE:
                continue
            elif typename not in cls.OLD_TYPES:
                continue
            else:
                found.append(node)

        return found

    @classmethod
    def update(cls, root, typed=None):
        """Updates controlled vocabularies found under the `root` document.

        This performs the following updates:
        * Updates ``xsi:type`` attribute to refer to the new type name.
        * Updates terms to align with new vocabulary in the case of typo fixes.
        * Updates ``vocab_name`` attribute value if present.
        * Updates ``vocab_reference`` attribute value if present.

        """
        if typed is None:
            typed = utils.get_typed_nodes(root)

        vocabs = cls.find(root, typed)

        for node in vocabs:
            alias, _ = utils.get_type_info(node)

            attribs    = node.attrib
            terms      = cls.TERMS
            new_type   = cls.NEW_TYPE
            vocab_ref  = cls.VOCAB_REFERENCE
            vocab_name = cls.VOCAB_NAME

            # Update the xsi:type attribute to identify the new
            # controlled vocabulary
            new_xsi_type = "%s:%s" % (alias, new_type)
            attribs[xmlconst.TAG_XSI_TYPE] = new_xsi_type

            # Update the vocab_reference attribute if present
            if TAG_VOCAB_REFERENCE in attribs:
                attribs[TAG_VOCAB_REFERENCE] = vocab_ref

            # Update the vocab_name attribute if present
            if TAG_VOCAB_NAME in attribs:
                attribs[TAG_VOCAB_NAME] = vocab_name

            # Update the node value if there is a new value in the updated
            # controlled vocabulary
            value = node.text
            if value in terms:
                node.text = terms[value]


class TranslatableField(object):
    """Helper class for translating field instances between versions of a
    language specifications.

    Note:
        The methods defined here may not (likely will not) apply to every
        translation scenario. As such, it is encouraged to override any/all
        of these methods for specific translation requirements.

    Attributes:
        NSMAP: A dictionary of namespace aliases => namespaces used in xpaths
            and type lookups.
        XPATH_NODE: An xpath which locates instances of the field to be
            translated.
        XPATH_VALUE: An xpath to be applied to the nodes discovered via
            `XPATH_NODE` which extracts the value.
        NEW_TAG: The etree tag for the translated field.
        COPY_ATTRIBUTES (boolean): If true, attributes are copied from the node
            discovered by `XPATH_VALUE` to the translated field.
        OVERRIDE_ATTRIBUTES (dict): A dictionary of attribute names => value to
            override during the translation. This will only update existing
            attributes--not add them.

    """
    NSMAP = None
    XPATH_NODE = None
    XPATH_VALUE = '.'
    NEW_TAG = None
    COPY_ATTRIBUTES = False
    OVERRIDE_ATTRIBUTES = {}

    @classmethod
    def _translate_value(cls, old, new):
        xpath, nsmap = cls.XPATH_VALUE, cls.NSMAP
        if xpath:
            value = old.xpath(xpath, namespaces=nsmap)[0]
            new.text = value.text
        else:
            # Used when the fields are the same data type, just different names
            new[:] = old[:]  # TODO: verify that namespaces don't get messed up here

    @classmethod
    def _translate_attributes(cls, old, new):
        """Copies attributes from `old` to `new` (discovered by `XPATH_VALUE`
        or the `old` node ``text`` value).

        If `COPY_ATTRIBUTES` is set to ``True``, attributes from the `old` node
        value are copied to `new`. If an attribute is found that matches a key
        in `OVERRIDE_ATTRIBUTES`, its value is overridden by the value found in
        `OVERRIDE_ATTRIBUTES`.

        """
        xpath, nsmap = cls.XPATH_VALUE, cls.NSMAP

        if xpath:
            source = old.xpath(xpath, namespaces=nsmap)[0]
        else:
            source = old

        if cls.COPY_ATTRIBUTES:
            new.attrib.update(source.attrib)

        for name, val in cls.OVERRIDE_ATTRIBUTES.iteritems():
            if name not in source.attrib:
                continue
            new.attrib[name] = val

    @classmethod
    def _translate_fields(cls, node):
        """Translates values and attributes from `node` to a new XML
        element.

        Returns:
            A translated ``etree._Element``.
        """
        tag = cls.NEW_TAG or node.tag
        new = etree.Element(tag)

        cls._translate_value(node, new)
        cls._translate_attributes(node, new)

        return new

    @classmethod
    def _find(cls, root):
        """Discovers translatable fields in the `root` document.

        Returns:
            A list of nodes discovered via the `XPATH_NODE` xpath.

        """
        return root.xpath(cls.XPATH_NODE, namespaces=cls.NSMAP)

    @classmethod
    def translate(cls, root):
        """Translates and replaces nodes found in `root` with new nodes.

        """
        nodes = cls._find(root)

        for node in nodes:
            new_node = cls._translate_fields(node)
            utils.replace_xml_element(node, new_node)


class RenamedField(TranslatableField):
    """Extension to ``_TranslatableField`` that only performs a renaming
    operation on discovered nodes.

    Note:
        The name of the node is defined by the `NEW_TAG` class-level attribute.

    """
    @classmethod
    def translate(cls, root):
        nodes = cls._find(root)

        for node in nodes:
            node.tag = cls.NEW_TAG


class DisallowedFields(object):
    """Helper class used to discover untranslatable fields within an XML
    instance document.

    Attributes:
        CTX_TYPES: A dictionary of xsi:type contexts to look for or within. If
            CTX_TYPES is ``None`` or empty, the root node is used as the
            context for xpaths.
        XPATH: An xpath used to discover nodes under the contexts determined
            by `CTX_TYPES`. By default, `XPATH` is ``'.'``, meaning the
            context nodes are returned by the `XPATH` by default.
        NSMAP: A dictionary of namespace aliases => namespaces. Used for xpath
            evaluation.

    """
    CTX_TYPES = {}
    XPATH = "."
    NSMAP = {}

    def __init__(self,):
        pass

    @classmethod
    def _interrogate(cls, nodes):
        """Overriden by implemmentation classes if a set of requirments must
        be evaluated before a node is considered untranslatable.

        For example, the `_interrogate()` method could only consider a node
        untranslatable if it has more than one child node.

        Args:
            nodes: A list of nodes to interrogate for untranslatable
                properties.

        Returns:
            A list of untranslatable nodes. By default, this method does not
            perform any inspection of `nodes` and only returns `nodes`.

        """
        return nodes

    @classmethod
    def _get_contexts(cls, root, typed=None):
        """Returns context nodes under `root` discovered by `CTX_TYPES`.

        If `CTX_TYPES` is ``None`` or empty, The entire `root` node is
        considered to be the context for the class-level `XPATH`.

        Args:
            root: The root node for an XML instance document.
            typed: xsi:typed nodes to search through when looking for
                context nodes. If ``None``, the entire `root` document will be
                searched for xsi:typed nodes that match the names and namespaces
                declared by `CTX_TYPES`. This is provided to speed up
                context node discovery.

        Returns:
            A list of context nodes for `XPATH` to be evaluated against.

        """
        ctx = cls.CTX_TYPES

        if not ctx:
            return (root,)

        if typed is None:
            typed = utils.get_typed_nodes(root)

        contexts = []
        for node in typed:
            type_ = utils.get_type_info(node)[1]
            ns = utils.get_ext_namespace(node)

            if ctx.get(type_) == ns:
                contexts.append(node)

        return contexts

    @classmethod
    def find(cls, root, typed=None):
        """Finds disallowed (untranslatable) fields under the `root` node.

        Returns:
            A list of disallowed or untranslatable nodes.

        """
        contexts = cls._get_contexts(root, typed)
        xpath, nsmap = cls.XPATH, cls.NSMAP

        found = []
        for ctx in contexts:
            nodes = ctx.xpath(xpath, namespaces=nsmap)
            interrogated = cls._interrogate(nodes)
            found.extend(interrogated)

        return found


class OptionalAttributes(DisallowedFields):
    """Helper class for discovering empty, optional attributes.

    There are cases where one revision of STIX/CybOX required the presence
    of an attribute which became optional in later revisions. This enables the
    discovery of these attributes which may be present in the input document
    only for schema-validation reasons.

    Attributes:
        ATTRIBUTES: A tuple of attribute tags to look for.

    """
    ATTRIBUTES = ()

    def __init__(self):
        super(OptionalAttributes, self).__init__()

    @classmethod
    def _interrogate(cls, nodes):
        """Inspects each node in `nodes` for the presence of empty attributes
        defined in `ATTRIBUTES`.

        Note:
            This overrides the `_interrogate()` method implemented in
            ``_DisallowedFields``.

        Returns:
            A list of nodes containing empty attributes defined in `ATTRIBUTES`.

        """
        contraband = []
        attrs = cls.ATTRIBUTES

        def is_empty(node, attr):
            if attr in node.attrib:
                val = node.attrib[attr]
                return len(val) == 0
            else:
                return False

        for node in nodes:
            if not any(is_empty(node, x) for x in attrs):
                continue
            contraband.append(node)

        return contraband


class OptionalElements(DisallowedFields):
    """Helper class for discovering empty, optional elements.

    There are cases where one revision of STIX/CybOX required the presence
    of an element which became optional in later revisions. This enables the
    discovery of elements which may be present in the input document only for
    the sake of schema-validation.

    """
    def __init__(self):
        super(OptionalElements, self).__init__()

    @classmethod
    def _is_empty(cls, node):
        """Returns ``False`` if `node` or any of its descendants contain
        attributes or text values.

        """
        nodes = node.iter('*')
        content = any(x.attrib or utils.strip_whitespace(x.text) for x in nodes)
        return content is False

    @classmethod
    def _interrogate(cls, nodes):
        """Checks if any of the nodes in `nodes` are empty.

        Note:
            A node is considered to be emtpy if it has no attributes, no text
            value, and no children with content (attribs or text content).
            These criterion may be overridden by implementations of this class.

        Returns:
            A list of nodes that are empty.

        """
        return [x for x in nodes if cls._is_empty(x)]


class BaseUpdater(object):
    """The base class for all STIX and CybOX updater code.

    Attributes:
        VERSION: Specifies the base langauge version for an updater
            implementation. For example, a STIX v1.0 updater would use '1.0'.
        NSMAP: A dictionary of namespace aliases => namespaces for a given
            language version. This is used for xpath evaluation and xsi:type
            lookup.
        DISALLOWED_NAMESPACES: A tuple of namespaces which cannot be translated
            during the update process. These namespaces will be stripped and
            not appear in the export document.
        UPDATE_NS_MAP: A dictionary of namespaces that are updated between
            language revisions. For example, CybOX 2.1 defines a new namespace
            for the Windows Driver Object. This dictionary would contain the
            old namespace as a key, and the new namespace as a value.
        UPDATE_SCHEMALOC_MAP: A dictionary of language namespaces to their
            updated schemalocations. If a namespace has been updated between
            langauge revisions, the new namespace will be used as the key (as
            is in the case of the CybOX 2.0.1 updater and the Windows Driver
            Object namespace).
        DEFAULT_VOCAB_NAMESPACE: The namespace for the default vocabulary
            schema.
        UPDATE_VOCABS: A tuple of ``_Vocab`` derivations
        XPATH_VERSIONED_NODES: An xpath which discovers all versioned nodes
            that need to be updated within the source document.
        XPATH_ROOT_NODES: An xpath which discovers all "root" nodes
            (implementations of ``STIXType and ObservablesType``) which may
            contain document-level version information.
        DISALLOWED: An iterable collection of DisallowedFields instances.
        OPTIONAL_ELEMENTS: An iterable collection of OptionalElements
            instances.
        OPTIONAL_ATTRIBUTES: An iterable collection of OptionalAttributes
            instances.
        TRANSLATABLE_FIELDS: An iterable collection of TranslatableField
            instances.
        cleaned_fields: A tuple of untranslatable nodes which were removed
            during a forced `update` or `clean` process.
        cleaned_ids: A dictionary of id => [nodes] which contains a list of
            nodes which have had their originally non-unique ids remapped to
            unique ids. This is only populated in a forced `update` or
            `clean` process.

    """
    # OVERRIDE THESE IN IMPLEMENTATIONS
    VERSION = None
    DISALLOWED_NAMESPACES = ()
    NSMAP = {}
    UPDATE_NS_MAP = {}
    UPDATE_SCHEMALOC_MAP = {}

    # Controlled Vocabularies
    DEFAULT_VOCAB_NAMESPACE = None
    UPDATE_VOCABS = ()

    XPATH_VERSIONED_NODES = "."
    XPATH_ROOT_NODES = "."

    DISALLOWED = ()
    OPTIONAL_ELEMENTS = ()
    OPTIONAL_ATTRIBUTES = ()
    TRANSLATABLE_FIELDS = ()

    def _is_leaf(self, node):
        """Returns ``True`` if the `node` has no children."""
        return len(node.xpath(xmlconst.XPATH_RELATIVE_CHILDREN)) == 0

    def _get_ns_alias(self, root, ns):
        """Returns the XML Namespace alias defined for a namespace in a given
        instance document.

        Args:
            root (lxml.etree._Element): The instance document root node.
            ns (string): A namespace in the instance document

        Returns:
            A string namespace alias for the given ``ns`` namespace. If the
            namespace is not found in the ``root`` instance document, ``None``
            is returned.

        """
        return root.nsmap.get(ns)

    def _get_duplicates(self, root):
        """This checks `root` for nodes with duplicate IDs.

        Returns:
            A dictionary where the ID is the key and the values are lists of
            lxml._Element nodes.

        """
        namespaces = self.NSMAP.values()
        id_nodes = collections.defaultdict(list)

        for desc in utils.iterdescendants(root):
            if 'id' not in desc.attrib:
                continue

            ns = utils.get_namespace(desc)

            if ns not in namespaces:
                continue

            id_ = desc.attrib['id']
            id_nodes[id_].append(desc)

        filtered = {}
        for id_, nodes in id_nodes.iteritems():
            if len(nodes) > 1:
                filtered[id_] = nodes

        return filtered

    def _get_versioned_nodes(self, root):
        """Discovers all versioned nodes under `root` defined by the class-level
        `XPATH_VERSIONED_NODES` xpath.

        Args:
            root: The root node to search under.

        Returns:
            A list of nodes discovered by evaluating the class-level
            `XPATH_VERSIONED_NODES` xpath.

        """
        xpath = self.XPATH_VERSIONED_NODES
        namespaces = self.NSMAP
        return root.xpath(xpath, namespaces=namespaces)

    def _get_root_nodes(self, root):
        """Discovers all versioned nodes under `root` defined by the class-level
        `XPATH_ROOT_NODES` xpath. This is used primarily when trying to
        determine the language version of the input document.

        Args:
            root: The root node to search under.

        Returns:
            A list of nodes discovered by evaluating the class-level
            `XPATH_ROOT_NODES` xpath.

        """
        xpath = self.XPATH_ROOT_NODES
        namespaces = self.NSMAP
        return root.xpath(xpath, namespaces=namespaces)

    def _check_version(self, root):
        """Checks that the version of the document matches the expected
        version. Derived classes need to implement this method.

        Note:
            This must be implemented by derived classes.

        Raises:
            NotImplementedError: If a derived class does not implement this
                method.

        """
        raise NotImplementedError()

    def _update_vocabs(self, root):
        """Updates controlled vocabularies found under the `root` document.

        This performs the following updates:
        * Updates ``xsi:type`` attribute to refer to the new type name.
        * Updates terms to align with new vocabulary in the case of typo fixes.
        * Updates ``vocab_name`` attribute value if present.
        * Updates ``vocab_reference`` attribute value if present.

        Vocabulary updates are dictated by the `UPDATE_VOCABS` class-level
        attribute.

        """

        typed_nodes = utils.get_typed_nodes(root)

        for vocab in self.UPDATE_VOCABS:
            vocab.update(root, typed=typed_nodes)

    def _remove_schemalocations(self, root):
        """Removes the ``xsi:schemaLocation`` attribute from `root`."""
        utils.remove_xml_attribute(root, xmlconst.TAG_SCHEMALOCATION)

    def _create_schemaloc_str(self, pairs):
        """Creates a valid ``xsi:schemaLocation`` string from the `pairs`
        list of ``(namespace, schemalocation)`` tuples.

        Args:
            pairs: list of tuples containing (ns, schemaloc).

        Returns:
            An ``xsi:schemaLocation`` value string.

        """
        schemaloc_str = "   ".join("%s %s" % (ns, loc) for ns, loc in pairs)
        return schemaloc_str

    def _clean_schemalocs(self, pairs):
        """Returns a list of ``(namespace, schemalocation)`` tuples that are
        allowed for the updated document.

        Args:
            pairs: a list of (namespace, schemalocation) tuples.

        Note:
            If a namespaces that exist in `DISALLOWED_NAMESPACES` will not be
            found in the return value.

        """
        disallowed = self.DISALLOWED_NAMESPACES
        return [(ns, loc) for ns, loc in pairs if ns not in disallowed]

    def _remap_schemalocs(self, pairs):
        """Updates the ``xsi:schemaLocation`` value to use namespaces and
        schemalocations for the next langauge revision.

        Args:
            pairs: A list of (namespace, schemalocation) tuples.

        Returns:
            A list of updated (namespace, schemalocation) tuples.

        """
        remapped = []

        for ns, loc in pairs:
            updated_ns  = self.UPDATE_NS_MAP.get(ns, ns)
            updated_loc = self.UPDATE_SCHEMALOC_MAP.get(updated_ns, loc)
            remapped.append((updated_ns, updated_loc))

        return remapped

    def _update_schemalocs(self, root):
        """Updates the schemalocations found on `root` to point to
        the schemalocations for the next language version.

        The new schemalocations are defined by the ``UPDATE_SCHEMALOC_MAP``
        class-level attribute.

        Args:
            root (lxml.etree._Element): The top-level xml node.

        """
        if xmlconst.TAG_SCHEMALOCATION not in root.attrib:
            return

        schemalocs = utils.get_schemaloc_pairs(root)
        cleaned = self._clean_schemalocs(schemalocs)
        remapped = self._remap_schemalocs(cleaned)
        updated = self._create_schemaloc_str(remapped)

        root.attrib[xmlconst.TAG_SCHEMALOCATION] = updated

    def _apply_namespace_updates(self, root):
        """Updates the children of `root` to be defined under their updated
        namespace.

        This uses the `UPDATE_NS_MAP` attribute to look up and assign
        an updated namespace to a node.

        If this isn't done, the node will retain its old namespace and receive
        a new `ns0` namespace alias.

        """
        for node in utils.iterdescendants(root):
            node_ns = utils.get_namespace(node)
            updated_ns = self.UPDATE_NS_MAP.get(node_ns, node_ns)
            node.tag = node.tag.replace(node_ns, updated_ns)

    def _remap_namespaces(self, node):
        """Remaps the namespaces found on the input `node` to namespaces
        defined by the ``UPDATE_NS_MAP``. If a namespace for a disallowed
        field/type is discovered, it is removed.

        Note:
            Disallowed namespaces are defined by the ``DISALLOWED_NAMESPACES``
            class-level attribute.

        Args:
            node (lxml.etree._Element): An ``etree`` XML node..

        Returns:
            A dictionary of aliases to namespaces.

        """
        remapped = {}
        for alias, ns in node.nsmap.iteritems():
            if ns in self.DISALLOWED_NAMESPACES:
                continue

            remapped[alias] = self.UPDATE_NS_MAP.get(ns, ns)

        return remapped

    def _get_remapped_tag(self, node):
        """Returns a new tag for `node` which includes an updated namespace
        portion of the tag. This is determined by looking up the tag
        namespace in the ``UPDATE_NS_MAP`` class dictionary.

        Returns:
            A new tag for `node` which contains an updated namespace.

        """
        namespace = utils.get_namespace(node)
        localname = utils.get_localname(node)
        updated_ns = self.UPDATE_NS_MAP.get(namespace, namespace)

        return "{%s}%s" % (updated_ns, localname)

    def _update_tag(self, node):
        """Updates the tag for `node` which a tag that includes an updated
        namespace. This is driven by the ``UPDATE_NS_MAP`` class attribute.

        Returns:
            `node` with an updated tag that includes a new namespace if the
            original namespace existed in ``UPDATE_NS_MAP``.

        """
        node.tag = self._get_remapped_tag(node)
        return node

    def _update_nsmap(self, node):
        """Updates the ``nsmap`` attribute found on `node` to `nsmap`.

        The lxml API does not allow in-place modification of the ``nsmap``
        dictionary. Instead, a copy of the node must be created and initialized
        with an updated ``nsmap`` attribute.

        Args:
            node (lxml.etree._Element): An XML element
            nsmap: A ``namspace alias => namespace`` dictionary.

        Returns:
            A copy of `root` with its ``nsmap`` attribute set to `nsmap`.

        """
        tag = self._get_remapped_tag(node)
        updated_nsmap = self._remap_namespaces(node)
        new  = etree.Element(tag, nsmap=updated_nsmap)
        new.attrib.update(node.attrib)
        new.text  = utils.get_node_text(node)
        new[:] = node[:]

        return new

    def _update_namespaces(self, node):
        """Updates the namespaces in the instance `node` to align with
        with the updated schema. This will also remove any disallowed
        namespaces if found in the instance document.

        Note:
            Only nodes that exist within the namespaces defined by
            the ``NS_MAP`` class attribute will be updated.

        Note:
            The lxml library does not allow you to modify the ``nsmap``
            attribute of an ``_Element`` directly. To modify the ``nsmap``,
            A copy of `root` must be made with a new initial ``nsmap``.

        Returns:
            A copy of the `node` with an updated ``nsmap`` attribute. Each
            of its descendants which belong to known namespaces are updated
            as well.

            If `node` is not an ``etree._Element`` (e.g, a comment node),
            or it does not belong to any namespace defined in the class-level
            ``NSMAP``, then this function returns `node` itself.

        """
        ns = utils.get_namespace(node)
        namespaces = self.NSMAP.itervalues()

        if ns not in namespaces:
            return node

        for child in utils.children(node):
            self._update_namespaces(child)

        new_node = self._update_nsmap(node)
        utils.replace_xml_element(node, new_node)
        return new_node

    def _create_update_results(self, root, remapped=None, removed=None):
        """Creates and returns a :class:`UpdateResults` object instance
        from the input `root` parameter, and the class instance attributes
        ``cleaned_ids`` and ``cleaned_fields``.

        Args:
            root: An instance of ``etree._Element`` or ``etree._ElementTree``.

        Returns:
            An instance of ``ramrod.UpdateResults``.

        """
        update_results = results.UpdateResults(root)
        update_results.remapped_ids = remapped or ()
        update_results.removed = removed or {}

        return update_results

    def _get_disallowed(self, root, options):
        raise NotImplementedError()

    def _clean_disallowed(self, disallowed, options):
        raise NotImplementedError()

    def _clean_duplicates(self, duplicates, options):
        raise NotImplementedError()

    def _clean(self, root, options):
        """Internal handler for public ``clean()`` method. Orchestrates the
        invocation of sub-cleaning methods (e.g., ``_clean_disallowed()``).

        """
        options = options or DEFAULT_UPDATE_OPTIONS
        disallowed = self._get_disallowed(root, options=options)
        duplicates = self._get_duplicates(root)
        remapped, removed = {}, ()

        if duplicates:
            remapped = self._clean_duplicates(duplicates, options=options)

        if disallowed:
            removed = self._clean_disallowed(disallowed, options=options)

        result = results.UpdateResults(root)
        result.remapped_ids = remapped
        result.removed = tuple(removed)

        return result

    def clean(self, root, options=None):
        """Removes disallowed elements from `root` and remaps non-unique
        IDs to unique IDs for the sake of schema-validation.

        Removed items can be retrieved via the ``removed`` attribute on the
        return value:

        >>> results = updater.clean(root)
        >>> print results.removed
        (<Element at 0xffdcf234>, <Element at 0xffdcf284>)

        Items which have been reassigned IDs can be retrieved via the
        ``remapped_ids`` attribute on the return value:

        >>> results = updater.clean(root)
        >>> print results.remapped_ids
        {'example:Observable-duplicate': [<Element {http://cybox.mitre.org...

        Note:
            This does not remap ``idref`` attributes to new ID values because
            it is impossible to determine which entity the ``idref`` was
            pointing to.

        Args:
            root: The XML document. This can be a filename, a file-like object,
                an instance of ``etree._Element`` or an instance of
                ``etree._ElementTree``.
            options (optional): A :class:`ramrod.UpdateOptions` instance. If
                ``None``,  ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.

        Returns:
            An instance of
            :class:`ramrod.UpdateResults`.

        """
        root = utils.get_etree_root(root, make_copy=True)
        results = self._clean(root, options)
        return results

    def check_update(self, root, options=None):
        """Checks to see if the `root` document can be updated.

        Note:
            This needs to be overidden by an implementation class.

        Raises:
            NotImplementedError: If this is called directly from _BaseUpdater.

        """
        raise NotImplementedError()

    def _force_update(self, root, options):
        """Removes untranslatable fields from the `root` document and calls
        ``self._update(...)``.

         Returns:
            An instance of ``ramrod.UpdateResults`` for the updated document.

        """
        # Clean the document
        cleaned_results = self._clean(root, options)
        cleaned_doc = cleaned_results.document.as_element()
        remapped = cleaned_results.remapped_ids
        removed = cleaned_results.removed

        # Update the document
        updated = self._update(cleaned_doc, options)
        results = self._create_update_results(
            root=updated,
            remapped=remapped,
            removed=removed
        )

        return results

    def _update(self, root, options):
        """Abstract method that needs to be overriden by concrete base
        classes.

        """
        raise NotImplementedError()

    def update(self, root, options=None, force=False):
        """Attempts to update `root` to the next version of its language
        specification.

        If `force` is set to True, items may be removed during the
        translation process and IDs may be reassigned if they are not
        unique within the document.

        Note:
            This does not remap ``idref`` attributes to new ID values because
            it is impossible to determine which entity the ``idref`` was
            pointing to.

        Removed items can be retrieved via the ``removed`` attribute on the
        return value:

        >>> results = updater.update(root, force=True)
        >>> print results.removed
        (<Element at 0xffdcf234>, <Element at 0xffdcf284>)

        Items which have been reassigned IDs can be retrieved via the
        ``remappped_ids`` attribute on the return value:

        >>> results = updater.update(root, force=True)
        >>> print results.remapped_ids
        {'example:Observable-duplicate-id-1': [<Element {http://cybox.mitre...

        Args:
            root: The XML document. This can be a filename, a file-like object,
                an instance of ``etree._Element`` or an instance of
                ``etree._ElementTree``.
            options: A :class:`ramrod.UpdateOptions` instance. If ``None``,
                ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.
            force: Forces the update process to complete by potentially
                removing untranslatable xml nodes and/or remapping non-unique
                IDs. This may result in non-schema=conformant XML. **USE AT
                YOUR OWN RISK!**

        Returns:
            An instance of ``ramrod.UpdateResults``.

        Raises:
            .UpdateError: If untranslatable fields or non-unique IDs are
                discovered in `root` and `force` is ``False``.
            .UnknownVersionError: If the `root` node contains no version
                information.
            .InvalidVersionError: If the `root` node contains invalid
                version information (e.g., the class expects v1.0 content and
                the `root` node contains v1.1 content).

        """
        root = utils.get_etree_root(root, make_copy=True)
        options = options or DEFAULT_UPDATE_OPTIONS

        try:
            self.check_update(root, options)
            updated = self._update(root, options)
            results = self._create_update_results(updated)
        except (errors.UpdateError, errors.UnknownVersionError, errors.InvalidVersionError):
            if force:
                results = self._force_update(root, options)
            else:
                raise

        return results
