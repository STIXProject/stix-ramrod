# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO
import ramrod.utils as utils

class _BaseOptional(unittest.TestCase):
    UPDATER = None
    XML_OPTIONALS = None
    OPTIONAL_KLASS = None
    OPTIONAL_COUNT = None

    @classmethod
    def setUpClass(cls):
        cls.xml = StringIO(cls.XML_OPTIONALS)

    def test_optional_find(self):
        root = utils.get_etree_root(self.xml)
        optionals = self.OPTIONAL_KLASS.find(root)
        self.assertEqual(len(optionals), self.OPTIONAL_COUNT)

    def test_optional_removal(self):
        root = utils.get_etree_root(self.xml)
        updater = self.UPDATER()
        updater._update_optionals(root)
        optionals = self.OPTIONAL_KLASS.find(root)
        self.assertEqual(len(optionals), 0)


class _BaseTrans(unittest.TestCase):
    UPDATER = None
    XML = None
    TRANS_COUNT = None
    TRANS_KLASS = None
    TRANS_XPATH = None
    TRANS_VALUE = "TEST! TEST! TEST!"

    @classmethod
    def setUpClass(cls):
        cls.xml = StringIO(cls.XML)

    def test_trans_find(self):
        root = utils.get_etree_root(self.xml)
        to_trans = self.TRANS_KLASS._find(root)
        self.assertEqual(len(to_trans), self.TRANS_COUNT)


    def test_trans(self):
         root = utils.get_etree_root(self.xml)
         self.TRANS_KLASS.translate(root)

         updated_nodes = root.xpath(self.TRANS_XPATH,
                                    namespaces=self.UPDATER.NSMAP)

         for node in updated_nodes:
             if self.TRANS_VALUE:
                self.assertEqual(node.text, self.TRANS_VALUE)
             else:
                 self.assertTrue(node != None)


class _BaseDisallowed(unittest.TestCase):
    UPDATER = None
    DISALLOWED_KLASS = None
    DISALLOWED_COUNT = None
    XML = None

    @classmethod
    def setUpClass(cls):
        cls.xml = StringIO(cls.XML)

    def test_disallowed_find(self):
        root = utils.get_etree_root(self.xml)
        disallowed = self.DISALLOWED_KLASS.find(root)
        self.assertEqual(len(disallowed), self.DISALLOWED_COUNT)

    def test_clean(self):
        root = utils.get_etree_root(self.xml)
        results = self.UPDATER().clean(root)

        doc = results.document.as_element()
        disallowed = self.DISALLOWED_KLASS.find(doc)
        self.assertEqual(len(disallowed), 0)



class _BaseVocab(unittest.TestCase):
    UPDATER = None
    VOCAB_KLASS = None
    VOCAB_COUNT = None
    XML = None

    @classmethod
    def setUpClass(cls):
        cls.xml = StringIO(cls.XML)

    def test_find(self):
        root = utils.get_etree_root(self.xml)
        vocabs = self.VOCAB_KLASS.find(root)
        self.assertEqual(len(vocabs), self.VOCAB_COUNT)

    def test_vocab_update(self):
        root = utils.get_etree_root(self.xml)
        self.VOCAB_KLASS.update(root)

        vocabs = self.VOCAB_KLASS.find(root)
        self.assertEqual(len(vocabs), 0)
