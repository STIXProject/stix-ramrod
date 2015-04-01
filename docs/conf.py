import os

import ramrod

project = u'stix-ramrod'
copyright = u'2015, The MITRE Corporation'
version = ramrod.__version__
release = version

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinxcontrib.napoleon',
]

intersphinx_mapping = {'http://docs.python.org/': None}

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

exclude_patterns = [
    '_build',
    '_includes',
    'updates/cybox/cybox*.rst',
    'updates/stix/stix*.rst'
]

pygments_style = 'sphinx'

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
if not on_rtd:  # only import and set the theme if we're building docs locally
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
else:
    html_theme = 'default'

html_show_sourcelink = False
htmlhelp_basename = 'stix-ramroddoc'

latex_elements = {}
latex_documents = [
  ('index', 'stix-ramrod.tex', u'stix-ramrod Documentation',
   u'The MITRE Corporation', 'manual'),
]
