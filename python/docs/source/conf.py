import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

project = 'GoodCam Device Proxy'
copyright = '2022, GoodCam'
author = 'GoodCam'
release = '0.1.0'

extensions = [
    'sphinx.ext.autodoc',
]

templates_path = ['_templates']
exclude_patterns = []
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
autodoc_class_signature = 'separated'
