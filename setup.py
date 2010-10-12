# -*- coding: utf-8 -*-
"""
This module contains the tool of pas.plugins.suisseid
"""
import os
from setuptools import setup, find_packages

def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

version = '0.1'

long_description = (
    read('README.txt')
    + '\n' +
    'Change history\n'
    '**************\n'
    + '\n' +
    read('CHANGES.txt')
    + '\n' +
    'Detailed Documentation\n'
    '**********************\n'
    + '\n' +
    read('pas', 'plugins', 'suisseid', 'README.txt')
    + '\n' +
    'Contributors\n'
    '************\n'
    + '\n' +
    read('CONTRIBUTORS.txt')
    + '\n' +
    'Download\n'
    '********\n'
    )

setup(name='pas.plugins.suisseid',
      version=version,
      description="",
      long_description=long_description,
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        'Environment :: Web Environment',
        'Framework :: Zope2',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: System :: Systems Administration :: Authentication/Directory'
        ],
      keywords='',
      author='Seantis GmbH',
      author_email='info@seantis.ch',
      url='http://www.seantis.ch',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['pas', 'pas.plugins', ],
      include_package_data=True,
      zip_safe=True,
      install_requires=['setuptools',
                        'httplib2',
                        'python-dateutil',
                        'Products.PluggableAuthService',
                        'Acquisition',
                        'Zope2',
                        # -*- Extra requirements: -*-
                        ],
      )
