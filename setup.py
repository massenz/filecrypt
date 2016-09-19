# @copyright: AlertAvert.com (c) 2016. All rights reserved.

from setuptools import setup
from pypandoc import convert_file

#: Converts the Markdown README in the RST format that PyPi expects.
long_description = convert_file('README.md', 'rst')

setup(name='crytto',
      description='An OpenSSL-based file encryption and decryption utility',
      long_description=long_description,
      version='0.3.0',
      url='https://github.com/massenz/filecrypt',
      author='M. Massenzio',
      author_email='marco@alertavert.com',
      license='Apache2',
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 3'
      ],
      packages=['crytto'],
      install_requires=[
          'PyYAML>=3.11',
          'sh>=1.11'
      ],
      entry_points={
          'console_scripts': [
              'encrypt=crytto.main:run'
          ]
      }

      )
