# @copyright: AlertAvert.com (c) 2016. All rights reserved.

from setuptools import setup

try:
    from pypandoc import convert_file
    long_description = convert_file('README.md', 'md')
    long_description_content_type = "text/markdown"
except ImportError:
    long_description = """
    Encryption / Decryption utilities, based on OpenSSL and 
    public/private keypairs.
    
    Use the `encrypt` command to encrypt a plaintext file securely (and, optionally
    securely destroy it) and the `decrypt` command to restore it.
    
    More information at: https://github.com/massenz/filecrypt.
"""
    long_description_content_type = "text/plain"


setup(name='crytto',
      description='An OpenSSL-based file encryption and decryption utility',
      long_description_content_type=long_description_content_type,
      long_description=long_description,
      version='0.7.0',
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
              'encrypt=crytto.main:encrypt_cmd',
              'decrypt=crytto.main:decrypt_cmd',
              'prune_store=crytto.main:prune_cmd',
              'encrypt_send=crytto.main:send_cmd'
          ]
      })
