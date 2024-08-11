import codecs
from setuptools import setup, find_packages

setup(
    name='fastaccesslimiter',
    version='0.9.0',
    description="A fast, lightweight, and full-featured IP address access limiter for any Python web framework or even any application that requires an IP access check. Supports IPv4 and IPv6 simultaneously. Can handle thousands of networks in your blocklist and gets responses in less than 0.000005 seconds. And it's pure Python!",
    url='https://github.com/rabuchaim/fastaccesslimiter',
    author='Ricardo Abuchaim',
    author_email='ricardoabuchaim@gmail.com',
    maintainer='Ricardo Abuchaim',
    maintainer_email='ricardoabuchaim@gmail.com',
    project_urls={
        "Issue Tracker": "https://github.com/rabuchaim/fastaccesslimiter/issues",
        "Source code": "https://github.com/rabuchaim/fastaccesslimiter"
    },    
    bugtrack_url='https://github.com/rabuchaim/fastaccesslimiter/issues',    
    license='MIT',
    keywords=['ratelimit','ratelimiter','fastaccesslimiter','api','rate limit','firewall','blocking','flask','tornado','django','pyramid','fastapi','bottle','purepython','pure','rules','tools'],
    packages=find_packages(),
    py_modules=['fastaccesslimiter', 'fastaccesslimiter'],
    package_dir = {'fastaccesslimiter': 'fastaccesslimiter'},
    include_package_data=True,
    zip_safe = False,
    package_data={
        'fastaccesslimiter': [
            'CHANGELOG.md', 
            'README.md',            
            'fastaccesslimiter/__init__.py', 
            'fastaccesslimiter/fastaccesslimiter.py'
            'fastaccesslimiter/test_fastaccesslimiter.py'
        ],
    },
    python_requires=">=3.7",    
    install_requires=[],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Internet :: Finger',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Localization',
        'Topic :: Utilities',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: Microsoft :: Windows :: Windows 11',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX :: BSD',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',  
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: Implementation :: PyPy',
        'License :: OSI Approved :: MIT License',
    ],
    long_description=codecs.open("README.md","r","utf-8").read(),
    long_description_content_type='text/markdown',
)