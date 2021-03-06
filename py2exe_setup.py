import sys, platform
from os.path import join, dirname
from distutils.core import setup
import py2exe


#sys.path.append(join(dirname(__file__), 'shadowsocks'))
#sys.path.append(join(dirname(__file__), 'shadowsocks', 'crypto'))

with open('README.rst') as f:
    long_description = f.read()

setup(
    name="shadowsocks",
    version="2.3.2",
    license='MIT',
    description="A fast tunnel proxy that help you get through firewalls",
    author='clowwindy',
    author_email='clowwindy42@gmail.com',
    url='https://github.com/clowwindy/shadowsocks',
    packages=['shadowsocks', 'shadowsocks.crypto'],
    package_data={
        'shadowsocks': ['README.rst', 'LICENSE']
    },
    install_requires=[],
    console=["shadowsocks/local.py","shadowsocks/server.py"],
    entry_points="""
    [console_scripts]
    sslocal = shadowsocks.local:main
    ssserver = shadowsocks.server:main
    """,
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
