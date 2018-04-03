from setuptools import setup, find_packages

__version__ = "1.0.0"

setup(
    name='blip',
    version=__version__,
    url="https://github.com/weatherman2095/blip",
    author='Gabriel Lupien-Angell',
    author_email='g.lupien-angell@adgear.com',
    install_requires=['protobuf>=3.0.0',
                      'pcapy',
                      'dpkt'],
    description="Bid-Request Capture Program",
    long_description='blip is a simple python utility for capturing network traffic from a provided device or pcap file and extract wanted protobuf or JSON payloads for the sake of replaying them later with another utility.',
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    entry_points={
        'console_scripts' : [
            'blip = blip.blip:main',
            'blip_showdb = blip.encoding:print_contents_cli',
        ]
    },
    platforms=['Linux', 'BSD'],
    keywords="Networking, Packet Filtering, Berkeley Packet Filter syntax, HTTP, JSON, protobuf",
    classifiers = [
        'Programming Language :: Python',
        'Topic :: System :: Networking :: Monitoring',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX :: Other',
        'Operating System :: POSIX :: BSD',
        'Topic :: System :: Networking',
        'Topic :: System :: Logging',
        'Environment :: Console',
        'Topic :: Internet',
        ],
    cmdclass={},
    test_suite='test',
    tests_require=[],
    extras_require={},
    include_package_data=True,
)
