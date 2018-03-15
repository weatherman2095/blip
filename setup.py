from setuptools import setup

__version__ = "1.0.0"

setup(
    name='blip',
    version=__version__,
    url="https://github.com/weatherman2095/blip",
    author='Gabriel Lupien-Angell',
    author_email='g.lupien-angell@adgear.com',
    # tests_require=['pytest'],
    install_requires=['protobuf>=3.0.0',
                      'scapy-python3>=0.20.0',
                      'scapy-http'],
    dependency_links=['git+https://github.com/invernizzi/scapy-http@df0caa6f38a88e45f64dff0bb3cdfaceee270ae2#egg=scapy-http'],
    # cmdclass={'test': PyTest},
    description="Bid-Request Capture Program",
    long_description='blip is a simple python utility for capturing network traffic from a provided device or pcap file and extract wanted protobuf or JSON payloads for the sake of replaying them later with another utility.',
    packages=['blip'],
    include_package_data=True,
    platforms=['Linux', 'BSD'],
    # test_suite='',
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
    extras_require={
        # 'testing': ['pytest'],
    }
)
