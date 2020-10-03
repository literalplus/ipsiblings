import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ipsiblings-bitcoin-pnowak",
    version="0.0.1.dev1",
    author="Marco Starke, Philipp Nowak",
    author_email="git@lit.plus",
    description="IP Siblings Toolkit, adapted to measure Bitcoin nodes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.sba-research.org/johanna/bitcoin_siblings_philipp_nowak",
    packages=setuptools.find_packages(include=['ipsiblings', 'ipsiblings.*']),
    install_requires=[
        'scapy~=2.4.4',
        'netifaces~=0.10.9',
        'numpy~=1.19.2',
        'scipy~=1.4.1',
        'pandas~=1.0.4',
        'matplotlib~=3.2.1',
        'PTable',
        'geoip2~=3.0.0',
        'scikit-learn~=0.23.1',
        'xgboost~=1.1.1',
        'requests~=2.24.0',
        'prettytable~=0.7.2',
        'retrie~=0.1.2',
    ],
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Science/Research",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",

        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        'Programming Language :: Python :: 3 :: Only',
        "Typing :: Typed",
    ],
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'ipsiblings=ipsiblings.run:main'
        ]
    },
    package_data={
        'ipsiblings': ['assets/*'],
    },
)
