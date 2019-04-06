from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='find2deny',
    version='0.1',
    description='find Bot request in log file to firewall them',
    long_description=readme(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Log File Processing',
    ],
    keywords='logfile-analyse',
    url='http://nix.nix',
    author='Hong-Phuc Bui',
    author_email='hong-phuc.bui@htwsaar.de',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'pendulum', 'ipaddress'
    ],
    tests_require=['pytest', 'pytest-cov'],
    setup_requires=["pytest-runner"],
    entry_points={
        'console_scripts': ['find2deny-cli=find2deny.cli:main'],
    },
    include_package_data=True,
    zip_safe=False
)