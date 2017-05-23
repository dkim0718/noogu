from setuptools import setup

setup(name='noogu',
        version='0.1',
        description='Simple python WHOIS parser',
        author='Doyoon Kim',
        author_email='dkim0718 (at) gmail (dot) com',
        url='https://github.com/dkim0718/noogu',
        packages=['noogu'],
        package_dir={'noogu':'noogu'},
        package_data={'pythonwhois':['*.dat']},
        install_requires=[],
        provides=['noogu'],
        scripts=[],
        license='GPLv3'
        )
