"""Minimal setup file for tasks project."""

from setuptools import setup, find_packages

setup(
    name='optest',
    version='0.1.0',
    license='Apache-2.0',
    description='The common components portion of the OpenPower system test project',

    author='IBM Corporation',
#    author_email='oohall@gmail.com',
    url='https://github.com/open-power/op-test',

    packages=find_packages(where='src'),
    package_dir={'': 'src'},

    # we also need telnetlib and a few others, TODO: find out what their package names are
    install_requires=['pexpect'],
    extras_require={'mongo': 'pymongo'},

#    entry_points={
#        'console_scripts': [
#            'tasks = tasks.cli:tasks_cli',
#        ]
#    },
)
