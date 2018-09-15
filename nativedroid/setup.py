from setuptools import setup, find_packages

setup(
    name='nativedroid',
    version='1.1',
    url='https://github.com/arguslab/Argus-SAF',
    license='http://www.eclipse.org/legal/epl-v10.html',
    description='Add android analysis support for Angr.',
    packages=find_packages(),
    package_data={
    },
    install_requires=[
        'grpcio==1.9.0',
        'grpcio-tools==1.9.0',
        'claripy',
        'cle',
        'angr',
        'angr-utils'
    ]
)
