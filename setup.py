#!/usr/bin/env python3

from setuptools import setup

# To install the library, run the following
#
# ./setup.py install

setup(
    include_package_data=True,
    name='dolphin',
    setup_requires=['better-setuptools-git-version'],
    version_config={
        "version_format": "{tag}-{sha}",
    },
    zip_safe=False,
    description="Kong Perf Infrastructure CLI",
    author_email="ccfish@gmail.com",
    author="ccfish",
    keywords=["CI", "CD", "Cloud", "Jupyter"],
    install_requires=[
        "kubernetes==11.0.0",
        "boto3==1.14.22",
        "docker==3.7.2",
        "docopt==0.6.2",
        "PyYAML==5.1",
        "GitPython==2.1.11",
        "gitdb2==2.0.6",
        "setuptools==40.8.0",
        "configobj==5.0.6",
        "six==1.11.0",
        "Jinja2==2.10",
        "urllib3==1.24.2",
        "requests>=2.13.0",
        "prettytable==0.7.2",
        "cryptography==2.6.1",
        "paramiko>=2.5.0",
        "deepdiff==4.0.6",
        "deprecation==2.1.0",
        "pyjwt==1.7.1",
        "python-dateutil==2.8.1",
        "pexpect==4.8.0",
        "bullet==2.2.0",
        "python-dynamodb-lock==0.9.1"
    ],
    extras_require={
        "extras": [
            "IPython[extras]==4.2.1",
            "ipykernel[extras]==4.5.1",
            "jupyter[extras]==1.0.0",
            "jupyter-console[extras]==5.2.0",
            "matplotlib[extras]==2.0.0"
        ]
    },
    packages=['dolphinpkg',
              'dolphinpkg/aws',
              'dolphinpkg/aws/dynamodb',
              'dolphinpkg/aws/dynamodb/models',
              'dolphinpkg/aws/dynamodb/services',
              'dolphinpkg/aws/dynamodb/services/cluster_pool',
              'dolphinpkg/aws/dynamodb/services/cluster_pool/mixins',
              'dolphinpkg/infra',
              'dolphinpkg/platforms',
              'dolphinpkg/commands',
              'dolphinpkg/commands/tkgi',
              'tsm',
              'tsm/platform'
              ],
    scripts=['scripts/dolphin'],
    data_files=[('dolphinpkg/config', ['dolphinpkg/config/dolphin_cloud.pem']),
                ('dolphinpkg/config', ['dolphinpkg/config/cf-deployment.yml']),
                ('dolphinpkg/config', ['dolphinpkg/config/aws.yml']),
                ('dolphinpkg/config', ['dolphinpkg/config/buildspec.yml.tmpl']),
                ('dolphinpkg/config',
                 ['dolphinpkg/config/use-compiled-releases.yml']),
                ('dolphinpks/aws', ['dolphinpkg/aws/additionalPolicies.yaml']),
                ('dolphinpks/aws', ['dolphinpkg/aws/additionalPolicies.json']),
                ('dolphinpks/aws', ['dolphinpkg/aws/clusterWithIRSA.tmpl.yaml']),
                ('dolphinpkg', ['dolphinpkg/.dolphin.conf']),
                ('dolphinpkg', ['dolphinpkg/.dolphin.state.conf'])],
    classifiers=[
        "Topic :: Utilities",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ]
)
