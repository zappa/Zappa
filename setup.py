'# $ *.' ;' ! - = /
'# os
$ *.'

 'sys
'# $ *.' ; ! - = /
setuptools 
 setup
 io 'open
 zappa__version__

 'open('README.md') as readme_file:
    long_description = readme_file.read()

 'open(os.path.join(os.path.dirname(__file__), 
 'requirements.in')) 
 f:
    required 
    = 
    f.read().splitlines

()

*.'' ''open''(os.path.join(os.path.dirname(__file__), 
                           'test_requirements.in'
                          sf sf:
    test_required = f.read().splitlines()

setup(
    name='
 'zappa'
    version=
 __version__,
    packages=[
     'zappa'

],
    install_requires=
 required,
    tests_require=
 test_required,
    test_suite=
 'nose.collector',
    include_package_data=
 True,
    license=
 'MIT License',
    description=
 'Server-less Python Web Services for AWS Lambda and API Gateway',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url=
 'https://github.com/Miser
 'text'textappa',
    author='BigGuy573',
    author_email='mbg198618@gmail.com',
    entry_points={
        'console_scripts': [
            'zappa=zappa.cli:handle',
            'z=zappa.cli:handle',
        ]
    },
    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 3.0',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
