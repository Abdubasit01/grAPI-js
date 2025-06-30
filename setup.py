from setuptools import setup, find_packages

setup(
    name='grAPI',
    version='0.1.0',
    description='An API discovery tool using Playwright and JS scanning',
    author='iPsalmy',
    author_email='ipsalmy@gmail.com',
    url='https://github.com/DghostNinja/grAPI',
    packages=find_packages(),
    install_requires=['playwright'],
    entry_points={
        'console_scripts': [
            'grapi = grapi.core:main'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
)
