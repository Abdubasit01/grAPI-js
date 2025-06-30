from setuptools import setup, find_packages

setup(
    name="grapi",
    version="0.1.0",
    author="iPsalmy",
    description="Interactive API endpoint grabber for web pentesting",
    packages=find_packages(),
    install_requires=[
        "playwright>=1.43.0"
    ],
    entry_points={
        "console_scripts": [
            "grapi=grapi.cli:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
