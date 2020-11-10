import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="json-encrypted-token",
    version="0.0.5",
    author="Francisco Rosal",
    author_email="frangrosalo@hotmail.com",
    description="JET - JSON Encrypted Token",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/FR98/jet-python",
    packages=setuptools.find_packages(exclude=('venv', 'tests')),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'backports.pbkdf2==0.1',
        'cffi==1.14.3',
        'cryptography==3.1.1',
        'pycparser==2.20',
        'six==1.15.0',
    ],
    python_requires='>=3.6',
)