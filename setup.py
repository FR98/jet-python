import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="json-encrypted-token",
    version="0.0.1",
    author="Francisco Rosal",
    author_email="frangrosalo@hotmail.com",
    description="JET - JSON Encrypted Token",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/FR98/jet-python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)