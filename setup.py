import setuptools

with open("readme.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ydsdk",
    version="0.1.4",
    author="lideqiang",
    author_email="lideqiang@yundun.com",
    description="Yundun Api Sdk For Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sdk_python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        ##"Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)
