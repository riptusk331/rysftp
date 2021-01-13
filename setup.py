import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

    setuptools.setup(
        name="RySftp",  # Replace with your own username
        version="0.0.1",
        author="Ryan P Joyce",
        author_email="ryan.joyce.88@gmail.com",
        description="simple, asynchronous sftp operations",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/riptusk331/rysftp",
        packages=setuptools.find_packages(),
        install_requires=[
            'paramiko>=2.7.2',
            "Werkzeug>=1.0.1"
        ],
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        python_requires=">=3.8.5",
    )
