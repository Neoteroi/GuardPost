from setuptools import setup


def readme():
    with open("README.md") as f:
        return f.read()


setup(
    name="guardpost",
    version="0.0.9",
    description=(
        "Basic framework to handle authentication and authorization "
        "in any kind of Python application."
    ),
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    url="https://github.com/Neoteroi/guardpost",
    author="Roberto Prevato",
    author_email="roberto.prevato@gmail.com",
    keywords="authentication authorization identity claims strategy "
    + "framework asyncio synchronous",
    license="MIT",
    packages=[
        "guardpost",
        "guardpost.synchronous",
        "guardpost.asynchronous",
        "guardpost.jwks",
        "guardpost.jwts",
    ],
    install_requires=[],
    extras_require={
        "jwt": [
            "PyJWT~=2.3.0",
            "cryptography~=35.0.0",
        ]
    },
    include_package_data=True,
    zip_safe=False,
)
