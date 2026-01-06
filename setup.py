from setuptools import setup, find_packages

setup(
    name="snaffler-linux",
    version="1.0.0",
    description="Snaffler Linux port – find credentials and sensitive data on Windows shares",
    author="totekuh",
    python_requires=">=3.9",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "impacket>=0.11.0",
        "typer>=0.12.0",
        "rich>=13.0.0",
        "toml>=0.10.2",
    ],
    entry_points={
        "console_scripts": [
            "snaffler=snaffler.cli:app",
        ]
    },
)
