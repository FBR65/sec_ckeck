from setuptools import setup, find_packages

setup(
    name="sec-check",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pydantic-ai[openai]>=0.0.7",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "httpx>=0.25.0",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "jinja2>=3.1.0",
        "aiofiles>=23.2.0",
        "rich>=13.0.0",
        "typer>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "sec-check=sec_ckeck.cli:main",
        ],
    },
    author="Security Team",
    description="Automated IT Security Testing Agent",
    python_requires=">=3.8",
)
