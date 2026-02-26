from setuptools import setup, find_packages

setup(
    name="avwds",
    version="1.0.0",
    author="Your Name",
    description="Automated Web Vulnerability Detection System",
    packages=find_packages(),
    install_requires=[
        "requests==2.31.0",
        "httpx==0.27.0",
        "beautifulsoup4==4.12.3",
        "playwright==1.44.0",
        "colorama==0.4.6",
        "jinja2==3.1.4",
    ],
    entry_points={
        "console_scripts": [
            "avwds=main:main",   # command=filename:function
        ],
    },
    python_requires=">=3.8",
)
