from setuptools import setup, find_packages

setup(
    name="antiscamai",
    version="1.0.2",
    description="AntiScam AI – AI-powered request inspection middleware for Python",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="AntiScam AI",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0",
    ],
    extras_require={
        "fastapi": ["fastapi>=0.100.0", "starlette>=0.27.0"],
        "django": ["django>=4.0"],
        "flask": ["flask>=3.0"],
        "all": ["fastapi>=0.100.0", "starlette>=0.27.0", "django>=4.0", "flask>=3.0"],
    },
    url="https://github.com/antiscamai/sdk",
    project_urls={
        "Homepage": "https://github.com/antiscamai/sdk",
        "Bug Tracker": "https://github.com/antiscamai/sdk/issues",
        "Documentation": "https://github.com/antiscamai/sdk#readme",
        "Source": "https://github.com/antiscamai/sdk",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        "Framework :: Django",
        "Framework :: FastAPI",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
    ],
    keywords=["antiscam", "security", "middleware", "ai", "fraud-detection", "phishing", "fastapi", "django", "flask"],
)
