from setuptools import setup, find_packages

setup(
    name="socks5tun",
    version="0.1",
    packages=find_packages(),  # автоматически найдёт socks5tun/
    include_package_data=True,
    python_requires=">=3.8",
)
