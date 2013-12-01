from setuptools import setup
setup(
    name = "Mausoleum",
    version = "0.0.1",
    packages = ['mausoleum'],
    install_requires=['mysql-python', 'python-magic', 'pycrypto'],
    entry_points={
        'console_scripts': ['mausoleum = mausoleum.tool:main']
    }
)
