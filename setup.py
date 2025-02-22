#!/usr/bin/env python


from setuptools import setup


setup(
    name='keyer',
    version='1.0',
    description='MIFARE Classic 1K EV premises access system (embedded part).',
    author='Vitaly Greck',
    author_email='vintozver@ya.ru',
    url='https://github.com/vintozver/keyer',
    package_dir={'keyer': 'src'},
    install_requires=[
        'adafruit_circuitpython_pn532', 'adafruit_circuitpython_charlcd',
        'gpiozero', 'pigpio', 'ecdsa', 'aiodns', 'aiohttp',
    ],
)
