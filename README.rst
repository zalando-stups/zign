====
Zign
====

.. image:: https://travis-ci.org/zalando-stups/zign.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/zign
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando-stups/zign/badge.svg
   :target: https://coveralls.io/r/zalando-stups/zign
   :alt: Code Coverage

.. image:: https://img.shields.io/pypi/dw/stups-zign.svg
   :target: https://pypi.python.org/pypi/stups-zign/
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/v/stups-zign.svg
   :target: https://pypi.python.org/pypi/stups-zign/
   :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/l/stups-zign.svg
   :target: https://pypi.python.org/pypi/stups-zign/
   :alt: License

OAuth2 token management command line utility.

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-zign

Usage
=====

.. code-block:: bash

    $ zign token uid cn
    $ ztoken # shortcut

See the `STUPS documentation on zign`_ for details.

Running Unit Tests
==================

.. code-block:: bash

    $ python3 setup.py test --cov-html=true

.. _STUPS documentation on zign: http://stups.readthedocs.org/en/latest/components/zign.html

Releasing
=========

.. code-block:: bash

    $ ./release.sh <NEW-VERSION>
