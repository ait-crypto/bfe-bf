Bloom Filter Encryption library
===============================

This library implements bloom filter encryption (BFE) based on the paper [*Bloom Filter Encryption
and Applications to Efficient Forward-Secret 0-RTT Key Exchange*](https://eprint.iacr.org/2018/199)
by David Derler, Tibor Jager, Daniel Slamanig, and Christoph Striecks. It implements IND-CCA2-secure
BFE based on the Boneh-Franklin IBE.

Dependencies
------------

The BFE library requires the following dependencies:
* [relic](https://github.com/relic-toolkit/relic)
* [doxygen](http://www.doxygen.nl/index.html) (optional, for documentation)
* [cgreen](https://github.com/cgreen-devs/cgreen) (optional, for tests)

Building
--------

First configure the build with `cmake` and then run `make`:
```sh
mkdir build
cd build
cmake ..
make
```

License
-------

The code is licensed under the CC0-1.0 license and was developed by AIT Austrian Institute of
Technolgy and Graz University of Technology as part of IoT4CPS. The bloom filter implementation was
originall written by Marin Krmpotić and was released to the public domain. It was heavily modified
for integration in to the BFE library.
