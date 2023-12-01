# Java Autocrypt library
[![Apache 2.0 License](https://img.shields.io/github/license/iNPUTmice/lttrs-autocrypt?color=informational)](https://tldrlegal.com/license/apache-license-2.0-(apache-2.0))
[![Build Status](https://github.com/inputmice/lttrs-autocrypt/actions/workflows/maven.yml/badge.svg)](https://github.com/iNPUTmice/lttrs-autocrypt/actions/workflows/maven.yml)
[![Codacy Badge](https://img.shields.io/codacy/grade/fe978522c5c54659bb6f4947552c57ed?logo=codacy)](https://www.codacy.com/gh/iNPUTmice/lttrs-autocrypt/dashboard)
[![codecov](https://img.shields.io/codecov/c/gh/inputmice/lttrs-autocrypt/master?logo=codecov&label=code%20coverage&token=D3ZCEII5CO)](https://codecov.io/gh/iNPUTmice/lttrs-autocrypt)
[![Maven Central](https://img.shields.io/maven-central/v/rs.ltt.autocrypt/autocrypt.svg?label=Maven%20Central&color=informational)](https://search.maven.org/search?q=g:%22rs.ltt.autocrypt%22%20AND%20a:%22autocrypt%22)
[![Liberapay patrons](https://img.shields.io/liberapay/patrons/inputmice?logo=liberapay&style=flat&color=informational)](https://liberapay.com/iNPUTmice)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/inputmice?label=GitHub%20Sponsors)](https://github.com/sponsors/iNPUTmice/)

This library is an implementation of the [Autocrypt Level 1](https://autocrypt.org/level1.html) specification. It is divided into two modules. One universal, reusable module that handles peer state managment, decryption and encryption (autocrypt-client) and one module that provides a plugin for [jmap-mua](https://codeberg.org/inputmice/jmap). Anything PGP related is handled by the great [PGPainless](https://github.com/pgpainless/pgpainless/) library.
