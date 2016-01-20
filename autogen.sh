#!/bin/bash

libtoolize --copy --force
aclocal
automake --gnu --copy --add-missing
autoconf

