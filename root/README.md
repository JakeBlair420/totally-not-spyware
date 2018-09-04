# Webroot

This is the final product, complete with exploit, payload and everything.

### Setting up a build environment

You'll need some of Google's closure tools. You can download the CSS compiler from [here](https://github.com/google/closure-stylesheets/releases) and the JS one from [here](https://github.com/google/closure-compiler/wiki/Binary-Downloads). Put them wherever you like, then set up two bash scripts somewhere in `PATH` like this:

`closure-css`:

    #!/bin/bash

    java -jar path/to/closure-stylesheets-*.jar "$@";

`closure-js`:

    #!/bin/bash

    java -jar path/to/closure-compiler-*.jar "$@";

### Building

`make -C ../glue && make`
