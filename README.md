#Argus-SAF 
[![License](https://img.shields.io/badge/License-EPL%201.0-red.svg)](https://opensource.org/licenses/EPL-1.0) 
[![Download](https://api.bintray.com/packages/arguslab/maven/argus-saf/images/download.svg)](https://bintray.com/arguslab/maven/argus-saf/_latestVersion)
[![Build Status](https://travis-ci.org/arguslab/Argus-SAF.svg?branch=master)](https://travis-ci.org/arguslab/Argus-SAF)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1a59d168b6fc42faaed643249ac3e2f5)](https://www.codacy.com/app/fgwei521/Argus-SAF?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=arguslab/Argus-SAF&amp;utm_campaign=Badge_Grade)

Argus static analysis framework

This is official reporitory for the [Argus-SAF](http://amandroid.sireum.org/).

## Repository structure

```
Argus-SAF/
+--src/org.argus.saf                 Main class for argus-saf CLI.
+--org.argus.jawa.core               Core static analysis data structures, "*.class"&"*.pilar" file managing, class hierarchy, method body resolving, etc.
+--org.argus.jawa.alir               All the flow related analysis for Pilar IR, including call graph building, control flow graph building, data flow analysis, data dependent analysis, points to algorithms, side effect analysis, etc.
+--org.argus.amandroid.core          Android resource parsers, information collector, decompiler, environment method builder.
+--org.argus.amandroid.alir          Component based analysis, Android specific reaching facts analysis, api models, etc.
+--org.argus.amandroid.cli           Amandroid command line tool modes.
+--org.argus.amandroid.concurrent    Amandroid actor system.
+--org.argus.amandroid.plugin        Amandroid plugins.
+--org.argus.amandroid.serialization Serialize amandroid data structures into json format.
```

## How to contribute

To contribute to the Argus-SAF, please send us a [pull request](https://help.github.com/articles/using-pull-requests/#fork--pull) from your fork of this repository!

For more information on building and developing Amandroid, please also check out our [guidelines for contributing](CONTRIBUTING.md). People who provided excellent ideas are listed in [contributor](CONTRIBUTOR.md).
 
## What to contribute

If you don't know what to contribute, please check out our [challenges need to resolve](CHALLENGE.md).
