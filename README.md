#Argus-SAF [ ![Download](https://api.bintray.com/packages/arguslab/maven/argus-saf/images/download.svg) ](https://bintray.com/arguslab/maven/argus-saf/_latestVersion)


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
