# Argus-SAF: Argus static analysis framework
[![License](https://img.shields.io/badge/License-EPL%201.0-red.svg)](https://opensource.org/licenses/EPL-1.0) 
[![Download](https://api.bintray.com/packages/arguslab/maven/argus-saf/images/download.svg)](https://bintray.com/arguslab/maven/argus-saf/_latestVersion)
[![Build Status](https://travis-ci.org/arguslab/Argus-SAF.svg?branch=master)](https://travis-ci.org/arguslab/Argus-SAF)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1a59d168b6fc42faaed643249ac3e2f5)](https://www.codacy.com/app/fgwei521/Argus-SAF?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=arguslab/Argus-SAF&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/1a59d168b6fc42faaed643249ac3e2f5)](https://www.codacy.com/app/fgwei521/Argus-SAF?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=arguslab/Argus-SAF&amp;utm_campaign=Badge_Coverage)

This is official reporitory for the [Argus-SAF](http://pag.arguslab.org/argus-saf).

For test and play with Argus-SAF, you can fork from our [Argus-SAF-playground](https://github.com/arguslab/Argus-SAF-playground)
project, which have the basic setup for a Argus-SAF enhanced project with demo codes of how to perform different kind of analysis.

## JN-SAF Integration Status
We are currently working on integrate [JN-SAF](http://www.fengguow.com/resources/papers/JN-SafCCS18.pdf) java-native code analysis framework into Argus-SAF. 

Original plan was open-source the JN-SAF part by 2018-10-31. However, due to engineering issues, we have to postpone the open-source date to 2018-11-30. Thanks for the understanding.

## Repository structure

```
Argus-SAF/
+--src/main/scala/org.argus.saf     Main class for argus-saf CLI.
+--org.argus.jawa                   Core static analysis data structures, "*.class"&"*.jawa" file managing, jawa compiler, class hierarchy, method body resolving, flow analysis, etc.
+--org.argus.amandroid              Android resource parsers, information collector, decompiler, environment method builder, flow analysis, etc.
+--org.argus.amandroid.concurrent   Akka actors for Amandroid.
```

## Obtaining Argus-SAF as library

Depend on Jawa
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.arguslab/jawa_2.12/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.arguslab/jawa_2.12)
by editing
`build.sbt`:

```
libraryDependencies += "com.github.arguslab" %% "jawa" % VERSION
```

Depend on Amandroid
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.arguslab/amandroid_2.12/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.arguslab/amandroid_2.12)
by editing
`build.sbt`:

```
libraryDependencies += "com.github.arguslab" %% "amandroid" % VERSION
```

> Note that: Depend on Amandroid will automatically add Jawa as dependency. If you use Maven or Gradle, you should translate it to corresponding format.

## Obtaining Argus-SAF CLI Tool

**Requirement: Java 8**

1. Click [![Download](https://api.bintray.com/packages/arguslab/maven/argus-saf/images/download.svg)](https://bintray.com/arguslab/maven/argus-saf/_latestVersion)
2. Download argus-saf_***-version-assembly.jar
3. Get usage by:
  
 ```
 $ java -jar argus-saf_***-version-assembly.jar
 ```

## Developing Argus-SAF

In order to take part in Argus-SAF development, you need to:

1. Install the following software:
    - IntelliJ IDEA 14 or higher with compatible version of Scala plugin

2. Fork this repository and clone it to your computer

  ```
  $ git clone https://github.com/arguslab/Argus-SAF.git
  ```

3. Open IntelliJ IDEA, select `File -> New -> Project from existing sources`
(if from initial window: `Import Project`), point to
the directory where Scala plugin repository is and then import it as SBT project.

4. When importing is finished, go to Argus-SAF repo directory and run

  ```
  $ git checkout .idea
  ```

  in order to get artifacts and run configurations for IDEA project.

5. [Optional] To build Argus-SAF more smooth you should give 2GB of the heap size to the compiler process.
   - if you use Scala Compile Server (default):
   `Settings > Languages & Frameworks > Scala Compile Server > JVM maximum heap size`

   - if Scala Compile Server is disabled:
   `Settings > Build, Execution, Deployment > Compiler > Build process heap size`
   
6. Build Argus-SAF from command line: go to Argus-SAF repo directory and run

  ```
  $ tools/bin/sbt clean compile test
  ```

## How to contribute

To contribute to the Argus-SAF, please send us a [pull request](https://help.github.com/articles/using-pull-requests/#fork--pull) from your fork of this repository!

For more information on building and developing Argus-SAF, please also check out our [guidelines for contributing](CONTRIBUTING.md). People who provided excellent ideas are listed in [contributor](CONTRIBUTOR.md).
 
## What to contribute

If you don't know what to contribute,
you can checkout the [issue tracker](https://github.com/arguslab/Argus-SAF/issues) with `help wanted` label, and claim one to help yourself warm up with Argus-SAF.
