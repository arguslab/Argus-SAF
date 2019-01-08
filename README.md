# Argus-SAF: Argus static analysis framework
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Download](https://api.bintray.com/packages/arguslab/maven/argus-saf/images/download.svg)](https://bintray.com/arguslab/maven/argus-saf/_latestVersion)
[![Build Status](https://travis-ci.org/arguslab/Argus-SAF.svg?branch=master)](https://travis-ci.org/arguslab/Argus-SAF)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1a59d168b6fc42faaed643249ac3e2f5)](https://www.codacy.com/app/fgwei521/Argus-SAF?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=arguslab/Argus-SAF&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/1a59d168b6fc42faaed643249ac3e2f5)](https://www.codacy.com/app/fgwei521/Argus-SAF?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=arguslab/Argus-SAF&amp;utm_campaign=Badge_Coverage)

This is official reporitory for the [Argus-SAF](http://pag.arguslab.org/argus-saf).

For test and play with Argus-SAF, you can fork from our [Argus-SAF-playground](https://github.com/arguslab/Argus-SAF-playground)
project, which have the basic setup for a Argus-SAF enhanced project with demo codes of how to perform different kind of analysis.

## Repository structure

```
Argus-SAF/
+--src/main/scala/org.argus.saf/Main.scala     Main class for argus-saf CLI.
+--jawa         Core static analysis data structures, "*.class"&"*.jawa" file managing, jawa compiler, class hierarchy, method body resolving, flow analysis, etc.
+--amandroid    Android resource parsers, information collector, decompiler, environment method builder, flow analysis, etc.
+--jnsaf        Java native interface analysis.
+--nativedroid  Annotation based analysis using angr symbolic execution engine.
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

**Requirement: Java 10**

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
the directory where Argus-SAF repository is and then import it as `SBT project`.

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

7. Generate fat jar: go to Argus-SAF repo directory and run
  ```
  $ tools/bin/sbt assembly
  ```
  
## Install JN-Saf with NativeDroid

Install `JN-Saf` and `NativeDroid`:
  ```
  $ tools/scripts/install.sh
  ```
  
You can install either one by:
  ```
  $ tools/scripts/install.sh jnsaf
  $ tools/scripts/install.sh nativedroid
  ```

## Run BenchMark Test
After install `JN-Saf` and `NativeDroid`. Run:
  ```
  $ tools/scripts/benchmark_cli.sh droidbench
  $ tools/scripts/benchmark_cli.sh iccbench
  $ tools/scripts/benchmark_cli.sh nativeflowbench
  ```
  
## Launch JN-SAF for native analysis

1. Install nativedroid:
  ```
  $ tools/scripts/install.sh nativedroid
  ```
2. Start nativedroid server:
  ```
  $ python nativedroid/nativedroid/server/native_droid_server.py /tmp/binaries nativedroid/nativedroid/data/sourceAndSinks/NativeSourcesAndSinks.txt nativedroid/data/sourceAndSinks/TaintSourcesAndSinks.txt
  ```
3. Use [NativeDroidClient.scala](https://github.com/arguslab/Argus-SAF/blob/master/jnsaf/src/main/scala/org/argus/jnsaf/client/NativeDroidClient.scala) to communicate with the nativedroid server to perform native analysis.

### Troubleshooting:

1. If python code in Intellij shows unresolved imports, you should manually import the nativedroid folder as a python module and set Python SDK.
Recommend to use a python virtualenv to install nativedroid with it's required python packages.

## Bazel build

Bazel integration in progress. Ignore all the BUILD files for now.

## How to contribute

To contribute to the Argus-SAF, please send us a [pull request](https://help.github.com/articles/using-pull-requests/#fork--pull) from your fork of this repository!

For more information on building and developing Argus-SAF, please also check out our [guidelines for contributing](CONTRIBUTING.md). People who provided excellent ideas are listed in [contributor](CONTRIBUTOR.md).
 
## What to contribute

If you don't know what to contribute,
you can checkout the [issue tracker](https://github.com/arguslab/Argus-SAF/issues) with `help wanted` label, and claim one to help yourself warm up with Argus-SAF.
