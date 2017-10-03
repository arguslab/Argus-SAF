/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

import sbt._

object ArgusVersions {
  val scalaVersion = "2.12.2"
  val sbtVersion = "0.13.13"
  val jgraphtVersion = "1.0.1"
  val json4sVersion = "3.5.0"
}

object Dependencies {
  import ArgusVersions._

  val sbtLaunch: ModuleID = "org.scala-sbt" % "sbt-launch" % sbtVersion

  val asm_all: ModuleID = "org.ow2.asm" % "asm-all" % "5.2"

  val antlr4_runtime: ModuleID = "org.antlr" % "antlr4-runtime" % "4.7"

  val st4: ModuleID = "org.antlr" % "ST4" % "4.0.8"

  val jgrapht_core: ModuleID = "org.jgrapht" % "jgrapht-core" % jgraphtVersion
  val jgrapht_ext: ModuleID = "org.jgrapht" % "jgrapht-ext" % jgraphtVersion

  val ini4j: ModuleID = "org.ini4j" % "ini4j" % "0.5.4"

  val commons_cli: ModuleID = "commons-cli" % "commons-cli" % "1.3.1"
  val commons_lang3: ModuleID = "org.apache.commons" % "commons-lang3" % "3.5"

  val guava: ModuleID = "com.google.guava" % "guava" % "21.0"

  val json4s_native: ModuleID = "org.json4s" %% "json4s-native" % json4sVersion
  val json4s_ext: ModuleID = "org.json4s" %% "json4s-ext" % json4sVersion

  val findbug: ModuleID = "com.google.code.findbugs" % "jsr305" % "3.0.+" % "compile"

  val akka_actor: ModuleID = "com.typesafe.akka" %% "akka-actor" % "2.4.17"

  val javaparser: ModuleID = "com.github.javaparser" % "javaparser-core" % "3.4.0"
}

object DependencyGroups {
  import Dependencies._

  val jawa: Seq[ModuleID] = Seq(
    findbug,
    guava,
    commons_lang3,
    antlr4_runtime,
    asm_all,
    st4,
    jgrapht_core,
    jgrapht_ext,
    javaparser
  )

  val amandroid: Seq[ModuleID] = Seq(
    ini4j,
    json4s_native,
    json4s_ext
  ) ++ jawa

  val argus_saf: Seq[ModuleID] = Seq(
    commons_cli
  ) ++ amandroid

  val amandroid_concurrent: Seq[ModuleID] = Seq(akka_actor) ++ amandroid

  val webfa: Seq[ModuleID] = Seq() ++ jawa
}