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
  val scalaVersion = "2.11.8"
  val sbtVersion = "0.13.13"
}

object Dependencies {
  import ArgusVersions._

  val sbtLaunch: ModuleID = "org.scala-sbt" % "sbt-launch" % sbtVersion

  val scala_reflect: ModuleID = "org.scala-lang" % "scala-reflect" % scalaVersion

  val asm_all: ModuleID = "org.ow2.asm" % "asm-all" % "5.1"

  val guava: ModuleID = "com.google.guava" % "guava" % "19.0"

  val antlr4_runtime: ModuleID = "org.antlr" % "antlr4-runtime" % "4.5.3"

  val st4: ModuleID = "org.antlr" % "ST4" % "4.0.8"

  val jgrapht_core: ModuleID = "org.jgrapht" % "jgrapht-core" % "0.9.2"
  val jgrapht_ext: ModuleID = "org.jgrapht" % "jgrapht-ext" % "0.9.2"

  val blueprints_core: ModuleID = ("com.tinkerpop.blueprints" % "blueprints-core" % "2.6.0").
    exclude("commons-beanutils", "commons-beanutils-core").
    exclude("commons-collections", "commons-collections").
    exclude("commons-logging", "commons-logging")

  val ini4j: ModuleID = "org.ini4j" % "ini4j" % "0.5.4"

  val commons_cli: ModuleID = "commons-cli" % "commons-cli" % "1.3.1"

  val commons_lang3: ModuleID = "org.apache.commons" % "commons-lang3" % "3.4"

  val akka_actor: ModuleID = "com.typesafe.akka" %% "akka-actor" % "2.4.14"

  val json4s_native: ModuleID = "org.json4s" %% "json4s-native" % "3.5.0"
  val json4s_ext: ModuleID = "org.json4s" %% "json4s-ext" % "3.5.0"

  val scalatest: ModuleID = "org.scalatest" %% "scalatest" % "3.0.1" % "test"
}

object DependencyGroups {
  import Dependencies._

  val saf_library = Seq(commons_lang3)

  val jawa_core: Seq[ModuleID] = Seq(
    scala_reflect,
    scalatest,
    asm_all,
    guava,
    st4,
    jgrapht_core,
    jgrapht_ext,
    blueprints_core
  ) ++ saf_library

  val amandroid_core: Seq[ModuleID] = Seq(
    ini4j,
    json4s_native,
    json4s_ext,
    akka_actor
  ) ++ jawa_core

  val argus_saf: Seq[ModuleID] = Seq(
    commons_cli
  ) ++ amandroid_core
}