/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
  val sbtVersion = "0.13.9"
  val kamonVersion = "0.3.4"
}

object Dependencies {
  import ArgusVersions._

  val sbtLaunch = "org.scala-sbt" % "sbt-launch" % sbtVersion

  val scala_reflect = "org.scala-lang" % "scala-reflect" % scalaVersion

  val asm_all = "org.ow2.asm" % "asm-all" % "5.1"

  val guava = "com.google.guava" % "guava" % "19.0"

  val antlr4_runtime = "org.antlr" % "antlr4-runtime" % "4.5.3"

  val st4 = "org.antlr" % "ST4" % "4.0.8"

  val jgrapht_core = "org.jgrapht" % "jgrapht-core" % "0.9.2"
  val jgrapht_ext = "org.jgrapht" % "jgrapht-ext" % "0.9.2"

  val blueprints_core = ("com.tinkerpop.blueprints" % "blueprints-core" % "2.6.0").
    exclude("commons-beanutils", "commons-beanutils-core").
    exclude("commons-collections", "commons-collections").
    exclude("commons-logging", "commons-logging")

  val ini4j = "org.ini4j" % "ini4j" % "0.5.4"

  val commons_cli = "commons-cli" % "commons-cli" % "1.3.1"

  val commons_lang3 = "org.apache.commons" % "commons-lang3" % "3.4"

  val akka_actor = "com.typesafe.akka" %% "akka-actor" % "2.4.7"

  val junitInterface = "com.novocode" % "junit-interface" % "0.11" % "test"

  val json4s_native = "org.json4s" %% "json4s-native" % "3.3.0"
  val json4s_ext = "org.json4s" %% "json4s-ext" % "3.3.0"

  val scalatest = "org.scalatest" %% "scalatest" % "2.2.6" % "test"

  val kamon = Seq(
    "com.typesafe.akka" %% "akka-actor" % "2.3.5",
    "io.kamon" %% "kamon-core" % kamonVersion,
    "io.kamon" %% "kamon-statsd" % kamonVersion,
    "io.kamon" %% "kamon-log-reporter" % kamonVersion,
    "io.kamon" %% "kamon-system-metrics" % kamonVersion,
    "org.aspectj" % "aspectjweaver" % "1.8.1"
  )

}

object DependencyGroups {
  import Dependencies._

  val saf_library = Seq(commons_lang3)

  val jawa_core = Seq(
    scala_reflect,
    scalatest,
    asm_all,
    guava,
//    antlr4_runtime,
    st4,
    jgrapht_core,
    jgrapht_ext,
    blueprints_core
  ) ++ saf_library

  val amandroid_core = Seq(
    ini4j,
    json4s_native,
    json4s_ext,
    akka_actor
  ) ++ jawa_core ++ kamon

  val argus_saf = Seq(
    commons_cli
  ) ++ amandroid_core
}