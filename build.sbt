import Common._
import com.typesafe.sbt.pgp.PgpKeys._
import sbt.Keys._
import sbtassembly.AssemblyPlugin.autoImport._
import sbtbuildinfo.BuildInfoPlugin.autoImport._
import sbtrelease.ReleaseStateTransformations._

licenses in ThisBuild := ("Eclipse-1.0" -> url("http://www.opensource.org/licenses/eclipse-1.0.php")) :: Nil // this is required! otherwise Bintray will reject the code

homepage in ThisBuild := Some(url("https://github.com/arguslab/Argus-SAF"))

bintrayOrganization in ThisBuild := Some("arguslab")
bintrayReleaseOnPublish in ThisBuild := false
bintrayRepository in ThisBuild := "maven"
bintrayPackage in ThisBuild := "argus-saf"

libraryDependencies in ThisBuild += "org.scalatest" %% "scalatest" % "3.0.1" % "test"

val argusSafSettings = Defaults.coreDefaultSettings ++ Seq(
  libraryDependencies += "org.scala-lang" % "scala-compiler" % ArgusVersions.scalaVersion,
  scalacOptions ++= Seq("-unchecked", "-deprecation", "-feature")
)

val pbSettings = Seq(
  PB.protoSources in Compile := Seq(baseDirectory.value / "src" / "main" / "protobuf"),
  PB.targets in Compile := Seq(
    scalapb.gen() -> (sourceManaged in Compile).value / "protos",
  )
)

val buildInfoSettings = Seq(
  // build info
  buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion),
  buildInfoPackage := "org.argus"
)

lazy val publishSnapshot = taskKey[Unit]("Publish Snapshot - Custom Task")
publishSnapshot := {
  println("Publishing Snapshot ...")
  isSnapshot in ThisBuild := true
  val extracted = Project.extract((state in jawa).value)
  Project.runTask(publishSigned in jawa, extracted.appendWithSession(Seq(
    publishTo in jawa := Some("Artifactory Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local"),
    credentials in jawa := List(Path.userHome / ".bintray" / ".artifactory").filter(_.exists).map(Credentials(_))
  ), state.value), checkCycles = true)
  Project.runTask(publishSigned in saf_library, extracted.appendWithSession(Seq(
    publishTo in saf_library := Some("Artifactory Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local"),
    credentials in saf_library := List(Path.userHome / ".bintray" / ".artifactory").filter(_.exists).map(Credentials(_))
  ), state.value), checkCycles = true)
  Project.runTask(publishSigned in amandroid, extracted.appendWithSession(Seq(
    publishTo in amandroid := Some("Artifactory Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local"),
    credentials in amandroid := List(Path.userHome / ".bintray" / ".artifactory").filter(_.exists).map(Credentials(_))
  ), state.value), checkCycles = true)
}


val doNotPublishSettings = Seq(
  Keys.`package` :=  file(""),
  packageBin in Global :=  file(""),
  packagedArtifacts :=  Map(),
  publishArtifact := false,
  publish := {})

val publishSettings = Seq(
    publishArtifact in Test := false,
    releasePublishArtifactsAction := PgpKeys.publishSigned.value,
    pomExtra := <scm>
      <url>https://github.com/arguslab/Argus-SAF</url>
      <connection>scm:git:https://github.com/arguslab/Argus-SAF.git</connection>
    </scm>
    <developers>
      <developer>
        <id>fgwei</id>
        <name>Fengguo Wei</name>
        <url>http://www.fengguow.com</url>
      </developer>
    </developers>
  )

lazy val argus_saf: Project =
  newProject("argus-saf", file("."))
  .enablePlugins(BuildInfoPlugin, BintrayPlugin, ScalaUnidocPlugin)
  .settings(libraryDependencies ++= DependencyGroups.argus_saf)
  .dependsOn(amandroid)
  .settings(argusSafSettings)
  .settings(buildInfoSettings)
  .aggregate(
    saf_library, jawa, amandroid
  )
  .settings(publishSettings)
  .settings(
    test in assembly := {},
    assemblyJarName in assembly := s"${name.value}-${version.value}-assembly.jar",
    mainClass in assembly := Some("org.argus.saf.Main")
  )
  .settings(
    artifact in (Compile, assembly) ~= { art =>
      art.withClassifier(Some("assembly"))
    },
    addArtifact(artifact in (Compile, assembly), assembly),
    publishArtifact in (Compile, packageBin) := false,
    publishArtifact in (Compile, packageDoc) := false,
    publishArtifact in (Compile, packageSrc) := false
  )

lazy val saf_library: Project =
  newProject("saf-library", file("saf.library"))
    .settings(
      assemblyOption in assembly := (assemblyOption in assembly).value.copy(`includeScala` = false),
      assemblyJarName in assembly := s"${name.value}-${version.value}.jar",
      mainClass in assembly := None,
      artifact in (Compile, assembly) ~= { art =>
        art.withClassifier(None)
      },
      addArtifact(artifact in (Compile, assembly), assembly),
      publishArtifact in (Compile, packageBin) := false
    )
    .settings(publishSettings)

lazy val jawa: Project =
  newProject("jawa", file("jawa"))
  .settings(libraryDependencies ++= DependencyGroups.jawa)
  .settings(publishSettings)
  .settings(pbSettings)

lazy val amandroid: Project =
  newProject("amandroid", file("amandroid"))
  .dependsOn(jawa, saf_library)
  .settings(libraryDependencies ++= DependencyGroups.amandroid)
  .settings(publishSettings)

lazy val amandroid_concurrent: Project =
  newProject("amandroid-concurrent", file("amandroid.concurrent"))
  .dependsOn(amandroid)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_concurrent)
  .settings(doNotPublishSettings)

lazy val jnsaf: Project =
  newProject("jnsaf", file("jnsaf"))
    .dependsOn(amandroid)
    .settings(libraryDependencies ++= DependencyGroups.jnsaf)
    .settings(libraryDependencies ++= Seq(
      "io.grpc" % "grpc-netty" % scalapb.compiler.Version.grpcJavaVersion,
      "com.thesamet.scalapb" %% "scalapb-runtime-grpc" % scalapb.compiler.Version.scalapbVersion
    ))
    .settings(publishSettings)
    .settings(pbSettings)

releaseProcess := Seq(
  checkSnapshotDependencies,
  inquireVersions,
  runClean,
  runTest,
  setReleaseVersion,
  commitReleaseVersion,
  ReleaseStep(releaseStepTask(assembly)),
  tagRelease,
  publishArtifacts,
  ReleaseStep(releaseStepTask(bintrayRelease in saf_library)),
  ReleaseStep(releaseStepTask(bintrayRelease in jawa)),
  ReleaseStep(releaseStepTask(bintrayRelease in amandroid)),
  ReleaseStep(releaseStepTask(bintrayRelease in argus_saf)),
  setNextVersion,
  commitNextVersion,
  pushChanges
)