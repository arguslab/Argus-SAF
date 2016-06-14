import Common._
import sbt.Keys._
import sbtassembly.AssemblyPlugin.autoImport._
import sbtbuildinfo.BuildInfoPlugin.autoImport._
import sbtrelease.ReleaseStateTransformations._
import com.typesafe.sbt.pgp.PgpKeys._

crossPaths in ThisBuild := false

licenses in ThisBuild := ("Eclipse-1.0" -> url("http://www.opensource.org/licenses/eclipse-1.0.php")) :: Nil // this is required! otherwise Bintray will reject the code

homepage in ThisBuild := Some(url("https://github.com/arguslab/Argus-SAF"))

bintrayOrganization in ThisBuild := Some("arguslab")
bintrayReleaseOnPublish in ThisBuild := false
bintrayRepository in ThisBuild := "maven"
bintrayPackage in ThisBuild := "argus-saf"

dependencyOverrides in ThisBuild += "org.scala-lang.modules" %% "scala-xml" % "1.0.5"

val argusSafSettings = Defaults.coreDefaultSettings ++ Seq(
  libraryDependencies += "org.scala-lang" % "scala-compiler" % ArgusVersions.scalaVersion,
  scalacOptions ++= Seq("-unchecked", "-deprecation", "-feature")
)

val myUnidocSettings = unidocSettings ++
  Seq(
    // unidoc
    scalacOptions in (Compile, doc) ++= Opts.doc.title("Argus-SAF-Api-Doc"),
    scalacOptions in (Compile, doc) ++= Seq("-doc-root-content", baseDirectory.value+"/root-doc.txt"),
    autoAPIMappings := true
  )

val buildInfoSettings = Seq(
  // build info
  buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion),
  buildInfoPackage := "org.argus"
)

val assemblySettings = Seq(
  assemblyJarName in assembly := s"${name.value}-${version.value}-assembly.jar",
  mainClass in assembly := Some("org.argus.saf.Main")
)

lazy val publishSnapshot = taskKey[Unit]("Publish Snapshot - Custom Task")
publishSnapshot := {
  println("Publishing Snapshot ...")
  val extracted = Project.extract(state.value)
  Project.runTask(publishSigned, extracted.append(Seq(
    publishTo := Some("Artifactory Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local"),
    // Only setting the credentials file if it exists (#52)
    credentials := List(Path.userHome / ".bintray" / ".artifactory").filter(_.exists).map(Credentials(_))
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
    publishMavenStyle := false,
    resolvers += Resolver.url("argus-saf ivy resolver", url("http://bintray.com/arguslab/maven"))(Resolver.ivyStylePatterns)
  )

lazy val argus_saf: Project =
  newProject("argus-saf", file("."))
  .enablePlugins(BuildInfoPlugin, BintrayPlugin)
  .dependsOn(amandroid_cli)
  .settings(argusSafSettings)
  .settings(myUnidocSettings)
  .settings(buildInfoSettings)
  .settings(assemblySettings)
  .aggregate(
    jawa_core, jawa_alir,
    amandroid_core, amandroid_alir,
    amandroid_plugin, amandroid_serialization,
    amandroid_concurrent, amandroid_cli
  )
  .settings(doNotPublishSettings)
  .settings(
    artifact in (Compile, assembly) ~= { art =>
      art.copy(`classifier` = Some("assembly"))
    },
    addArtifact(artifact in (Compile, assembly), assembly),
    publishArtifact := false,
    publishArtifact in assembly := true,
    publishMavenStyle := false,
    pomExtra := <scm>
      <url>https://github.com/arguslab/Argus-SAF</url>
      <connection>scm:git:https://github.com/arguslab/Argus-SAF</connection>
    </scm>
    <developers>
      <developer>
        <id>fgwei</id>
        <name>Fengguo Wei</name>
        <url>http://www.arguslab.org/~fgwei/</url>
      </developer>
    </developers>,
    resolvers += Resolver.url("argus-saf", url("https://dl.bintray.com/arguslab/maven"))(Resolver.ivyStylePatterns)
  )

lazy val jawa_core: Project =
  newProject("jawa-core", file("org.argus.jawa.core"))
  .settings(libraryDependencies ++= DependencyGroups.jawa_core)
  .settings(doNotPublishSettings)

lazy val jawa_alir: Project =
  newProject("jawa-alir", file("org.argus.jawa.alir"))
  .dependsOn(jawa_core)
  .settings(libraryDependencies ++= DependencyGroups.jawa_alir)
  .settings(doNotPublishSettings)

lazy val amandroid_core: Project =
  newProject("amandroid-core", file("org.argus.amandroid.core"))
  .dependsOn(jawa_alir)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_core)
  .settings(doNotPublishSettings)

lazy val amandroid_alir: Project =
  newProject("amandroid-alir", file("org.argus.amandroid.alir"))
  .dependsOn(amandroid_core)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_alir)
  .settings(doNotPublishSettings)

lazy val amandroid_plugin: Project =
  newProject("amandroid-plugin", file("org.argus.amandroid.plugin"))
  .dependsOn(amandroid_alir)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_plugin)
  .settings(doNotPublishSettings)

lazy val amandroid_serialization: Project =
  newProject("amandroid-serialization", file("org.argus.amandroid.serialization"))
  .dependsOn(amandroid_plugin)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_serialization)
  .settings(doNotPublishSettings)

lazy val amandroid_concurrent: Project =
  newProject("amandroid-concurrent", file("org.argus.amandroid.concurrent"))
  .dependsOn(amandroid_serialization)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_concurrent)
  .settings(doNotPublishSettings)

lazy val amandroid_cli: Project =
  newProject("amandroid-cli", file("org.argus.amandroid.cli"))
  .dependsOn(amandroid_concurrent)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_cli)
  .settings(doNotPublishSettings)

releasePublishArtifactsAction := PgpKeys.publishSigned.value
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
  ReleaseStep(releaseStepTask(bintrayRelease in argus_saf)),
  setNextVersion,
  commitNextVersion,
  pushChanges
)