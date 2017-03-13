import Common._
import sbt.Keys._
import sbtassembly.AssemblyPlugin.autoImport._
import sbtbuildinfo.BuildInfoPlugin.autoImport._
import sbtrelease.ReleaseStateTransformations._
import com.typesafe.sbt.pgp.PgpKeys._

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
  test in assembly := {},
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
    releasePublishArtifactsAction := PgpKeys.publishSigned.value,
    pomExtra := <scm>
      <url>https://github.com/arguslab/Argus-SAF</url>
      <connection>scm:git:https://github.com/arguslab/Argus-SAF.git</connection>
    </scm>
    <developers>
      <developer>
        <id>fgwei</id>
        <name>Fengguo Wei</name>
        <url>http://fgwei.arguslab.org</url>
      </developer>
    </developers>
  )

lazy val argus_saf: Project =
  newProject("argus-saf", file("."))
  .enablePlugins(BuildInfoPlugin, BintrayPlugin)
  .settings(libraryDependencies ++= DependencyGroups.argus_saf)
  .dependsOn(amandroid_core)
  .settings(argusSafSettings)
  .settings(myUnidocSettings)
  .settings(buildInfoSettings)
  .settings(assemblySettings)
  .aggregate(
    saf_library, jawa_core, amandroid_core
  )
  .settings(publishSettings)
  .settings(
    artifact in (Compile, assembly) ~= { art =>
      art.copy(`classifier` = Some("assembly"))
    },
    addArtifact(artifact in (Compile, assembly), assembly),
    publishArtifact in (Compile, packageBin) := false,
    publishArtifact in (Compile, packageDoc) := false,
    publishArtifact in (Compile, packageSrc) := false
  )

lazy val saf_library: Project =
  newProject("saf-library", file("org.argus.saf.library"))
    .settings(libraryDependencies ++= DependencyGroups.saf_library)
    .settings(
      assemblyOption in assembly := (assemblyOption in assembly).value.copy(includeScala = false),
      assemblyJarName in assembly := s"${name.value}-${version.value}.jar",
      mainClass in assembly := None,
      artifact in (Compile, assembly) ~= { art =>
        art.copy(`classifier` = None)
      },
      addArtifact(artifact in (Compile, assembly), assembly),
      publishArtifact in (Compile, packageBin) := false
    )
    .settings(publishSettings)

lazy val jawa_core: Project =
  newProject("jawa-core", file("org.argus.jawa.core"))
  .dependsOn(saf_library)
  .settings(libraryDependencies ++= DependencyGroups.jawa_core)
  .settings(publishSettings)

lazy val amandroid_core: Project =
  newProject("amandroid-core", file("org.argus.amandroid.core"))
  .dependsOn(jawa_core)
  .settings(libraryDependencies ++= DependencyGroups.amandroid_core)
  .settings(publishSettings)

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
  ReleaseStep(releaseStepTask(bintrayRelease in jawa_core)),
  ReleaseStep(releaseStepTask(bintrayRelease in amandroid_core)),
  ReleaseStep(releaseStepTask(bintrayRelease in argus_saf)),
  setNextVersion,
  commitNextVersion,
  pushChanges
)