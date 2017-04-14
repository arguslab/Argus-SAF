/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.compile

import scala.annotation.tailrec
import java.io.File

import org.argus.jawa.compiler.compile.io.IO
import org.argus.jawa.compiler.log.Logger
import org.argus.jawa.compiler.util.cp.Locate
import org.argus.jawa.core.Reporter
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class AggressiveCompile(cacheFile: File) {
  def apply(compiler: JawaCompiler,
            javac: JavaCompiler,
            sources: IList[File],
            output: Output,
            progress: CompileProgress,
            javacOptions: IList[String] = Nil,
            definesClass: Locate.DefinesClass = Locate.definesClass,
            reporter: Reporter)(implicit log: Logger): Unit =
  {
//    val absClasspath = classpath.map(_.getAbsoluteFile)
    val outputDirs = outputDirectories(output)
    outputDirs foreach IO.createDirectory
    val incSrc = sources//.filter(include)
    val (javaSrcs, jawaSrcs) = incSrc partition javaOnly
    
    def compileJawa() =
      if(jawaSrcs.nonEmpty)
      {
        val sources = jawaSrcs
        timed("Jawa compilation", log) {
          compiler.compile(sources.toArray, outputDirs.toArray, reporter, log, progress)
        }
      }
    def compileJava() =
      if(javaSrcs.nonEmpty)
      {
        @tailrec def ancestor(f1: File, f2: File): Boolean =
          if (f2 eq null) false else
            if (f1 == f2) true else ancestor(f1, f2.getParentFile)
  
        val chunks: Map[Option[File], Seq[File]] = output match {
          case single: SingleOutput => Map(Some(single.outputDirectory()) -> javaSrcs)
          case multi: MultipleOutput =>
            javaSrcs groupBy { src =>
              multi.outputGroups find {out => ancestor(out.sourceDirectory(), src)} map (_.outputDirectory())
            }
        }
        chunks.get(None) foreach { srcs =>
          log.error("No output directory mapped for: " + srcs.map(_.getAbsolutePath).mkString(","))
        }
//        val memo = for ((Some(outputDirectory), srcs) <- chunks) yield {
//          val classesFinder = PathFinder(outputDirectory) ** "*.class"
//          (classesFinder, classesFinder.get, srcs)
//        }
//        val loader = ClasspathUtilities.toLoader(searchClasspath)
        timed("Java compilation", log) {
          javac.compile(javaSrcs, javacOptions, log)
        }
//        def readAPI(source: File, classes: Seq[Class[_]]): Set[String] = {
//          val (api, inherits) = ClassToAPI.process(classes)
//          callback.api(source, api)
//          inherits.map(_.getName)
//        }
//  
//        timed("Java analysis", log) {
//          for ((classesFinder, oldClasses, srcs) <- memo) {
//            val newClasses = Set(classesFinder.get: _*) -- oldClasses
//            Analyze(newClasses.toSeq, srcs, log)(callback, loader, readAPI)
//          }
//        }
      }
    compileJava()
    compileJawa()
  }

  def javaOnly(f: File): Boolean = f.getName.endsWith(".java")
  
  private[this] def outputDirectories(output: Output): Seq[File] = output match {
    case single: SingleOutput => List(single.outputDirectory())
    case mult: MultipleOutput => mult.outputGroups map (_.outputDirectory())
  }
  
  private[this] def timed[T](label: String, log: Logger)(t: => T): T = {
    val start = System.nanoTime
    val result = t
    val elapsed = System.nanoTime - start
    log.debug(label + " took " + (elapsed/1e9) + " s")
    result
  }
}
