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

import java.io.File

import org.argus.jawa.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.compiler.lexer.JawaLexer
import org.argus.jawa.compiler.log.Logger
import org.argus.jawa.compiler.parser.JawaParser
import org.argus.jawa.core.{DefaultReporter, Reporter}
import org.argus.jawa.core.io.{FgSourceFile, PlainFile}
import org.sireum.util._

import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class JawaCompiler(javaVersionStr: String) {
  val reporter = new DefaultReporter
  private def parser(s: Either[String, FgSourceFile]) = new JawaParser(JawaLexer.tokenise(s, reporter).toArray, reporter)
  def compile(sources: Array[File], outputDirs: Array[File], reporter: Reporter, log: Logger, progress: CompileProgress): Unit = {
    sources foreach{
      source =>
        require(source.getPath.endsWith("jawa"), "Wrong file extension to compile " + source)
        val file = new FgSourceFile(new PlainFile(source))
        val cu = parser(Right(file)).compilationUnit(true)
        val css = new JavaByteCodeGenerator(javaVersionStr).generate(cu)
        css foreach {
          case (typ, bcs) =>
            outputDirs.foreach {
              output =>
                JavaByteCodeGenerator.writeClassFile(output.getAbsolutePath, typ.getPackage.get, typ.name.substring(typ.name.lastIndexOf(".") + 1), bcs)
            }
        }
    }
  }
}

object JawaCompiler
{
  import io.IO.{copy, zip, unzip, withTemporaryDirectory}

  def compileSources(sourceJars: Iterable[File], targetJar: File, id: String, compiler: RawCompiler)
  {
    val isSource = (f: File) => isSourceName(f.getName)
    def keepIfSource(files: Set[File]): Set[File] = if(files.exists(isSource)) files else Set()

    withTemporaryDirectory { dir =>
      val extractedSources = (Set[File]() /: sourceJars) { (extracted, sourceJar)=> extracted ++ keepIfSource(unzip(sourceJar, dir)) }
      val (sourceFiles, resources) = extractedSources.partition(isSource)
      withTemporaryDirectory { outputDirectory =>
        try {
          compiler(sourceFiles.toSeq, ilistEmpty, outputDirectory, "-nowarn" :: Nil)
        }
        catch { case e: CompileFailed => throw new CompileFailed(e.arguments, "Error compiling jawa component '" + id + "'") }
        import io.Path._
        copy(resources x rebase(dir, outputDirectory))
        zip((outputDirectory ***) x_! relativeTo(outputDirectory), targetJar)
      }
    }
  }
  private def isSourceName(name: String): Boolean = name.endsWith(".jawa") || name.endsWith(".java")
}

private[this] object IgnoreProgress extends CompileProgress {
  def startUnit(unitPath: String) {}
  def advance(current: Int, total: Int) = true
}
