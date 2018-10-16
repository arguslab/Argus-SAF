/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.compile

import java.io.File

import hu.ssh.progressbar.ProgressBar
import org.argus.jawa.core.{Constants, Global}
import org.argus.jawa.core.compiler.codegen.JavaByteCodeGenerator
import org.argus.jawa.core.compiler.lexer.JawaLexer
import org.argus.jawa.core.compiler.parser.JawaParser
import org.argus.jawa.core.ast.jawafile.JawaSourceFile
import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.io.{DefaultReporter, PlainFile}
import org.argus.jawa.core.util._

import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class JawaCompiler(javaVersionStr: String) {
  val reporter = new DefaultReporter
  private def parser(s: Either[String, JawaSourceFile]) = new JawaParser(JawaLexer.tokenise(s, reporter).toArray, reporter)
  def compile(sources: Array[File], outputDirs: Array[File], globalOpt: Option[Global], progress: ProgressBar): Unit = {
    def codeGenHandler: File => Unit = { source =>
      require(source.getPath.endsWith(Constants.JAWA_FILE_EXT), "Wrong file extension to compile " + source)
      val file = new JawaSourceFile(new PlainFile(source))
      val cu = parser(Right(file)).compilationUnit(true)
      val css: ISet[(JawaType, Array[Byte])] = new JavaByteCodeGenerator(javaVersionStr).generate(globalOpt, cu).toSet
      css.foreach { case (typ, bcs) =>
        outputDirs.foreach { output =>
          JavaByteCodeGenerator.writeClassFile(output.getAbsolutePath, typ.getPackage.get, typ.name.substring(typ.name.lastIndexOf(".") + 1), bcs)
        }
      }
    }
    ProgressBarUtil.withProgressBar("Generating Bytecode...", progress)(sources.toSet, codeGenHandler)
  }
}

object JawaCompiler {
  import io.IO.{copy, zip, unzip, withTemporaryDirectory}

  def compileSources(sourceJars: Iterable[File], targetJar: File, id: String, compiler: RawCompiler) {
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