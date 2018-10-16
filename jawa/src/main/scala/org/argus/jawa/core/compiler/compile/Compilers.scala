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

import org.argus.jawa.core.util._
import java.io.File

import org.argus.jawa.core.compiler.log.Logger

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait Compilers[JawaCompiler] {
  def javac: JavaCompiler
  def jawac: JawaCompiler
}

trait JavaCompiler {
  /**
   * Compiles Java sources using the provided classpath, 
   * output directory, and additional options. Output should 
   * be sent to the provided reporter
   */
  def compile(sources: IList[File], options: IList[String], log: Logger)
}
