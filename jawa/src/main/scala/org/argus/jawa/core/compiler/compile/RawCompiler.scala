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

/** A basic interface to the compiler.  It is called in the same virtual machine, but no dependency analysis is done.  This
 * is used, for example, to compile the interface/plugin code..*/
class RawCompiler()
{
  def apply(sources: Seq[File], classpath: Seq[File], outputDirectory: File, options: Seq[String])
  {
    
  }
}
class CompileFailed(val arguments: Array[String], override val toString: String) extends FeedbackProvidedException
