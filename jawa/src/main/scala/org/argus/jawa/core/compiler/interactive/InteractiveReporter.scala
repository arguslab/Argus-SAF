/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.interactive

import org.argus.jawa.core.io.{Position, Problem, ReporterImpl}
import org.argus.jawa.core.util._

abstract class InteractiveReporter extends ReporterImpl {

  def compiler: Global

  val otherProblems: MList[Problem] = mlistEmpty

  override def info0(pos: Position, msg: String, severity: Severity, force: Boolean): Unit = try {
    severity.count += 1
    val problems =
      if (compiler eq null) {
        otherProblems
      } else if (pos.isDefined) {
        compiler.getCompilationUnit(pos.source.file) match {
          case Some(unit) =>
            unit.problems
          case None =>
            otherProblems
        }
      } else {
        otherProblems
      }
    problems += Problem(pos, msg, severity.id)
  } catch {
    case _: UnsupportedOperationException =>
  }
  
  override def info1(title: String, msg: String, severity: Severity, force: Boolean): Unit = {}

  override def reset() {
    super.reset()
    otherProblems.clear()
  }
}
