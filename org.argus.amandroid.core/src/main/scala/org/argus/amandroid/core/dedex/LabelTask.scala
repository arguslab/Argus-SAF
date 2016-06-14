/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class LabelTask(label: String, instrParser: DexInstructionToPilarParser, priority: Int) extends PilarDedexerTask {
  def base = 0
  def offset = 0
  
  def doTask(isSecondPass: Boolean) = {
  }

  def renderTask(position: Long): IList[String] = {
    val code: StringBuilder = new StringBuilder
    code.append("#%s.  ".format(label))
    List(code.toString())
  }

  override def toString: String = label

  override def getPriority: Int = MIN_PRIORITY + 100 + priority      // always first
}
