/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachingDefinitionAnalysis

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
sealed abstract class DefDesc {
  def isUndefined: Boolean = this == UnDefDesc

  def isDefinedInitially: Boolean = this == InitDefDesc
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
case object UnDefDesc extends DefDesc {
  override def toString = "?"
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
case object InitDefDesc extends DefDesc {
  override def toString = "*"
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
abstract class LocDefDesc extends DefDesc {
  def locUri: String
  def locIndex: Int

  def hasSameDesc(that: DefDesc): Boolean = that match {
    case t: LocDefDesc =>
      locIndex == t.locIndex
    case _ => false
  }

  override def toString: String = locUri
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
final case class LLocDefDesc(
  locUri: String,
  locIndex: Int)
    extends LocDefDesc

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
final case class ParamDefDesc(
  locUri: String,
  locIndex: Int,
  paramIndex: Int)
    extends LocDefDesc {

  override def toString: String = super.toString + "." + paramIndex
}

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
final case class EffectDefDesc(
  locUri: String,
  locIndex: Int)
    extends LocDefDesc {

  override def toString: String = super.toString + ".effect"
}