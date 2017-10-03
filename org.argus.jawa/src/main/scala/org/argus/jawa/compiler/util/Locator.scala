/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.util

import org.argus.jawa.ast.{JawaAstNode, JawaSymbol}
import org.argus.jawa.core.io.Position


/**
  * A locator for trees with given positions.
  * Given a position `pos`, locator.apply returns
  * the smallest tree that encloses `pos`.
  */
class Locator(pos: Position) {
  var last: JawaAstNode = _
  def locateIn(root: JawaAstNode): JawaAstNode = {
    traverse(root)
    this.last
  }
  def traverse(t: JawaAstNode) {
    t match {
      case tt : JawaSymbol =>
        if (t.pos includes pos) {
          this.last = tt
        }
      case a =>
        if (t.pos includes pos) {
          val children = t.immediateChildren
          children.find(_.pos includes pos) match {
            case Some(c) => traverse(c)
            case None => this.last = a
          }
        }
    }
  }
}
