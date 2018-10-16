/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

/**
  * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
  */
object Antlr4 {
  import org.antlr.v4.runtime.tree._

  trait Visitor[N] extends ParseTreeVisitor[N] {
    def getChildren[T, PT <: ParseTree](trees: Seq[PT]): Seq[T] = {
      var children: Seq[T] = Seq()
      if (trees != null) {
        for (tree <- trees)
          children :+= getChild(tree)
      }
      children
    }

    def getChild[T](tree: ParseTree): T =
      visit(tree).asInstanceOf[T]

    def getOptChild[T](tree: ParseTree): Option[T] =
      if (tree == null) None
      else Some(visit(tree).asInstanceOf[T])
  }
}