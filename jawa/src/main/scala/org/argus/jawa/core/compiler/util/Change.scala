/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.util

import org.argus.jawa.core.io.{AbstractFile, SourceFile}

/**
 * The common interface for all changes.
 *
 * Note: it's the
 * super type of `TextChange` and `NewFileChange`. `NewFileChanges`
 * are used by refactorings that create new source files (Move Class).
 *
 * Additionally, the `file` attribute is now of type `SourceFile`,
 * because parts of the refactoring process need to access the content
 * of the  underlying source file.
 **/
sealed trait Change {
  val text: String
}

case class TextChange(sourceFile: SourceFile, from: Int, to: Int, text: String) extends Change {

  def file: AbstractFile = sourceFile.file

  /**
   * Instead of a change to an existing file, return a change that creates a new file
   * with the change applied to the original file.
   *
   * @param fullNewName The fully qualified package name of the target.
   */
  def toNewFile(fullNewName: String): NewFileChange = {
    val src = Change.applyChanges(List(this), new String(sourceFile.content))
    NewFileChange(fullNewName, src)
  }
}

/**
 * The changes creates a new source file, indicated by the `fullName` parameter. It is of
 * the form "some.package.FileName".
 */
case class NewFileChange(fullName: String, text: String) extends Change {

  def file = throw new UnsupportedOperationException
  def from = throw new UnsupportedOperationException
  def to   = throw new UnsupportedOperationException
}

object Change {
  /**
   * Applies the list of changes to the source string. NewFileChanges are ignored.
   * Primarily used for testing / debugging.
   */
  def applyChanges(ch: List[Change], source: String): String = {
    val changes = ch collect {
      case tc: TextChange => tc
    }

    val sortedChanges = changes.sortBy(-_.to)

    /* Test if there are any overlapping text edits. This is
       not necessarily an error, but Eclipse doesn't allow
       overlapping text edits, and this helps us catch them
       in our own tests. */
    sortedChanges.sliding(2).toList foreach {
      case List(TextChange(_, from, _, _), TextChange(_, _, to, _)) =>
        assert(from >= to)
      case _ => ()
    }

    (source /: sortedChanges) { (src, change) =>
      src.substring(0, change.from) + change.text + src.substring(change.to)
    }
  }
}
