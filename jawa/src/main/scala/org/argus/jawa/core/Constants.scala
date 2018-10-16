/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.elements.{FieldFQN, JavaKnowledge, JawaType}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object Constants {
  final val ALL_FIELD = "ALL.FIELD"
  def ALL_FIELD_FQN(typ: JawaType) = new FieldFQN(typ, ALL_FIELD, JavaKnowledge.OBJECT)

  final val JAWA_FILE_EXT = ".jawa"
  final val JAVA_FILE_EXT = ".java"
  final val CLASS_FILE_EXT = ".class"


  final val THREAD = "java.lang.Thread"
  final val RUNNABLE = "java.lang.Runnable"
  final val THREAD_RUNNABLE = "runnable"

  final val LIST = "java.util.List"
  final val LIST_ITEMS = "items"
  final val MAP = "java.util.Map"
  final val MAP_ENTRIES = "entries"
  final val SET = "java.util.Set"
  final val SET_ITEMS = "items"
  final val HASHSET = "java.util.HashSet"
  final val HASHSET_ITEMS = "items"

  final val STRING = "java.lang.String"
  final val STRING_BUILDER = "java.lang.StringBuilder"
  final val STRING_BUILDER_VALUE = "value"
  final val STRING_BUFFER = "java.lang.StringBuffer"
  final val STRING_BUFFER_VALUE = "value"

  final val CLASS = "java.lang.Class"
  final val CLASS_NAME = "name"
}
