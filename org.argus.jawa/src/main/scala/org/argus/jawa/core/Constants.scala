/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object Constants {
  final val ALL_FIELD = "ALL.FIELD"
  def ALL_FIELD_FQN(typ: JawaType) = FieldFQN(typ, ALL_FIELD, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)

  final val JAWA_FILE_EXT = "jawa"


  final val THREAD = "java.lang.Thread"
  final val RUNNABLE = "java.lang.Runnable"
  final val THREAD_RUNNABLE = FieldFQN(new JawaType(THREAD), "runnable", new JawaType(RUNNABLE))

  final val LIST = "java.util.List"
  final val LIST_ITEMS = FieldFQN(new JawaType(LIST), "items", new JawaType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, 1))
  final val MAP = "java.util.Map"
  final val MAP_ENTRIES = FieldFQN(new JawaType(MAP), "entries", new JawaType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, 1))
  final val SET = "java.util.Set"
  final val SET_ITEMS = FieldFQN(new JawaType(SET), "items", new JawaType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, 1))
  final val HASHSET = "java.util.HashSet"
  final val HASHSET_ITEMS = FieldFQN(new JawaType(HASHSET), "items", new JawaType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, 1))

  final val STRING = "java.lang.String"
  final val STRING_BUILDER = "java.lang.StringBuilder"
  final val STRING_BUILDER_VALUE = FieldFQN(new JawaType(STRING_BUILDER), "value", new JawaType(STRING))

  final val CLASS = "java.lang.Class"
  final val CLASS_NAME = FieldFQN(new JawaType(CLASS), "name", new JawaType(STRING))
}
