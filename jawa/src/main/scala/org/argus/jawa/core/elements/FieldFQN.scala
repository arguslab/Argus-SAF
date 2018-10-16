/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.elements

import org.argus.jawa.core.java_signatures.FieldSignature

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class FieldFQN(field_signature: FieldSignature) extends JavaKnowledge {
  def this(owner: JawaType, fieldName: String, typ: JawaType) =
    this(FieldSignature(owner = Some(owner.javaType), name = fieldName, fieldType = Some(typ.javaType)))
  def this(fqn: String, typ: JawaType) =
    this(JavaKnowledge.getClassTypeFromFieldFQN(fqn), JavaKnowledge.getFieldNameFromFieldFQN(fqn), typ)
  val owner: JawaType = JawaType(field_signature.getOwner)
  val fieldName: String = field_signature.name
  val typ: JawaType = JawaType(field_signature.getFieldType)
  def fqn: String = (owner.jawaName + "." + fieldName).intern()
  override def toString: String = (owner.jawaName + "." + fieldName + ":" + typ.jawaName).intern()
}
