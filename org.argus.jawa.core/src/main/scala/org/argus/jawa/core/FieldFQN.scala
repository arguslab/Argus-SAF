/*
 * Copyright (c) 2016. Fengguo Wei and others.
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
case class FieldFQN(owner: JawaType, fieldName: String, typ: JawaType) extends JavaKnowledge {
  def this(fqn: String, typ: JawaType) = this(JavaKnowledge.getClassTypeFromFieldFQN(fqn), JavaKnowledge.getFieldNameFromFieldFQN(fqn), typ)
  def fqn: String = (owner.jawaName + "." + fieldName).intern()
  override def toString: String = (owner.jawaName + "." + fieldName + ":" + typ.jawaName).intern()
}
