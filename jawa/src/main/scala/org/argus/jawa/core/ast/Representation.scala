/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast

import org.argus.jawa.core.elements.{FieldFQN, JawaType, Signature}
import org.argus.jawa.core.util._


case class MyClass(
    accessFlag: Int,
    typ: JawaType,
    superType: Option[JawaType],
    interfaces: IList[JawaType],
    var outerType: Option[JawaType] = None,
    var fields: IList[MyField] = ilistEmpty,
    var methods: IList[MyMethod] = ilistEmpty) {
  protected[jawa] def setOuter(o: JawaType): Unit = this.outerType = Some(o)
  protected[jawa] def addField(f: MyField): Unit = this.fields :+= f
  protected[jawa] def addMethod(m: MyMethod): Unit = this.methods :+= m
}

case class MyField(accessFlag: Int, FQN: FieldFQN) {
  
}

case class MyMethod(
    accessFlag: Int,
    signature: Signature,
    thisParam: Option[String],
    var params: IList[String] = ilistEmpty,
    var body: Option[MethodDeclaration] = None) {
  protected[jawa] def addParam(name: String): Unit = this.params :+= name
  protected[jawa] def setBody(b: MethodDeclaration): Unit = this.body = Some(b)
}
