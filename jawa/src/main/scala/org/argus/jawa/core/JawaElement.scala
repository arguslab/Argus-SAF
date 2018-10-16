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

import org.argus.jawa.core.elements.AccessFlag
import org.argus.jawa.core.util.Property.Key
import org.argus.jawa.core.util.{MLinkedMap, Property, PropertyProvider, mlinkedMapEmpty}

trait JawaElement extends PropertyProvider {

  /**
   * supply property
   */
  val propertyMap: MLinkedMap[Key, Any] = mlinkedMapEmpty[Property.Key, Any]

  def accessFlags: Int

  def getAccessFlags: Int = this.accessFlags

  /**
   * get field access flags in text form
   */
  def getAccessFlagsStr: String = AccessFlag.toString(this.accessFlags)

  /**
   * unknown means it's not available in our code repo
   */
  protected var unknown: Boolean = false

  def setUnknown(): Unit = this.unknown = true

  def isConcrete: Boolean

  /**
   * return true if this class is abstract
   */
  def isAbstract: Boolean = AccessFlag.isAbstract(this.accessFlags)

  /**
   * return true if this class is public
   */
  def isPublic: Boolean = AccessFlag.isPublic(this.accessFlags)

  /**
   * return true if this class is private
   */
  def isPrivate: Boolean = AccessFlag.isPrivate(this.accessFlags)

  /**
   * return true if this class is protected
   */
  def isProtected: Boolean = AccessFlag.isProtected(this.accessFlags)

  /**
   * return true if this class is final
   */
  def isFinal: Boolean = AccessFlag.isFinal(this.accessFlags)

  /**
   * return true if this class is static
   */
  def isStatic: Boolean = AccessFlag.isStatic(this.accessFlags)

  /**
   * return true if this method is native
   */
  def isNative: Boolean = AccessFlag.isNative(this.accessFlags)

  /**
   * return true if this class is unknown class
   */
  def isUnknown: Boolean = this.unknown

  def isClass: Boolean = this.isInstanceOf[JawaClass]

  def isMethod: Boolean = this.isInstanceOf[JawaMethod]

  def isField: Boolean = this.isInstanceOf[JawaField]
}
