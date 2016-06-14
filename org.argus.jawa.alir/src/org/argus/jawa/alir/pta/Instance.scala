/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta

import org.argus.jawa.alir.Context
import org.argus.jawa.core.JawaType


/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class Instance{
  def typ: JawaType
  def defSite: Context
  def isNull: Boolean = false
  def isUnknown: Boolean = false
  def ===(ins: Instance): Boolean = this == ins
  def clone(newDefSite: Context): Instance
}


final case class ClassInstance(classtyp: JawaType, defSite: Context) extends Instance{
  override def clone(newDefSite: Context): Instance = ClassInstance(classtyp, newDefSite)
  def typ = new JawaType("java.lang.Class")
  def getName = classtyp.jawaName
  override def ===(ins: Instance): Boolean = {
    ins match {
      case instance: ClassInstance => instance.getName.equals(getName)
      case _ => false
    }
  }
  override def toString: String = getName + ".class@" + this.defSite.getCurrentLocUri
}

//final case class UnknownInstance(baseTyp: JawaType, defSite: Context) extends Instance{
//  override def clone(newDefSite: Context): Instance = UnknownInstance(baseTyp, newDefSite)
//  def typ: JawaType = baseTyp
//  override def toString: String = baseTyp + "*" + "@" + defSite.getCurrentLocUri
//}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class PTAInstance(typ: JawaType, defSite: Context, isNull_ : Boolean) extends Instance {
  override def clone(newDefSite: Context): Instance = PTAInstance(typ, newDefSite, isNull_)
  override def isUnknown: Boolean = typ.baseType.unknown
  override def toString: String = {
    val sb = new StringBuilder
    sb.append(this.typ + "@")
    sb.append(this.defSite.getCurrentLocUri)
    sb.toString.intern()
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class PTATupleInstance(left: Instance, right: Instance, defSite: Context) extends Instance {
  override def clone(newDefSite: Context): Instance = PTATupleInstance(left, right, newDefSite)
  def typ: JawaType = new JawaType("Tuple")
  override def toString: String = {
    val sb = new StringBuilder
    sb.append(this.typ + "@")
    sb.append(this.defSite.getCurrentLocUri)
    sb.toString.intern()
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
abstract class PTAAbstractStringInstance(defSite: Context) extends Instance{
  def typ: JawaType = new JawaType("java.lang.String") 
  override def toString: String = this.typ + ":abstract@" + this.defSite.getCurrentLocUri
}

/**
 * PTAPointStringInstance represents a general String instance whose content can be any string i.e. reg expression "*"
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class PTAPointStringInstance(defSite: Context) extends PTAAbstractStringInstance(defSite){
  override def clone(newDefSite: Context): Instance = PTAPointStringInstance(newDefSite)
  override def ===(ins: Instance): Boolean = {
    ins match {
      case _: PTAPointStringInstance => true
      case _: PTAConcreteStringInstance => true
      case _ => false
    }
  }
  override def toString: String = this.typ + ":*@" + this.defSite.getCurrentLocUri
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
final case class PTAConcreteStringInstance(string: String, defSite: Context) extends PTAAbstractStringInstance(defSite){
  override def clone(newDefSite: Context): Instance = PTAConcreteStringInstance(string, newDefSite)
  override def ===(ins: Instance): Boolean = {
    ins match {
      case instance: PTAConcreteStringInstance => instance.string.equals(string)
      case _: PTAPointStringInstance => true
      case _ => false
    }
  }
  override def toString: String = {
    val sb = new StringBuilder
    sb.append(this.typ + ":")
    sb.append("\"" + {if(this.string.length > 30)this.string.substring(0, 30) + ".." else this.string} + "\"@")
    sb.append(this.defSite.getCurrentLocUri)
    sb.toString.intern()
  }
}