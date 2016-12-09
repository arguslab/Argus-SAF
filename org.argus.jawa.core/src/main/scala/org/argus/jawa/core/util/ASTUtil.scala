/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import org.argus.jawa.core.{FieldFQN, JawaType, Signature}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object ASTUtil {
	def getCallArgs(jumploc: JumpLocation): List[String] = {
	  val argNames: MList[String] = mlistEmpty
    jumploc.jump match {
      case t: CallJump if t.jump.isEmpty =>
        t.callExp.arg match {
          case te: TupleExp =>
            val exps = te.exps
            for(i <- exps.indices) {
              val varName = exps(i) match{
                case ne: NameExp => ne.name.name
                case a => a.toString
              }
              argNames += varName
            }
          case _ =>
        }
      case _ =>
    }
	  argNames.toList
	}
  
  def getReturnVars(jumploc: JumpLocation): List[String] = {
    val retNames: MList[String] = mlistEmpty
    jumploc.jump match {
      case t: CallJump if t.jump.isEmpty =>
        for(i <- t.lhss.indices){
          val retName = t.lhss(i) match {
            case ne: NameExp => ne.name.name
            case a => a.toString
          }
          retNames += retName
        }
      case _ =>
    }
    retNames.toList
  }
  
  def getSignature[T <: Annotable[T]](ast: Annotable[T]): Option[Signature] = {
    ast.getValueAnnotation("signature") match {
      case Some(NameExp(name)) =>
        Some(new Signature(name.name))
      case _ => None
    }
  }
  
  def getAccessFlag[T <: Annotable[T]](ast: Annotable[T]): String = {
    ast.getValueAnnotation("AccessFlag") match {
      case Some(NameExp(name)) =>
        name.name
      case _ => ""
    }
  }
  
  def getType[T <: Annotable[T]](ast: Annotable[T]): Option[JawaType] = {
    ast.getValueAnnotation("type") match {
      case Some(NewExp(typespec, _, typeFragments)) =>
        val typ = getTypeFromTypeSpec(typespec)
        val dim = typeFragments.size
        Some(JawaType.addDimensions(typ, dim))
      case _ => None
    }
  }
  
  def getTypeFromTypeSpec(ts: TypeSpec): JawaType = {
    var d = 0
    var tmpTs = ts
    while(tmpTs.isInstanceOf[SeqTypeSpec]){
      d += 1
      tmpTs = tmpTs.asInstanceOf[SeqTypeSpec].elementType
    }
    require(tmpTs.isInstanceOf[NamedTypeSpec])
    JawaType.generateType(tmpTs.asInstanceOf[NamedTypeSpec].name.name, d)
  }
  
  def getKind[T <: Annotable[T]](ast: Annotable[T]): String = {
    ast.getValueAnnotation("kind") match {
      case Some(NameExp(name)) =>
        name.name
      case _ => ""
    }
  }
  
  def getFieldFQN(accessExp: AccessExp, typ: JawaType): FieldFQN = {
    new FieldFQN(accessExp.attributeName.name, typ)
  }

  def isStaticExp(exp: Exp): Boolean = {
    exp match {
      case al: NameExp =>
        al.name.name.contains("@@")
      case _ => false
    }
  }
}
