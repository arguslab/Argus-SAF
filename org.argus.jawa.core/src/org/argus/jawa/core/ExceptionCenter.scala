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

import org.argus.jawa.core.util.ASTUtil
import org.sireum.pilar.ast._
import org.sireum.util._
import org.sireum.pilar.symbol.ProcedureSymbolTable

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object ExceptionCenter {
  
  /**
   * following is the exception constant list
   */
  final val THROWABLE = new JawaType("java.lang.Throwable")
  final val EXCEPTION = new JawaType("java.lang.Exception")
  final val RUNTIME_EXCEPTION = new JawaType("java.lang.RuntimeException")
  final val ARITHMETIC_EXCEPTION = new JawaType("java.lang.ArithmeticException")
  final val ARRAYINDEXOUTOFBOUNDS_EXCEPTION = new JawaType("java.lang.ArrayIndexOutOfBoundsException")
  final val CLASSCAST_EXCEPTION = new JawaType("java.lang.ClassCastException")
  
  final val EXCEPTION_VAR_NAME = "Exception"  
  
  
  def getExceptionsMayThrow(pst: ProcedureSymbolTable, loc: LocationDecl, catchclauses: ISet[CatchClause]): ISet[JawaType] = {
    val result = msetEmpty[JawaType]
    loc match{
      case l: ComplexLocation =>
      case l: ActionLocation =>
        result ++= getExceptionMayThrowFromAction(l.action)
      case l: JumpLocation =>
      case l: EmptyLocation =>
    }
    catchclauses.foreach {
      cc => 
        try {
          val from = pst.location(cc.fromTarget.name)
          val to = pst.location(cc.toTarget.name)
          if(loc.index >= from.index && loc.index <= to.index) result += ASTUtil.getTypeFromTypeSpec(cc.typeSpec.get)
        } catch {
          case ex: Exception =>
            System.err.println("ExceptionCenter:" + ex.getMessage)
        }
    }
    result.toSet
  }
  
  def getExceptionMayThrowFromAssignment(a: Assignment): ISet[JawaType] = {
    val result = msetEmpty[JawaType]
    a match{
      case aa: AssignAction =>
        result ++= getExceptionMayThrowFromAction(aa)
      case cj: CallJump =>
      case _ =>
    }
    result.toSet
  }
  
  def getExceptionMayThrowFromAction(a: Action): ISet[JawaType] = {
    val result = msetEmpty[JawaType]
    a match{
      case aa: AssignAction =>
        aa.op match{
          case "%" | "/" =>
            result += ARITHMETIC_EXCEPTION
          case _ =>
        }
        val lhss = PilarAstHelper.getLHSs(aa)
        val rhss = PilarAstHelper.getRHSs(aa)
        (lhss ++ rhss).foreach {
          case ie: IndexingExp =>
            result += ARRAYINDEXOUTOFBOUNDS_EXCEPTION
          case ce: CastExp =>
            result += CLASSCAST_EXCEPTION
          case _ =>
        }
      case ta: ThrowAction =>
        result += THROWABLE
      case _ =>
    }
    result.toSet
  }
}
