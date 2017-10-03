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

import org.argus.jawa.ast._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.util._

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
  final val ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = new JawaType("java.lang.ArrayIndexOutOfBoundsException")
  final val CLASS_CAST_EXCEPTION = new JawaType("java.lang.ClassCastException")
  
  final val EXCEPTION_VAR_NAME = "Exception"  
  
  
  def getExceptionsMayThrow(body: ResolvedBody, loc: Location, catchClauses: ISet[CatchClause]): ISet[JawaType] = {
    val result = msetEmpty[JawaType]
    getExceptionMayThrowFromStatement(loc.statement)
    catchClauses.foreach { cc =>
      try {
        if(loc.locationIndex >= cc.range.fromLocation.locationIndex && loc.locationIndex <= cc.range.toLocation.locationIndex) result += cc.typ.typ
      } catch {
        case ex: Exception =>
          System.err.println("ExceptionCenter:" + ex.getMessage)
      }
    }
    result.toSet
  }
  
  def getExceptionMayThrowFromStatement(s: Statement): ISet[JawaType] = {
    val result = msetEmpty[JawaType]
    s match{
      case aa: AssignmentStatement =>
        aa.assignOP.text match{
          case "%" | "/" =>
            result += ARITHMETIC_EXCEPTION
          case _ =>
        }
        aa.lhs match {
          case _: IndexingExpression =>
            result += ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION
          case _ =>
        }
        aa.rhs match {
          case _: IndexingExpression =>
            result += ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION
          case _: CastExpression =>
            result += CLASS_CAST_EXCEPTION
          case _ =>
        }
      case _: ThrowStatement =>
        result += THROWABLE
      case _ =>
    }
    result.toSet
  }
}
