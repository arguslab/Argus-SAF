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

import org.argus.jawa.core.elements.JawaType
import org.argus.jawa.core.util.{ISet, msetEmpty}

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
          case be: BinaryExpression =>
            be.op.text match{
              case "%" | "/" =>
                result += ARITHMETIC_EXCEPTION
              case _ =>
            }
          case _ =>
        }
      case _: ThrowStatement =>
        result += THROWABLE
      case _ =>
    }
    result.toSet
  }
}
