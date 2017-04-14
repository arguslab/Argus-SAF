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

import org.sireum.pilar.ast._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object PilarAstHelper {
  def getLHSs(a: PilarAstNode): List[Exp] = {
    var result = List[Exp]()

    def getLHSRec(e: Exp): Any =
      e match {
        case te: TupleExp => te.exps.foreach(getLHSRec)
        case _             => result ::= e
      }

    a match {
      case aa: AssignAction => getLHSRec(aa.lhs)
      case cj: CallJump =>
        cj.lhss.foreach{lhs => getLHSRec(lhs)}
      case _ =>
    }
    result
  }
  
  def getRHSs(a: PilarAstNode): List[Exp] = {
    var result = List[Exp]()

    def getRHSRec(e: Exp): Any =
      e match {
        case te: TupleExp => te.exps.foreach(getRHSRec)
        case _             => result ::= e
      }

    a match {
      case aa: AssignAction => getRHSRec(aa.rhs)
      case cj: CallJump =>
          getRHSRec(cj.callExp)
      case _ =>
    }
    result
  }

  def getCallArgs(body: MethodBody, locationIndex: Int): List[String] = {
    body.location(locationIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump].callExp.arg match {
      case te: TupleExp =>
        te.exps.map {
          case ne: NameExp => ne.name.name
          case exp => exp.toString
        }.toList
      case a => throw new RuntimeException("wrong exp type: " + a)
    }
  }

}
