/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.Position
import org.argus.jawa.core.util._

class BytecodeInstructions(
    sig: Signature,
    pos: Position,
    lvr: LocalVarResolver) {

  val usedVars: MSet[String] = msetEmpty
  def genJawa: ResolvedBody = {
    lvr.resolveType(instructions.toList)
    instructions.zipWithIndex.foreach { case (insn, loc) =>
      val vars = lvr.variables.getOrElse(loc, mlistEmpty)
      def getVar(idx: Int): String = {
        vars.lift(idx) match {
          case Some(lv) =>
            if(!usedVars.contains(lv.name)) {
              locals += new LocalVarDeclaration(lv.typ.typ, lv.name)
              usedVars += lv.name
            }
            lv.name
          case None =>
            throw DeBytecodeException("Local variable access out of bound.")
        }
      }
      val stmtOpt = insn.exec(getVar)
      stmtOpt match {
        case Some(stmt) =>
          insn match {
            case LabelInsn(l, _, typ) =>
              createLabel(l, stmt)
              typ match {
                case Some(t) =>
                  val temp = getVar(0)
                  val ee = new ExceptionExpression(t)
                  val stmt = new AssignmentStatement(temp, ee, List(new Annotation("kind", new TokenValue("object"))))
                  createLocation(stmt)
                case None =>
              }
            case _ =>
              createLocation(stmt)
          }
        case None =>
      }
    }
    ResolvedBody(locals.toList, locations.toList, catchClauses.toList)(pos)
  }

  //******************************************************************************
  //                         Local Variable management
  //******************************************************************************

  val locals: MList[LocalVarDeclaration] = mlistEmpty

  //************************ Local Variable management End ***********************
  private var locCount: Int = 0

  val locations: MList[Location] = mlistEmpty
  val catchClauses: MList[CatchClause] = mlistEmpty

  private def createLabel(l: String, stmt: Statement): Unit = {
    val loc = new Location(l, stmt)
    loc.locationSymbol.locationIndex = locCount
    locations += loc
    locCount += 1
  }

  private def createLocation(stmt: Statement): Unit = {
    val l = s"L$locCount"
    val loc = new Location(l, stmt)
    loc.locationSymbol.locationIndex = locCount
    locations += loc
    locCount += 1
  }

  private val instructions: MList[BytecodeInstruction] = mlistEmpty

  def addInsn(instruction: BytecodeInstruction): Int = {
    instructions += instruction
    instructions.size - 1
  }
}
