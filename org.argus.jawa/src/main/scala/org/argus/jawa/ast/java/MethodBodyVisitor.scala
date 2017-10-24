/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.java

import com.github.javaparser.ast.expr._
import com.github.javaparser.ast.stmt._
import com.github.javaparser.ast.visitor.VoidVisitorAdapter
import org.argus.jawa.ast.{AssignmentStatement, BinaryExpression, CallLhs, CallRhs, CallStatement, EmptyStatement, IfStatement, LiteralExpression, LocalVarDeclaration, Location, LocationDefSymbol, LocationSymbol, MethodNameSymbol, NameExpression, NewExpression, ReturnStatement, ThrowStatement, TokenValue, TypeSymbol, VarDefSymbol, VarSymbol, Annotation => JawaAnnotation, CatchClause => JawaCatchClause, Statement => JawaStatement}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.RangePosition
import org.argus.jawa.core.util._

class MethodBodyVisitor(j2j: Java2Jawa, ownerSig: Signature, ownerPos: RangePosition) extends VoidVisitorAdapter[Void] {

  import j2j._

  var lineCount: Int = 0
  var labelCount: Int = 0

  val localVariables: MMap[String, JawaType] = mmapEmpty
  val localVarDeclarations: MList[LocalVarDeclaration] = mlistEmpty

  trait LocPresentation {
    def num: Int
    def index: Int
    def pos: RangePosition
  }
  case class Loc(num: Int, index: Int, pos: RangePosition) extends LocPresentation
  case class Label(num: Int, index: Int, pos: RangePosition) extends LocPresentation
  private val statements: MList[(LocPresentation, JawaStatement)] = mlistEmpty
  val catchClauses: MList[JawaCatchClause] = mlistEmpty

  def locations: IList[Location] = {
    checkVoidReturn()
    val digits: Int = if (lineCount == 0) 1 else 1 + Math.floor(Math.log10(Math.abs(lineCount))).toInt
    val format = "#L%%0%dd.".format(digits)
    statements.map { case (presentation, statement) =>
      val locStr = presentation match {
        case Loc(num, _, _) =>
          format.format(num)
        case Label(num, _, _) =>
          s"#Label$num."
      }
      val lds = LocationDefSymbol(Token(Tokens.LOCATION_ID, presentation.pos, locStr))
      lds.locationIndex = presentation.index
      Location(lds, statement).withPos(presentation.pos)
    }.toList
  }

  private def checkVoidReturn(): Unit = {
    if(ownerSig.getReturnType == JavaKnowledge.VOID) {
      var needVoidReturn = false
      statements.lastOption match {
        case Some((_, s)) =>
          if(!s.isInstanceOf[ReturnStatement] && !s.isInstanceOf[ThrowStatement]) {
            needVoidReturn = true
          }
        case None =>
          needVoidReturn = true
      }
      if(needVoidReturn) {
        val kindKey = Token(Tokens.ID, ownerPos, "kind")
        val kindValue = TokenValue(Token(Tokens.ID, ownerPos, "void"))
        val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
        val rs = ReturnStatement(None, List(annotation)).withPos(ownerPos)
        createLocation(ownerPos, rs)
      }
    }
  }

  var resultHolder: VarSymbol = _

  private def createLocation(pos: RangePosition, statement: JawaStatement): Unit = {
    statements += ((Loc(lineCount, lineCount + labelCount, pos), statement))
    lineCount += 1

  }

  private def createLabel(pos: RangePosition, label: String): Unit = {
    statements += ((Label(labelCount, lineCount + labelCount, pos), EmptyStatement(List())))
    labelCount += 1
  }

  /**
    * expectedName could be already exist, if type did not match we will create a new name by adding numbers
    */
  private def checkAndAddVariable(varType: JawaType, typPos: RangePosition, expectedName: String, namePos: RangePosition): String = {
    var needAdd: Boolean = false
    var varName = expectedName
    if(localVariables.contains(varName)) {
      var i = 1
      while (localVariables.getOrElseUpdate(varName, varType) != varType) {
        varName = varName + i
        i += 1
        needAdd = true
      }
    } else {
      needAdd = true
    }
    if(needAdd) {
      val vType = handleJawaType(varType, typPos)
      val vdf = VarDefSymbol(Token(Tokens.ID, namePos, varName))
      val lvd = LocalVarDeclaration(Some(vType), vdf).withPos(namePos)
      localVarDeclarations += lvd
    }
    varName
  }

  /**
    * java:
    *   assert check : message;
    *
    * jawa:
    *   result := check;
    *   if result != 0 then goto Label;
    *   msg := message;
    *   assertionError:= new java.lang.AssertionError(msg);
    *   throw assertionError;
    *   Label:
    */
  override def visit(as: AssertStmt, arg: Void): Unit = {
    as.getCheck.accept(this, arg)
    val biExpr = BinaryExpression(resultHolder, Token(Tokens.OP, getKeyWordRange(as), "!="), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, getKeyWordRange(as), "0"))))).withNode(as)
    val label = s"Label$labelCount"
    val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, getKeyWordRange(as), label))).withNode(as)
    createLocation(getKeyWordRange(as), ifStmt)
    as.getMessage.ifPresent(m => m.accept(this, arg))

    // create AssertionError
    val assertType = new JawaType("java.lang.AssertionError")
    val assertVarName = checkAndAddVariable(assertType, as.toRange, "assertionError", as.toRange)
    val assertVarSymbol = VarSymbol(Token(Tokens.ID, as.toRange, assertVarName))
    val assertNameExp = NameExpression(Left(assertVarSymbol)).withNode(as)
    val assertNewExp = NewExpression(Left(TypeSymbol(Token(Tokens.ID, as.toRange, assertType.jawaName.apostrophe))), ilistEmpty).withNode(as)
    val assertAssign = AssignmentStatement(assertNameExp, assertNewExp, ilistEmpty).withNode(as)
    createLocation(as.toRange, assertAssign)

    // create AssertionError init
    val assertInitVarSymbols: MList[VarSymbol] = mlistEmpty
    assertInitVarSymbols += assertVarSymbol
    val assertInitParamTyps: MList[JawaType] = mlistEmpty
    as.getMessage.ifPresent { msg =>
      msg.accept(this, arg)
      assertInitVarSymbols += resultHolder
      val msgType = localVariables.getOrElse(resultHolder.varName, JavaKnowledge.STRING)
      val paramType = msgType match {
        case t if t.isObject =>
          JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
        case t => t
      }
      assertInitParamTyps += paramType
    }
    val assertInitCall = generateCall(None, assertType, "<init>", as.toRange, assertInitVarSymbols.toList, assertInitParamTyps.toList, JavaKnowledge.VOID, "direct")
    createLocation(as.toRange, assertInitCall)

    // create throw statement
    val assertThrow = ThrowStatement(assertVarSymbol).withNode(as)
    createLocation(as.toRange, assertThrow)

    createLabel(as.toRange, label)
  }

  /**
    * java:
    *   super(15);
    *
    * jawa:
    *   arg = 15;
    *   call `<init>`(arg) @signature `LC;.<init>:(I)V` @kind direct;
    */
  override def visit(ecis: ExplicitConstructorInvocationStmt, arg: Void): Unit = {
    val args: MList[VarSymbol] = mlistEmpty
    val argTypes: MList[JawaType] = mlistEmpty
    args += VarSymbol(Token(Tokens.ID, ecis.toRange, "this".apostrophe))
    ecis.getArguments.forEach { argument =>
      argument.accept(this, arg)
      args += resultHolder
      argTypes += localVariables.getOrElse(resultHolder.varName, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
    }
    val call = generateCall(None, ownerSig.getClassType, "<init>", ecis.toRange, args.toList, argTypes.toList, JavaKnowledge.VOID, "direct")
    createLocation(ecis.toRange, call)
  }

  private def generateCall(lhsOpt: Option[CallLhs], classType: JawaType, methodName: String, namePos: RangePosition, args: IList[VarSymbol], argTypes: IList[JawaType], retType: JawaType, kind: String): CallStatement = {
    val sig = JavaKnowledge.genSignature(classType, methodName, argTypes, retType)
    val mns = MethodNameSymbol(Token(Tokens.ID, namePos, methodName.apostrophe))
    mns.signature = sig
    val rhs = CallRhs(mns, args).withPos(namePos)
    val annotations: MList[JawaAnnotation] = mlistEmpty
    // add singature annotation
    val signatureKey = Token(Tokens.ID, namePos, "signature")
    val signatureValue = TokenValue(Token(Tokens.ID, namePos, sig.signature.apostrophe))
    annotations += JawaAnnotation(signatureKey, Some(signatureValue)).withPos(namePos)
    // add kind annotation
    val accessFlagKey = Token(Tokens.ID, namePos, "kind")
    val accessFlagValue = TokenValue(Token(Tokens.ID, namePos, kind))
    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue)).withPos(namePos)
    CallStatement(lhsOpt, rhs, annotations.toList)
  }

  // visit LiteralExpr

  private def processLiteralExpr(l: LiteralExpr): VarSymbol = {
    l.getParentNode.ifPresent{
      case _ : AssignExpr =>
        return resultHolder
      case _ =>
    }
    val (varName, typ) = l match {
      case _ : BooleanLiteralExpr => ("booleanTemp", JavaKnowledge.BOOLEAN)
      case _ : CharLiteralExpr => ("charTemp", JavaKnowledge.CHAR)
      case _ : DoubleLiteralExpr => ("doubleTemp", JavaKnowledge.DOUBLE)
      case _ : IntegerLiteralExpr => ("intTemp", JavaKnowledge.INT)
      case _ : LongLiteralExpr => ("longTemp", JavaKnowledge.LONG)
      case _ : NullLiteralExpr => ("objectTemp", JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
      case _ : StringLiteralExpr => ("stringTemp", JavaKnowledge.STRING)
      case _ => throw Java2JawaException(s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
    }

    VarSymbol(Token(Tokens.ID, l.toRange, checkAndAddVariable(typ, l.toRange, varName, l.toRange)))
  }

  /**
    * java:
    *   false
    *
    * jawa:
    *   result := false
    */
  override def visit(l: BooleanLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: Int = if(l.getValue) 1 else 0
    val be = AssignmentStatement(NameExpression(Left(left)), LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, s"${b.toString}I")), ilistEmpty).withNode(l)
    createLocation(l.toRange, be)
    resultHolder = left
  }
}
