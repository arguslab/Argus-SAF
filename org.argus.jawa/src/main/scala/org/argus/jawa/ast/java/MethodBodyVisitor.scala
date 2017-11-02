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

import com.github.javaparser.ast.body.VariableDeclarator
import com.github.javaparser.ast.expr._
import com.github.javaparser.ast.stmt._
import com.github.javaparser.ast.visitor.VoidVisitorAdapter
import org.argus.jawa.ast.{AccessExpression, AssignmentStatement, BinaryExpression, CallRhs, CallStatement, EmptyStatement, FieldNameSymbol, GotoStatement, IfStatement, LHS, LiteralExpression, LocalVarDeclaration, Location, LocationDefSymbol, LocationSymbol, MethodNameSymbol, NewExpression, NullExpression, RHS, ReturnStatement, StaticFieldAccessExpression, ThrowStatement, TokenValue, TypeExpression, TypeFragmentWithInit, TypeSymbol, VarDefSymbol, VarSymbol, VariableNameExpression, Annotation => JawaAnnotation, CatchClause => JawaCatchClause, Expression => JawaExpression, Statement => JawaStatement}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.{JavaKnowledge, JawaPackage, JawaType, Signature}
import org.argus.jawa.core.io.{Position => JawaPosition, RangePosition}
import org.argus.jawa.core.util._

class MethodBodyVisitor(j2j: Java2Jawa, ownerSig: Signature, ownerPos: RangePosition) extends VoidVisitorAdapter[Void] {

  import j2j._

  var lineCount: Int = 0
  var labelCount: Int = 0

  val thisVar: VarSymbol = VarSymbol(Token(Tokens.ID, ownerPos, "this".apostrophe))(ownerPos)
  val localVariables: MMap[String, JawaType] = mmapEmpty ++ getParams(ownerSig)
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
      val lds = LocationDefSymbol(Token(Tokens.LOCATION_ID, presentation.pos, locStr))(presentation.pos)
      lds.locationIndex = presentation.index
      Location(lds, statement)(presentation.pos)
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
        val kindValue = TokenValue(Token(Tokens.ID, ownerPos, "void"))(ownerPos)
        val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(ownerPos)
        val rs = ReturnStatement(None, List(annotation))(ownerPos)
        createLocation(ownerPos, rs)
      }
    }
  }

  private def createLocation(pos: RangePosition, statement: JawaStatement): Unit = {
    statements += ((Loc(lineCount, lineCount + labelCount, pos), statement))
    lineCount += 1
  }

  private def createLabel(pos: RangePosition): Unit = {
    statements += ((Label(labelCount, lineCount + labelCount, pos), EmptyStatement(List())(pos)))
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
      val vdf = VarDefSymbol(Token(Tokens.ID, namePos, varName.apostrophe))(namePos)
      val lvd = LocalVarDeclaration(Some(vType), vdf)(namePos)
      localVariables(varName) = vType.typ
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
    isLeft = false
    as.getCheck.accept(this, arg)
    val biExpr = BinaryExpression(resultHolder, Token(Tokens.OP, getKeyWordRange(as), "!="), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, getKeyWordRange(as), "0"))(as.toRange))))(as.toRange)
    val label = s"Label$labelCount"
    val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, getKeyWordRange(as), label))(as.toRange))(as.toRange)
    createLocation(getKeyWordRange(as), ifStmt)
    as.getMessage.ifPresent { m =>
      isLeft = false
      m.accept(this, arg)
    }
    // create AssertionError
    val assertType = new JawaType("java.lang.AssertionError")
    val assertVarName = checkAndAddVariable(assertType, as.toRange, "assertionError", as.toRange)
    val assertVarSymbol = VarSymbol(Token(Tokens.ID, as.toRange, assertVarName.apostrophe))(as.toRange)
    val assertNameExp = VariableNameExpression(assertVarSymbol)(as.toRange)
    val assertNewExp = NewExpression(TypeSymbol(Token(Tokens.ID, as.toRange, assertType.jawaName.apostrophe))(as.toRange), ilistEmpty)(as.toRange)
    val assertAssign = AssignmentStatement(assertNameExp, assertNewExp, ilistEmpty)(as.toRange)
    createLocation(as.toRange, assertAssign)

    // create AssertionError init
    val assertInitVarSymbols: MList[VarSymbol] = mlistEmpty
    assertInitVarSymbols += assertVarSymbol
    val assertInitParamTyps: MList[JawaType] = mlistEmpty
    as.getMessage.ifPresent { msg =>
      isLeft = false
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
    val assertThrow = ThrowStatement(assertVarSymbol)(as.toRange)
    createLocation(as.toRange, assertThrow)

    createLabel(as.toRange)
  }

  override def visit(blockStmt: BlockStmt, arg: Void): Unit = {
    blockStmt.getStatements.forEach{ stmt =>
      isLeft = true
      stmt.accept(this, arg)
    }
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
    args += thisVar
    ecis.getArguments.forEach { argument =>
      isLeft = false
      argument.accept(this, arg)
      args += resultHolder
      argTypes += localVariables.getOrElse(resultHolder.varName, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
    }
    val classType = if(ecis.isThis) {
      ownerSig.getClassType
    } else {
      getSuperType(ownerSig.getClassType)
    }
    val call = generateCall(None, classType, "<init>", ecis.toRange, args.toList, argTypes.toList, JavaKnowledge.VOID, "direct")
    createLocation(ecis.toRange, call)
  }

  /**
    * java:
    *   return exp;
    *
    * jawa:
    *   temp:= exp;
    *   return temp;
    */
  override def visit(rs: ReturnStmt, arg: Void): Unit = {
    var retVs: Option[VarSymbol] = None
    rs.getExpression.ifPresent{ exp =>
      isLeft = false
      exp.accept(this, arg)
      retVs = Some(resultHolder)
    }
    val annotations: MList[JawaAnnotation] = mlistEmpty
    retVs match {
      case Some(_) =>
        if(ownerSig.getReturnType.isObject) {
          val kindKey = Token(Tokens.ID, rs.toRange, "kind")
          val kindValue = TokenValue(Token(Tokens.ID, rs.toRange, "object"))(rs.toRange)
          annotations += JawaAnnotation(kindKey, Some(kindValue))(rs.toRange)
        }
      case None =>
        val kindKey = Token(Tokens.ID, rs.toRange, "kind")
        val kindValue = TokenValue(Token(Tokens.ID, rs.toRange, "void"))(rs.toRange)
        annotations += JawaAnnotation(kindKey, Some(kindValue))(rs.toRange)
    }
    val reStat = ReturnStatement(retVs, annotations.toList)(rs.toRange)
    createLocation(rs.toRange, reStat)
  }

  private def generateCall(lhsOpt: Option[VariableNameExpression], classType: JawaType, methodName: String, namePos: JawaPosition, args: IList[VarSymbol], argTypes: IList[JawaType], retType: JawaType, kind: String): CallStatement = {
    val sig = JavaKnowledge.genSignature(classType, methodName, argTypes, retType)
    val mns = MethodNameSymbol(Token(Tokens.ID, namePos, methodName.apostrophe))(namePos)
    mns.signature = sig
    val rhs = CallRhs(mns, args)(namePos)
    val annotations: MList[JawaAnnotation] = mlistEmpty
    // add singature annotation
    val signatureKey = Token(Tokens.ID, namePos, "signature")
    val signatureValue = TokenValue(Token(Tokens.ID, namePos, sig.signature.apostrophe))(namePos)
    annotations += JawaAnnotation(signatureKey, Some(signatureValue))(namePos)
    // add kind annotation
    val accessFlagKey = Token(Tokens.ID, namePos, "kind")
    val accessFlagValue = TokenValue(Token(Tokens.ID, namePos, kind))(namePos)
    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(namePos)
    CallStatement(lhsOpt, rhs, annotations.toList)(namePos)
  }

  //***********************************************************************************************
  //                                          Visit Expression
  //***********************************************************************************************

  private var resultHolder: VarSymbol = _
  private var LHS: JawaExpression with LHS = _
  // Toggle to control generate resultHolder or LHS
  private var isLeft = false

  //*********************************************************************
  //                       LiteralExpr
  //*********************************************************************

  private def processLiteralExpr(l: LiteralExpr): VarSymbol = {
    val (varName, typ) = l match {
      case _ : BooleanLiteralExpr => ("boolean_temp", JavaKnowledge.BOOLEAN)
      case _ : CharLiteralExpr => ("char_temp", JavaKnowledge.CHAR)
      case _ : DoubleLiteralExpr => ("double_temp", JavaKnowledge.DOUBLE)
      case _ : IntegerLiteralExpr => ("int_temp", JavaKnowledge.INT)
      case _ : LongLiteralExpr => ("long_temp", JavaKnowledge.LONG)
      case _ : NullLiteralExpr => ("object_temp", JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
      case _ : StringLiteralExpr => ("string_temp", JavaKnowledge.STRING)
      case _ => throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
    }
    VarSymbol(Token(Tokens.ID, l.toRange, checkAndAddVariable(typ, l.toRange, varName, l.toRange).apostrophe))(l.toRange)
  }

  /**
    * java:
    *   false
    *
    * jawa:
    *   result := 0
    */
  override def visit(l: BooleanLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = if(l.getValue) "1I" else "0I"
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: CharLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = l.getValue
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.CHARACTER_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: DoubleLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = l.getValue
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.FLOATING_POINT_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: IntegerLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = l.getValue
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: LongLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = l.getValue
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: NullLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = "null"
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), NullExpression(Token(Tokens.NULL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: StringLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val b: String = l.getValue
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), LiteralExpression(Token(Tokens.STRING_LITERAL, l.toRange, b))(l.toRange), ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  /**
    * java:
    *   left = right;
    *
    * jawa:
    *   temp1:= right;
    *   left:= temp;
    *   temp:= left;
    *
    * java:
    *   left += right;
    *
    * jawa:
    *   temp1:= right;
    *   temp2:= left;
    *   left:= temp2 + temp1;
    *   temp:= left;
    */
  override def visit(ae: AssignExpr, arg: Void): Unit = {
    val left = isLeft
    isLeft = false
    ae.getValue.accept(this, arg)
    val temp1 = resultHolder
    val temp1Type = localVariables.getOrElse(temp1.varName, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
    val annotations: MList[JawaAnnotation] = mlistEmpty
    val rhs: JawaExpression with RHS = ae.getOperator match {
      case AssignExpr.Operator.ASSIGN =>
        if(temp1Type.isObject) {
          val kindKey = Token(Tokens.ID, ae.toRange, "kind")
          val kindValue = TokenValue(Token(Tokens.ID, ae.toRange, "object"))(ae.toRange)
          annotations += JawaAnnotation(kindKey, Some(kindValue))(ae.toRange)
        }
        VariableNameExpression(temp1)(ae.toRange)
      case op =>
        isLeft = false
        ae.getTarget.accept(this, arg)
        val temp2 = resultHolder
        val opStr = op match {
          case AssignExpr.Operator.AND => "^&"
          case AssignExpr.Operator.DIVIDE => "/"
          case AssignExpr.Operator.LEFT_SHIFT => "^<"
          case AssignExpr.Operator.MINUS => "-"
          case AssignExpr.Operator.MULTIPLY => "*"
          case AssignExpr.Operator.OR => "^|"
          case AssignExpr.Operator.PLUS => "+"
          case AssignExpr.Operator.REMAINDER => "%%"
          case AssignExpr.Operator.SIGNED_RIGHT_SHIFT => "^>"
          case AssignExpr.Operator.UNSIGNED_RIGHT_SHIFT => "^>>"
          case AssignExpr.Operator.XOR => "^~"
          case _ => throw Java2JawaException(ae.toRange, s"Unhandled operator $op, please contact author: fgwei521@gmail.com")
        }
        BinaryExpression(temp2, Token(Tokens.OP, getKeyWordRange(ae), opStr), Left(temp1))(ae.toRange)
    }
    isLeft = true
    ae.getTarget.accept(this, arg)
    val assign = AssignmentStatement(LHS, rhs, annotations.toList)(ae.toRange)
    createLocation(ae.toRange, assign)
    if(!left) {
      val tempName = checkAndAddVariable(temp1Type, ae.toRange, s"${temp1Type.baseType.name}_temp", ae.toRange)
      val tempVar = VarSymbol(Token(Tokens.ID, ae.toRange, tempName.apostrophe))(ae.toRange)
      val tempannotations: MList[JawaAnnotation] = mlistEmpty
      if (temp1Type.isObject) {
        val kindKey = Token(Tokens.ID, ae.toRange, "kind")
        val kindValue = TokenValue(Token(Tokens.ID, ae.toRange, "object"))(ae.toRange)
        tempannotations += JawaAnnotation(kindKey, Some(kindValue))(ae.toRange)
      }
      val tempAssign = AssignmentStatement(VariableNameExpression(tempVar)(ae.toRange), LHS, tempannotations.toList)(ae.toRange)
      createLocation(getKeyWordRange(ae), tempAssign)
      resultHolder = tempVar
    }
  }

  /**
    * java:
    *   a + b
    *
    * jawa:
    *   temp1:= a;
    *   temp2:= b;
    *   temp3:= temp1 + temp2;
    *
    * java:
    *   a == b
    *
    * jawa:
    *   temp1:= a;
    *   temp2:= b;
    *   if temp1 != temp2 then goto Label1:
    *   temp3:= 1;
    *   goto Label2;
    *   Label1:
    *   temp3:= 0;
    *   Label2:
    */
  override def visit(be: BinaryExpr, arg: Void): Unit = {
    isLeft = false
    be.getLeft.accept(this, arg)
    val temp1 = resultHolder
    isLeft = false
    be.getRight.accept(this, arg)
    val temp2 = resultHolder
    val op: Either[String, String] = be.getOperator match {
      case BinaryExpr.Operator.AND => Right("^&")
      case BinaryExpr.Operator.BINARY_AND => Right("^&")
      case BinaryExpr.Operator.BINARY_OR => Right("^|")
      case BinaryExpr.Operator.DIVIDE => Right("/")
      case BinaryExpr.Operator.EQUALS => Left("==")
      case BinaryExpr.Operator.GREATER => Left(">")
      case BinaryExpr.Operator.GREATER_EQUALS => Left(">=")
      case BinaryExpr.Operator.LEFT_SHIFT => Right("^<")
      case BinaryExpr.Operator.LESS => Left("<")
      case BinaryExpr.Operator.LESS_EQUALS => Left("<=")
      case BinaryExpr.Operator.MINUS => Right("-")
      case BinaryExpr.Operator.MULTIPLY => Right("*")
      case BinaryExpr.Operator.NOT_EQUALS => Left("!=")
      case BinaryExpr.Operator.OR => Right("^|")
      case BinaryExpr.Operator.PLUS => Right("+")
      case BinaryExpr.Operator.REMAINDER => Right("%%")
      case BinaryExpr.Operator.SIGNED_RIGHT_SHIFT => Right("^>")
      case BinaryExpr.Operator.UNSIGNED_RIGHT_SHIFT => Right("^>>")
      case BinaryExpr.Operator.XOR => Right("^~")
    }
    op match {
      case Left(o) =>
        val biExpr = BinaryExpression(temp1, Token(Tokens.OP, getKeyWordRange(be), o), Left(temp2))(be.toRange)
        val label = s"Label$labelCount"
        val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, getKeyWordRange(be), label))(be.toRange))(be.toRange)
        createLocation(getKeyWordRange(be), ifStmt)
        val temp3Name = checkAndAddVariable(JavaKnowledge.BOOLEAN, be.toRange, "boolean_temp", be.toRange)
        val temp3Var = VarSymbol(Token(Tokens.ID, be.toRange, temp3Name.apostrophe))(be.toRange)
        val assignStmt1 = AssignmentStatement(VariableNameExpression(temp3Var)(be.toRange), LiteralExpression(Token(Tokens.INTEGER_LITERAL, be.toRange, "0"))(be.toRange), ilistEmpty)(be.toRange)
        createLocation(getKeyWordRange(be), assignStmt1)
        val label2 = s"Label${labelCount + 1}"
        val gotoStmt = GotoStatement(LocationSymbol(Token(Tokens.ID, be.toRange, label2))(be.toRange))(be.toRange)
        createLocation(getKeyWordRange(be), gotoStmt)
        createLabel(getKeyWordRange(be))
        val assignStmt2 = AssignmentStatement(VariableNameExpression(temp3Var)(be.toRange), LiteralExpression(Token(Tokens.INTEGER_LITERAL, be.toRange, "1"))(be.toRange), ilistEmpty)(be.toRange)
        createLocation(getKeyWordRange(be), assignStmt2)
        createLabel(getKeyWordRange(be))
        resultHolder = temp3Var
      case Right(o) =>
        val binExp = BinaryExpression(temp1, Token(Tokens.OP, getKeyWordRange(be), o), Left(temp2))(be.toRange)
        val typ = localVariables.getOrElse(temp1.varName, JavaKnowledge.INT)
        val expectedName = if(typ.isObject) "object_temp" else s"${typ.name}_temp"
        val temp3Name = checkAndAddVariable(typ, be.toRange, expectedName, be.toRange)
        val temp3Var = VarSymbol(Token(Tokens.ID, be.toRange, temp3Name.apostrophe))(be.toRange)
        val assignStmt = AssignmentStatement(VariableNameExpression(temp3Var)(be.toRange), binExp, ilistEmpty)(be.toRange)
        createLocation(getKeyWordRange(be), assignStmt)
        resultHolder = temp3Var
    }
  }

  /**
    * java (left):
    *   name:= v;
    *
    * jawa:
    *   name:= v;
    *
    * java (right):
    *   v:= name
    *
    * jawa:
    *   v:= name;
    *
    */
  override def visit(ne: NameExpr, arg: Void): Unit = {
    val clazz = global.getClassOrResolve(ownerSig.getClassType)
    clazz.getField(ne.getNameAsString) match {
      case Some(f) =>
        val typeExp = TypeExpression(handleJawaType(f.typ, ne.toRange))(ne.toRange)
        val exp = if(f.isStatic) {
          StaticFieldAccessExpression(FieldNameSymbol(Token(Tokens.ID, ne.toRange, s"@@${f.FQN.fqn}".apostrophe))(ne.toRange), typeExp)(ne.toRange)
        } else {
          AccessExpression(thisVar, FieldNameSymbol(Token(Tokens.ID, ne.getName.toRange, f.FQN.fqn.apostrophe))(ne.toRange), typeExp)(ne.toRange)
        }
        if(isLeft) {
          LHS = exp
        } else {
          val temp = checkAndAddVariable(f.typ, ne.toRange, s"field_${f.getName}", ne.toRange)
          val tempVs = VarSymbol(Token(Tokens.ID, ne.toRange, temp.apostrophe))(ne.toRange)
          val annotations: MList[JawaAnnotation] = mlistEmpty
          if (f.isObject) {
            val kindKey = Token(Tokens.ID, ne.toRange, "kind")
            val kindValue = TokenValue(Token(Tokens.ID, ne.toRange, "object"))(ne.toRange)
            annotations += JawaAnnotation(kindKey, Some(kindValue))(ne.toRange)
          }
          val assign = AssignmentStatement(VariableNameExpression(tempVs)(ne.toRange), exp, annotations.toList)(ne.toRange)
          createLocation(ne.toRange, assign)
          resultHolder = tempVs
        }
      case None =>
        val vs = VarSymbol(Token(Tokens.ID, ne.toRange, ne.getNameAsString.apostrophe))(ne.toRange)
        if(isLeft) {
          val name = VariableNameExpression(vs)(vs.pos)
          LHS = name
        } else {
          resultHolder = vs
        }
    }
  }

  /**
    * java (left):
    *   person.name = v;
    *
    * jawa:
    *   temp := person;
    *   temp.name := v;
    *
    * java (right):
    *   v = person.name;
    *
    * jawa:
    *   temp := person;
    *   temp2 := temp.name;
    *   v := temp2;
    */
  override def visit(fae: FieldAccessExpr, arg: Void): Unit = {
    val left = isLeft
    resolveScope(fae.getScope) match {
      case Left(baseType) =>
        val clazz = global.getClassOrResolve(baseType)
        clazz.getField(fae.getNameAsString) match {
          case Some(f) =>
            val typeExp = TypeExpression(handleJawaType(f.typ, fae.toRange))(fae.toRange)
            val exp = if(f.isStatic) {
              StaticFieldAccessExpression(FieldNameSymbol(Token(Tokens.ID, fae.toRange, s"@@${f.FQN.fqn}".apostrophe))(fae.toRange), typeExp)(fae.toRange)
            } else {
              isLeft = false
              fae.getScope.accept(this, arg)
              val temp = resultHolder
              AccessExpression(temp, FieldNameSymbol(Token(Tokens.ID, fae.getName.toRange, f.FQN.fqn.apostrophe))(fae.getName.toRange), typeExp)(fae.getName.toRange)
            }
            if(left) {
              LHS = exp
            } else {
              val temp2_name = checkAndAddVariable(f.typ, fae.toRange, s"field_${f.getName}", fae.toRange)
              val temp2_var = VarSymbol(Token(Tokens.ID, fae.toRange, temp2_name.apostrophe))(fae.toRange)
              val temp2_vne = VariableNameExpression(temp2_var)(temp2_var.pos)
              val annotations: MList[JawaAnnotation] = mlistEmpty
              if (f.typ.isObject) {
                val kindKey = Token(Tokens.ID, temp2_vne.pos, "kind")
                val kindValue = TokenValue(Token(Tokens.ID, temp2_vne.pos, "object"))(temp2_vne.pos)
                annotations += JawaAnnotation(kindKey, Some(kindValue))(kindKey.pos)
              }
              val assign_stmt = AssignmentStatement(temp2_vne, exp, annotations.toList)(temp2_vne.pos)
              createLocation(getKeyWordRange(fae), assign_stmt)
              resultHolder = temp2_var
            }
          case None =>
            throw Java2JawaException(fae.toRange, s"Could not find field ${fae.getNameAsString} from ${baseType.jawaName}")
        }
      case Right(pkg) =>
        throw Java2JawaException(fae.toRange, s"Array access on package is not allowed. Package name: ${pkg.toPkgString(".")}")
    }
  }

  /**
    * java:
    *   new A().new Data(arg1, arg2);
    *
    * jawa:
    *   temp:= new A$Data;
    *   temp2:= new A;
    *   call <init>(temp2) @kind direct;
    *   call class_temp:=  `java.lang.Object.getClass`(temp2) @signature `Ljava/lang/Object;.getClass:()Ljava/lang/Class;` @kind virtual;
    *
    *   arg1_temp:= arg1;
    *   arg2_temp:= arg2;
    *   call <init>(temp, temp2, arg1_temp, arg2_temp) @kind direct;
    */
  override def visit(oce: ObjectCreationExpr, arg: Void): Unit = {
    val typ = resolveScope(oce) match {
      case Left(t) => t
      case Right(pkg) =>
        throw Java2JawaException(oce.getType.toRange, s"ObjectCreationExpr should not be package. Package name: ${pkg.toPkgString(".")}")
    }
    val baseTyp = TypeSymbol(Token(Tokens.ID, oce.getType.toRange, typ.jawaName.apostrophe))(oce.getType.toRange)
    val typeFragmentsWithInit: MList[TypeFragmentWithInit] = mlistEmpty
    for(_ <- 0 until typ.dimensions) {
      typeFragmentsWithInit += TypeFragmentWithInit(ilistEmpty)(oce.getType.toRange)
    }
    val temp = checkAndAddVariable(typ, oce.toRange, s"${typ.baseType.name}_temp", oce.toRange)
    val temp_var = VarSymbol(Token(Tokens.ID, baseTyp.pos, temp.apostrophe))(baseTyp.pos)
    val temp_vne = VariableNameExpression(temp_var)(baseTyp.pos)
    val newExp = NewExpression(baseTyp, typeFragmentsWithInit.toList)(temp_vne.pos)
    val assign_stmt = AssignmentStatement(temp_vne, newExp, ilistEmpty)(temp_vne.pos)
    createLocation(getKeyWordRange(oce), assign_stmt)
    val args: MList[VarSymbol] = mlistEmpty
    args += temp_var
    val arg_types: MList[JawaType] = mlistEmpty
    oce.getScope.ifPresent{ s =>
      isLeft = false
      s.accept(this, arg)
      val outerVar = resultHolder
      val class_temp = checkAndAddVariable(JavaKnowledge.CLASS, oce.toRange, "class_temp", oce.toRange)
      val lhs = VariableNameExpression(VarSymbol(Token(Tokens.ID, oce.toRange, class_temp.apostrophe))(oce.toRange))(oce.toRange)
      val call = generateCall(Some(lhs), JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, "getClass", oce.toRange, List(outerVar), ilistEmpty, JavaKnowledge.CLASS, "virtual")
      createLocation(getKeyWordRange(oce), call)
      args += outerVar
      arg_types += JavaKnowledge.getOuterTypeFrom(typ)
    }
    oce.getArguments.forEach{ argument =>
      isLeft = false
      argument.accept(this, arg)
      args += resultHolder
      arg_types += localVariables.getOrElse(resultHolder.varName, throw Java2JawaException(argument.toRange, s"Cannot resolve argument type for: $argument"))
    }
    val init_call = generateCall(None, typ, "<init>", assign_stmt.pos, args.toList, arg_types.toList, JavaKnowledge.VOID, "direct")
    createLocation(getKeyWordRange(oce), init_call)
    resultHolder = temp_var
  }

  override def visit(thisExp: ThisExpr, arg: Void): Unit = {
    resultHolder = thisVar
  }

  /**
    * java:
    *   int i = 1;
    *
    * jawa:
    *   `int` i;
    *
    *   temp:= 1;
    *   i:= temp;
    *
    * java:
    *   Data d = new Data();
    *
    * jawa:
    *   `Data` d;
    *
    *   temp := new `Data`;
    *   call `<init>`(temp) @signature `LData;.<init>:()V` @kind direct;
    *   d := temp;
    */
  override def visit(vde: VariableDeclarationExpr, arg: Void): Unit = {
    vde.getVariables.forEach(v => v.accept(this, arg))
  }

  override def visit(vd: VariableDeclarator, arg: Void): Unit = {
    val varType = handleType(vd.getType)
    val varName = checkAndAddVariable(varType.typ, vd.getName.toRange, vd.getNameAsString, vd.getName.toRange)
    vd.getInitializer.ifPresent { init =>
      isLeft = false
      init.accept(this, arg)
      val vs = VarSymbol(Token(Tokens.ID, vd.getName.toRange, varName.apostrophe))(vd.getName.toRange)
      val vne = VariableNameExpression(vs)(vd.getName.toRange)
      val annotations: MList[JawaAnnotation] = mlistEmpty
      if (varType.typ.isObject) {
        val kindKey = Token(Tokens.ID, vd.toRange, "kind")
        val kindValue = TokenValue(Token(Tokens.ID, vd.toRange, "object"))(vd.toRange)
        annotations += JawaAnnotation(kindKey, Some(kindValue))(vd.toRange)
      }
      val assignStmt = AssignmentStatement(vne, VariableNameExpression(resultHolder)(vd.toRange), annotations.toList)(vd.toRange)
      createLocation(getKeyWordRange(vd), assignStmt)
      resultHolder = vs
    }
  }

  private def resolveScope(scope: Expression): Either[JawaType, JawaPackage] = {
    scope match {
      case ne: NameExpr =>
        val name = ne.getNameAsString
        localVariables.get(name) match {
          case Some(typ) => Left(typ)
          case None =>
            findTypeOpt(name) match {
              case Some(typ) => Left(typ)
              case None => // it must be a package part
                Right(JawaPackage(name, None))
            }
        }
      case fae: FieldAccessExpr =>
        resolveScope(fae.getScope) match {
          case Left(typ) =>
            val clazz = global.getClassOrResolve(typ)
            clazz.getField(fae.getNameAsString) match {
              case Some(f) => Left(f.typ)
              case None => throw Java2JawaException(fae.getName.toRange, s"Field ${fae.getNameAsString} not found from class ${typ.jawaName}.")
            }
          case Right(pkg) =>
            findTypeOpt(s"${pkg.toPkgString(".")}.${fae.getNameAsString}") match {
              case Some(typ) => Left(typ)
              case None => Right(JawaPackage(fae.getNameAsString, Some(pkg)))
            }
        }
      case aae: ArrayAccessExpr =>
        resolveScope(aae.getName) match {
          case Left(typ) =>
            Left(JawaType(typ.baseType, typ.dimensions - 1))
          case Right(pkg) =>
            throw Java2JawaException(scope.toRange, s"Array access on package is not allowed. Package name: ${pkg.toPkgString(".")}")
        }
      case ace: ArrayCreationExpr =>
        Left(findType(ace.createdType()))
      case _: ClassExpr =>
        Left(JavaKnowledge.CLASS)
      case ee: EnclosedExpr =>
        resolveScope(ee.getInner)
      case mce: MethodCallExpr =>
        val baseType = if(mce.getScope.isPresent) {
          resolveScope(mce.getScope.get()) match {
            case Left(typ) =>
              typ
            case Right(pkg) =>
              throw Java2JawaException(scope.toRange, s"Method call on package is not allowed. Package name: ${pkg.toPkgString(".")}")
          }
        } else {
          ownerSig.getClassType
        }
        var argTypes: MList[JawaType] = mlistEmpty
        mce.getArguments.forEach{ arg =>
          resolveScope(arg) match {
            case Left(argTyp) =>
              argTypes += argTyp
            case Right(pkg) =>
              throw Java2JawaException(scope.toRange, s"Arg should not be package. Package name: ${pkg.toPkgString(".")}")
          }
        }
        val clazz = global.getClassOrResolve(baseType)
        clazz.getMethodByNameAndArgTypes(mce.getNameAsString, argTypes.toList) match {
          case Some(m) =>
            Left(m.getReturnType)
          case None =>
            throw Java2JawaException(scope.toRange, s"Could not find method with name: ${mce.getNameAsString}, arg types: ${argTypes.mkString(", ")}")
        }
      case oce: ObjectCreationExpr =>
        var baseTypOpt: Option[JawaType] = None
        oce.getScope.ifPresent{ s =>
          val typ = resolveScope(s)
          typ match {
            case Left(t) =>
              baseTypOpt = Some(t)
            case Right(pkg) =>
              throw Java2JawaException(scope.toRange, s"Scope for ObjectCreationExpr should not be package. Package name: ${pkg.toPkgString(".")}")
          }
        }
        baseTypOpt match {
          case Some(bt) =>
            val className = s"${bt.baseTyp}$$${oce.getType.getNameAsString}"
            Left(findType(className, oce.getType.toRange))
          case None =>
            Left(findType(oce.getType))
        }
      case _: SuperExpr =>
        Left(getSuperType(ownerSig.getClassType))
      case _: ThisExpr =>
        Left(ownerSig.getClassType)
      case _ =>
        throw Java2JawaException(scope.toRange, s"Unsupported scope expression: $scope")
    }
  }
}
