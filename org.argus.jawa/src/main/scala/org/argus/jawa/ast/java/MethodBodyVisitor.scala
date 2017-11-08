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
import org.argus.jawa.ast.{AccessExpression, AssignmentStatement, BinaryExpression, CallRhs, CallStatement, CastExpression, ConstClassExpression, EmptyStatement, FieldNameSymbol, GotoStatement, IfStatement, IndexingExpression, IndexingSuffix, InstanceOfExpression, LHS, LiteralExpression, LocalVarDeclaration, Location, LocationDefSymbol, LocationSymbol, MethodNameSymbol, NewArrayExpression, NewExpression, RHS, ReturnStatement, StaticFieldAccessExpression, ThrowStatement, TokenValue, TupleExpression, TypeExpression, TypeSymbol, UnaryExpression, VarDefSymbol, VarSymbol, VariableNameExpression, Annotation => JawaAnnotation, CatchClause => JawaCatchClause, Expression => JawaExpression, Statement => JawaStatement, Type => JawaTypeAst}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.{JavaKnowledge, JawaPackage, JawaType, Signature}
import org.argus.jawa.core.io.{RangePosition, Position => JawaPosition}
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
    def pos: JawaPosition
  }
  case class Loc(num: Int, index: Int, pos: JawaPosition) extends LocPresentation
  case class Label(num: Int, index: Int, pos: JawaPosition) extends LocPresentation
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

  private def createLocation(pos: JawaPosition, statement: JawaStatement): Unit = {
    statements += ((Loc(lineCount, lineCount + labelCount, pos), statement))
    lineCount += 1
  }

  private def createLabel(pos: JawaPosition): Unit = {
    statements += ((Label(labelCount, lineCount + labelCount, pos), EmptyStatement(List())(pos)))
    labelCount += 1
  }

  private def generateTempVarName(varType: JawaType): String = {
    s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
  }

  /**
    * expectedName could be already exist, if type did not match we will create a new name by adding numbers
    */
  private def checkAndAddVariable(varType: JawaType, typPos: JawaPosition, expectedName: String, namePos: JawaPosition): String = {
    var needAdd: Boolean = false
    var varName = expectedName
    if(localVariables.contains(varName)) {
      var i = 1
      while (localVariables.contains(varName)) {
        varName = expectedName + i
        i += 1
        needAdd = true
      }
      localVariables(varName) = varType
//      while (localVariables.getOrElseUpdate(varName, varType) != varType) {
//        varName = varName + i
//        i += 1
//        needAdd = true
//      }
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
    val asRange = as.toRange
    as.getCheck.accept(this, arg)
    val biExpr = BinaryExpression(resultHolder, Token(Tokens.OP, getKeyWordRange(as), "!="), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, getKeyWordRange(as), "0"))(asRange))))(asRange)
    val label = s"Label$labelCount"
    val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, getKeyWordRange(as), label))(asRange))(asRange)
    createLocation(getKeyWordRange(as), ifStmt)
    as.getMessage.ifPresent { m =>
      isLeft = false
      m.accept(this, arg)
    }
    // create AssertionError
    val assertType = new JawaType("java.lang.AssertionError")
    val assertVarName = checkAndAddVariable(assertType, asRange, "assertionError", asRange)
    val assertVarSymbol = VarSymbol(Token(Tokens.ID, asRange, assertVarName.apostrophe))(asRange)
    val assertNameExp = VariableNameExpression(assertVarSymbol)(asRange)
    val assertTypeSymbol = TypeSymbol(Token(Tokens.ID, asRange, assertType.jawaName.apostrophe))(asRange)
    val assertNewExp = NewExpression(JawaTypeAst(assertTypeSymbol, ilistEmpty)(asRange))(asRange)
    val assertAssign = AssignmentStatement(assertNameExp, assertNewExp, ilistEmpty)(asRange)
    createLocation(asRange, assertAssign)

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
    val assertInitCall = generateCall(None, assertType, "<init>", asRange, assertInitVarSymbols.toList, assertInitParamTyps.toList, JavaKnowledge.VOID, "direct")
    createLocation(asRange, assertInitCall)

    // create throw statement
    val assertThrow = ThrowStatement(assertVarSymbol)(asRange)
    createLocation(asRange, assertThrow)

    createLabel(asRange)
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

  private def getLiteralExpression(l: LiteralExpr): LiteralExpression = {
    l match {
      case ble: BooleanLiteralExpr =>
        val n = if(ble.getValue) "1I" else "0I"
        LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, n))(l.toRange)
      case cle: CharLiteralExpr =>
        LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, cle.getValue))(l.toRange)
      case dle: DoubleLiteralExpr =>
        LiteralExpression(Token(Tokens.FLOATING_POINT_LITERAL, l.toRange, dle.getValue))(l.toRange)
      case ile: IntegerLiteralExpr =>
        LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, ile.getValue))(l.toRange)
      case lle: LongLiteralExpr =>
        LiteralExpression(Token(Tokens.INTEGER_LITERAL, l.toRange, lle.getValue))(l.toRange)
      case _ : NullLiteralExpr =>
        LiteralExpression(Token(Tokens.NULL, l.toRange, "null"))(l.toRange)
      case sle: StringLiteralExpr =>
        LiteralExpression(Token(Tokens.STRING_LITERAL, l.toRange, sle.getValue))(l.toRange)
      case _ => throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
    }
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
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: CharLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: DoubleLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: IntegerLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: LongLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: NullLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  override def visit(l: StringLiteralExpr, arg: Void): Unit = {
    val left = processLiteralExpr(l)
    val le: LiteralExpression = getLiteralExpression(l)
    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
    createLocation(l.toRange, be)
    resultHolder = left
  }

  private def createIntAssignment(name: String, lit: Int, pos: JawaPosition): VarSymbol = {
    val vs = VarSymbol(Token(Tokens.ID, pos, checkAndAddVariable(JavaKnowledge.INT, pos, name, pos).apostrophe))(pos)
    val vne = VariableNameExpression(vs)(pos)
    val litexp = LiteralExpression(Token(Tokens.INTEGER_LITERAL, pos, lit.toString))(pos)
    val dimension_assign = AssignmentStatement(vne, litexp, ilistEmpty)(pos)
    createLocation(pos, dimension_assign)
    vs
  }

  /**
    * java:
    *   new arr[1][2];
    *
    * jawa:
    *   temp1:= 1;
    *   temp2:= 2;
    *   temp:= new arr[temp1, temp2];
    *
    * java:
    *   new arr[][]{{1, 2}, {x, 4}};
    *
    * jawa:
    *   temp:= new arr[] [2];
    *   temp1:= new arr[2];
    *   temp1:= (1, 2) @kind object;
    *   temp2:= new arr[2];
    *   temp2[0]:= temp_x;
    *   temp2[1]:= 4;
    *   temp[0]:= temp1;
    *   temp[1]:= temp2;
    */
  override def visit(ace: ArrayCreationExpr, arg: Void): Unit = {
    val arrBaseType = handleType(ace.getElementType)
    val arrType = JawaType.addDimensions(arrBaseType.typ, ace.getLevels.size())
    if(ace.getInitializer.isPresent) {
      val init = ace.getInitializer.get()
      val init_range = init.toRange
      val dimensions = init.getValues.size()
      val dimensions_vs = createIntAssignment("int_temp", dimensions, init_range)
      val arr_type1 = JawaType(arrType.baseType, arrType.dimensions - 1)
      val nae = NewArrayExpression(handleJawaType(arr_type1, init_range), List(dimensions_vs))(init_range)
      val nae_temp_name = checkAndAddVariable(arrType, init_range, generateTempVarName(arrType), init_range)
      val nae_temp_vs = VarSymbol(Token(Tokens.ID, init_range, nae_temp_name.apostrophe))(init_range)
      val nae_temp_vne = VariableNameExpression(nae_temp_vs)(init_range)
      val nae_assign = AssignmentStatement(nae_temp_vne, nae, ilistEmpty)(init_range)
      createLocation(getKeyWordRange(ace), nae_assign)
      resultHolder = nae_temp_vs
      isLeft = false
      init.accept(this, arg)
    } else {
      val vss: MList[VarSymbol] = mlistEmpty
      ace.getLevels.forEach{ l =>
        l.getDimension.ifPresent{ d =>
          isLeft = false
          d.accept(this, arg)
          vss += resultHolder
        }
      }
      val typeRange = ace.getElementType.toRange
      val temp = checkAndAddVariable(arrType, typeRange, generateTempVarName(arrType), typeRange)
      val temp_vs = VarSymbol(Token(Tokens.ID, typeRange, temp.apostrophe))(typeRange)
      val temp_vne = VariableNameExpression(temp_vs)(typeRange)
      val nae = NewArrayExpression(arrBaseType, vss.toList)(ace.toRange)
      val assign = AssignmentStatement(temp_vne, nae, ilistEmpty)(ace.toRange)
      createLocation(getKeyWordRange(ace), assign)
      resultHolder = temp_vs
    }
  }

  override def visit(aie: ArrayInitializerExpr, arg: Void): Unit = {
    val base_vs = resultHolder
    val base_typ = localVariables.getOrElse(base_vs.varName, throw Java2JawaException(aie.toRange, "Array Type for ArrayInitializerExpr should always set."))
    val aie_range = aie.toRange
    var allLiteral = true
    val constants: MList[LiteralExpression] = mlistEmpty
    var allInit = false
    aie.getValues.forEach{
      case ble: BooleanLiteralExpr =>
        val le = getLiteralExpression(ble)
        constants += le
      case cle: CharLiteralExpr =>
        val le = getLiteralExpression(cle)
        constants += le
      case dle: DoubleLiteralExpr =>
        val le = getLiteralExpression(dle)
        constants += le
      case ile: IntegerLiteralExpr =>
        val le = getLiteralExpression(ile)
        constants += le
      case lle: LongLiteralExpr =>
        val le = getLiteralExpression(lle)
        constants += le
      case _ : ArrayInitializerExpr =>
        allLiteral = false
        allInit = true // If one is init all should be init.
      case _ =>
        allLiteral = false
    }

    if(allLiteral) {
      val tuple_exp = TupleExpression(constants.toList)(aie_range)
      val kindKey = Token(Tokens.ID, aie_range, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, aie_range, "object"))(aie_range)
      val assign_stmt = AssignmentStatement(VariableNameExpression(base_vs)(base_vs.pos), tuple_exp, List(JawaAnnotation(kindKey, Some(kindValue))(kindKey.pos)))(aie_range)
      createLocation(getKeyWordRange(aie), assign_stmt)
    } else {
      var rh = base_vs
      aie.getValues.forEach{ v =>
        if(allInit) {
          val dimensions = v.asInstanceOf[ArrayInitializerExpr].getValues.size()
          val dimensions_vs = createIntAssignment("int_temp", dimensions, aie_range)
          val arr_type1 = JawaType(base_typ.baseType, base_typ.dimensions - 1)
          val nae_temp_name = checkAndAddVariable(arr_type1, aie_range, generateTempVarName(arr_type1), aie_range)
          val nae_temp_vs = VarSymbol(Token(Tokens.ID, aie_range, nae_temp_name.apostrophe))(aie_range)
          val nae_temp_vne = VariableNameExpression(nae_temp_vs)(aie_range)
          val arr_type2 = JawaType(arr_type1.baseType, arr_type1.dimensions - 1)
          val nae = NewArrayExpression(handleJawaType(arr_type2, aie_range), List(dimensions_vs))(aie_range)
          val nae_assign = AssignmentStatement(nae_temp_vne, nae, ilistEmpty)(aie_range)
          createLocation(getKeyWordRange(aie), nae_assign)
          rh = nae_temp_vs
        }
        val idx = aie.getValues.indexOf(v)
        val idx_vs = createIntAssignment("int_temp", idx, aie_range)
        val idx_exp = IndexingExpression(base_vs, List(IndexingSuffix(Left(idx_vs))(aie_range)))(aie_range)
        isLeft = false
        resultHolder = rh
        v.accept(this, arg)
        val vs = resultHolder
        val vs_type = JawaType(base_typ.baseType, base_typ.dimensions - 1)
        val annotations: MList[JawaAnnotation] = mlistEmpty
        if (vs_type.isObject) {
          val kindKey = Token(Tokens.ID, aie_range, "kind")
          val kindValue = TokenValue(Token(Tokens.ID, aie_range, "object"))(aie_range)
          annotations += JawaAnnotation(kindKey, Some(kindValue))(aie_range)
        }
        val value_assign = AssignmentStatement(idx_exp, VariableNameExpression(vs)(aie_range), annotations.toList)(aie_range)
        createLocation(getKeyWordRange(aie), value_assign)
      }

    }
    resultHolder = base_vs
  }

  /**
    * java:
    *   arr[0][1];
    *
    * jawa:
    *   temp1:= 0;
    *   temp_arr1:= arr[temp1];
    *   temp2:= 1;
    *   temp:= temp_arr1[temp2];
    */
  override def visit(aae: ArrayAccessExpr, arg: Void): Unit = {
    val left = isLeft
    val aae_range = aae.toRange
    isLeft = false
    aae.getName.accept(this, arg)
    val name_vs = resultHolder
    isLeft = false
    aae.getIndex.accept(this, arg)
    val idx_vs = resultHolder
    val name_type = localVariables.getOrElse(name_vs.varName, throw Java2JawaException(aae_range, "Array Type for ArrayInitializerExpr should always set."))
    val temp_type = JawaType(name_type.baseType, name_type.dimensions - 1)
    val temp_name = checkAndAddVariable(temp_type, aae_range, generateTempVarName(temp_type), aae_range)
    val temp_vs = VarSymbol(Token(Tokens.ID, aae_range, temp_name.apostrophe))(aae_range)
    val idx_exp = IndexingExpression(name_vs, List(IndexingSuffix(Left(idx_vs))(aae_range)))(aae_range)
    if(left) {
      LHS = idx_exp
    } else {
      val annotations: MList[JawaAnnotation] = mlistEmpty
      if (temp_type.isObject) {
        val kindKey = Token(Tokens.ID, aae_range, "kind")
        val kindValue = TokenValue(Token(Tokens.ID, aae_range, "object"))(aae_range)
        annotations += JawaAnnotation(kindKey, Some(kindValue))(aae_range)
      }
      val assign_stmt = AssignmentStatement(VariableNameExpression(temp_vs)(aae_range), idx_exp, annotations.toList)(aae_range)
      createLocation(getKeyWordRange(aae), assign_stmt)
      resultHolder = temp_vs
    }
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
      val tempName = checkAndAddVariable(temp1Type, ae.toRange, generateTempVarName(temp1Type), ae.toRange)
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
        val expectedName = if(typ.isObject) "object_temp" else s"${typ.simpleName}_temp"
        val temp3Name = checkAndAddVariable(typ, be.toRange, expectedName, be.toRange)
        val temp3Var = VarSymbol(Token(Tokens.ID, be.toRange, temp3Name.apostrophe))(be.toRange)
        val assignStmt = AssignmentStatement(VariableNameExpression(temp3Var)(be.toRange), binExp, ilistEmpty)(be.toRange)
        createLocation(getKeyWordRange(be), assignStmt)
        resultHolder = temp3Var
    }
  }

  /**
    * java:
    *   Data a = (Data) o;
    *
    * jawa:
    *   temp:= o;
    *   temp2:= (Data) temp;
    *   a:= temp2;
    */
  override def visit(ce: CastExpr, arg: Void): Unit = {
    val ce_range = ce.toRange
    isLeft = false
    ce.getExpression.accept(this, arg)
    val temp = resultHolder
    val cast_type = handleType(ce.getType)
    val cexp = CastExpression(cast_type, temp)(ce_range)
    val temp2Name = checkAndAddVariable(cast_type.typ, ce_range, generateTempVarName(cast_type.typ), ce_range)
    val temp2Var = VarSymbol(Token(Tokens.ID, ce_range, temp2Name.apostrophe))(ce_range)
    val temp2annotations: MList[JawaAnnotation] = mlistEmpty
    if (cast_type.typ.isObject) {
      val kindKey = Token(Tokens.ID, ce_range, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, ce_range, "object"))(ce_range)
      temp2annotations += JawaAnnotation(kindKey, Some(kindValue))(ce_range)
    }
    val cast_assign = AssignmentStatement(VariableNameExpression(temp2Var)(ce_range), cexp, temp2annotations.toList)(ce_range)
    createLocation(getKeyWordRange(ce), cast_assign)
    resultHolder = temp2Var
  }

  /**
    * java:
    *   Object.class;
    *
    * jawa:
    *   temp:= constclass @type `Object` @kind object;
    */
  override def visit(ce: ClassExpr, arg: Void): Unit = {
    val ce_range = ce.toRange
    val tempName = checkAndAddVariable(JavaKnowledge.CLASS, ce_range, generateTempVarName(JavaKnowledge.CLASS), ce_range)
    val tempVar = VarSymbol(Token(Tokens.ID, ce_range, tempName.apostrophe))(ce_range)
    val cc = ConstClassExpression(TypeExpression(handleType(ce.getType))(ce_range))(ce_range)
    val kindKey = Token(Tokens.ID, ce_range, "kind")
    val kindValue = TokenValue(Token(Tokens.ID, ce_range, "object"))(ce_range)
    val ce_assign = AssignmentStatement(VariableNameExpression(tempVar)(ce_range), cc, List(JawaAnnotation(kindKey, Some(kindValue))(ce_range)))(ce_range)
    createLocation(getKeyWordRange(ce), ce_assign)
    resultHolder = tempVar
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
    *   d instanceof Data;
    *
    * jawa:
    *   temp:= d;
    *   temp2:= instanceof @variable temp @type `Data`;
    */
  override def visit(ie: InstanceOfExpr, arg: Void): Unit = {
    val ie_range = ie.toRange
    isLeft = false
    ie.getExpression.accept(this, arg)
    val temp = resultHolder
    val temp2Name = checkAndAddVariable(JavaKnowledge.BOOLEAN, ie_range, generateTempVarName(JavaKnowledge.BOOLEAN), ie_range)
    val temp2Var = VarSymbol(Token(Tokens.ID, ie_range, temp2Name.apostrophe))(ie_range)
    val type_ast = handleType(ie.getType)
    val ioe = InstanceOfExpression(temp, TypeExpression(type_ast)(ie_range))(ie_range)
    val ie_assign = AssignmentStatement(VariableNameExpression(temp2Var)(ie_range), ioe, ilistEmpty)(ie_range)
    createLocation(getKeyWordRange(ie), ie_assign)
    resultHolder = temp2Var
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
        val vs = VarSymbol(Token(Tokens.ID, ne.toRange, ne.getNameAsString.apostrophe))(ne.toRange) // TODO: fix the name
        if(isLeft) {
          val name = VariableNameExpression(vs)(vs.pos)
          LHS = name
        } else {
          resultHolder = vs
        }
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
    val baseTypeSymbol = TypeSymbol(Token(Tokens.ID, oce.getType.toRange, typ.jawaName.apostrophe))(oce.getType.toRange)
    val temp = checkAndAddVariable(typ, oce.toRange, generateTempVarName(typ), oce.toRange)
    val temp_var = VarSymbol(Token(Tokens.ID, baseTypeSymbol.pos, temp.apostrophe))(baseTypeSymbol.pos)
    val temp_vne = VariableNameExpression(temp_var)(baseTypeSymbol.pos)
    val newExp = NewExpression(JawaTypeAst(baseTypeSymbol, ilistEmpty)(baseTypeSymbol.pos))(temp_vne.pos)
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
    // TODO: add anonymous class handle logic
  }

  override def visit(thisExp: ThisExpr, arg: Void): Unit = {
    resultHolder = thisVar
  }

  /**
    * java:
    *   i++;
    *
    * jawa:
    *   temp:= i;
    *   i:= temp + 1;
    *
    * java:
    *   ++i;
    *
    * jawa:
    *   temp:= i;
    *   temp:= temp + 1;
    *   i:= temp;
    *
    * java:
    *   -i;
    *
    * jawa:
    *   temp:= i;
    *   temp:= -temp;
    *
    * java:
    *   ~i;
    *
    * jawa:
    *   temp:= i;
    *   temp:= ~temp;
    *
    * java:
    *   !b;
    *
    * jawa:
    *   temp:= b;
    *   if temp != 0 then goto Label1;
    *   temp:= 1;
    *   goto Label2;
    *   Label1:
    *   temp:= 0;
    *   Label2:
    */
  override def visit(ue: UnaryExpr, arg: Void): Unit = {
    val ue_range = ue.toRange
    isLeft = false
    ue.getExpression.accept(this, arg)
    val vs = resultHolder
    val vs_type = localVariables.getOrElse(vs.varName, throw Java2JawaException(ue_range, s"Type should already been set for variable: $vs"))
    val temp_name = checkAndAddVariable(vs_type, ue_range, generateTempVarName(vs_type), ue_range)
    val temp = VarSymbol(Token(Tokens.ID, ue_range, temp_name.apostrophe))(ue_range)
    val temp_assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), VariableNameExpression(vs)(ue_range), ilistEmpty)(ue_range)
    createLocation(getKeyWordRange(ue), temp_assign)
    ue.getOperator match {
      case UnaryExpr.Operator.POSTFIX_DECREMENT =>
        isLeft = true
        ue.getExpression.accept(this, arg)
        val lhs = LHS
        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "-"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
        val be_assign = AssignmentStatement(lhs, be, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), be_assign)
      case UnaryExpr.Operator.POSTFIX_INCREMENT =>
        isLeft = true
        ue.getExpression.accept(this, arg)
        val lhs = LHS
        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "+"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
        val be_assign = AssignmentStatement(lhs, be, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), be_assign)
      case UnaryExpr.Operator.PREFIX_DECREMENT =>
        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "-"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
        val temp_vne = VariableNameExpression(temp)(ue_range)
        val be_assign = AssignmentStatement(temp_vne, be, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), be_assign)
        isLeft = true
        ue.getExpression.accept(this, arg)
        val lhs = LHS
        val assign = AssignmentStatement(lhs, temp_vne, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), assign)
      case UnaryExpr.Operator.PREFIX_INCREMENT =>
        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "+"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
        val temp_vne = VariableNameExpression(temp)(ue_range)
        val be_assign = AssignmentStatement(temp_vne, be, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), be_assign)
        isLeft = true
        ue.getExpression.accept(this, arg)
        val lhs = LHS
        val assign = AssignmentStatement(lhs, temp_vne, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), assign)
      case UnaryExpr.Operator.BITWISE_COMPLEMENT =>
        val uexpr = UnaryExpression(Token(Tokens.OP, ue_range, "~"), temp)(ue_range)
        val assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), uexpr, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), assign)
      case UnaryExpr.Operator.LOGICAL_COMPLEMENT =>
        val biExpr = BinaryExpression(temp, Token(Tokens.OP, ue_range, "!="), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "0"))(ue_range))))(ue_range)
        val label = s"Label$labelCount"
        val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, ue_range, label))(ue_range))(ue_range)
        createLocation(getKeyWordRange(ue), ifStmt)
        val true_assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range), ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), true_assign)
        val label2 = s"Label${labelCount + 1}"
        val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, ue_range, label2))(ue_range))(ue_range)
        createLocation(getKeyWordRange(ue), goto)
        createLabel(getKeyWordRange(ue))
        val false_assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "0"))(ue_range), ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), false_assign)
        createLabel(getKeyWordRange(ue))
      case UnaryExpr.Operator.MINUS =>
        val uexpr = UnaryExpression(Token(Tokens.OP, ue_range, "-"), temp)(ue_range)
        val assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), uexpr, ilistEmpty)(ue_range)
        createLocation(getKeyWordRange(ue), assign)
      case UnaryExpr.Operator.PLUS =>
      case _ =>
        throw Java2JawaException(ue_range, s"Unhandled operator for unary expr: $ue")
    }
    resultHolder = temp
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
