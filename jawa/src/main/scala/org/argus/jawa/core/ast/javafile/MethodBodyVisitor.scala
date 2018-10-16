/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

///*
// * Copyright (c) 2017. Fengguo Wei and others.
// * All rights reserved. This program and the accompanying materials
// * are made available under the terms of the Eclipse Public License v1.0
// * which accompanies this distribution, and is available at
// * http://www.eclipse.org/legal/epl-v10.html
// *
// * Detailed contributors are listed in the CONTRIBUTOR.md
// */
//
//package org.argus.jawa.core.ast.javafile
//
//import com.github.javaparser.JavaParser
//import com.github.javaparser.ast.{Modifier, NodeList}
//import com.github.javaparser.ast.`type`.{IntersectionType, Type, UnionType}
//import com.github.javaparser.ast.body.{ClassOrInterfaceDeclaration, Parameter, VariableDeclarator}
//import com.github.javaparser.ast.expr._
//import com.github.javaparser.ast.stmt._
//import com.github.javaparser.ast.visitor.VoidVisitorAdapter
//import org.argus.jawa.core.ast.{AccessExpression, AssignmentStatement, BinaryExpression, CallRhs, CallStatement, CastExpression, CatchRange, ConstClassExpression, EmptyStatement, ExceptionExpression, FieldNameSymbol, GotoStatement, IfStatement, IndexingExpression, IndexingSuffix, InstanceOfExpression, LHS, LengthExpression, LiteralExpression, LocalVarDeclaration, Location, LocationDefSymbol, LocationSymbol, MethodNameSymbol, MonitorStatement, NewArrayExpression, NewExpression, NullExpression, RHS, ReturnStatement, StaticFieldAccessExpression, SwitchCase, SwitchDefaultCase, SwitchStatement, ThrowStatement, TokenValue, TupleExpression, TypeExpression, TypeSymbol, UnaryExpression, VarDefSymbol, VarSymbol, VariableNameExpression, Annotation => JawaAnnotation, CatchClause => JawaCatchClause, Expression => JawaExpression, Statement => JawaStatement, Type => JawaTypeAst}
//import org.argus.jawa.core.compiler.lexer.{Keywords, Token, Tokens}
//import org.argus.jawa.core.io.{NoPosition, RangePosition, Position => JawaPosition}
//import org.argus.jawa.core.util._
//import org.argus.jawa.core.{ExceptionCenter, JavaKnowledge, JawaMethod, JawaPackage, JawaType, Signature}
//
//import scala.util.{Failure, Success, Try}
//
//class MethodBodyVisitor(cr: ClassResolver, ownerSig: Signature, ownerPos: RangePosition) extends VoidVisitorAdapter[Void] {
//
//  import cr._
//  import cr.j2j._
//
//  imports.resolveStaticImports()
//
//  private def isStatic = isStaticMethod(ownerSig)
//
//  //******************************************************************************
//  //                         Type management
//  //******************************************************************************
//  val localClasses: MMap[String, JawaType] = mmapEmpty
//
//  private def handleType(javaType: Type): JawaTypeAst = {
//    val typ = localClasses.get(javaType.asString()) match {
//      case Some(t) =>
//        t
//      case None =>
//        imports.findType(javaType)
//    }
//    handleJawaType(typ, javaType.toRange)
//  }
//
//  private def handleTypes(javaType: Type): IList[JawaTypeAst] = {
//    val types: MList[JawaType] = mlistEmpty
//    javaType match {
//      case ut: UnionType =>
//        ut.getElements.forEach { elem =>
//          types += handleType(elem).typ
//        }
//      case it: IntersectionType =>
//        it.getElements.forEach { elem =>
//          types += handleType(elem).typ
//        }
//      case t =>
//        types += handleType(t).typ
//    }
//    types.map { t =>
//      handleJawaType(t, javaType.getElementType.toRange)
//    }.toList
//  }
//
//  //************************ Type management End ***********************
//
//
//  //******************************************************************************
//  //                         Local Variable management
//  //******************************************************************************
//
//  val thisVar: VarSymbol = VarSymbol(Token(Tokens.ID, ownerPos, "this".apostrophe))(ownerPos)
//
//  val localVariables: MMap[String, JawaType] = mmapEmpty ++ getParams(ownerSig)
//  localVariables("this") = ownerSig.getClassType
//  val localVarDeclarations: MList[LocalVarDeclaration] = mlistEmpty
//
//  private def generateTempVarName(varType: JawaType): String = {
//    s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
//  }
//
//  /**
//    * expectedName could be already exist, if type did not match we will create a new name by adding numbers
//    */
//  private def checkAndAddVariable(varType: JawaType, typPos: JawaPosition, expectedName: String, namePos: JawaPosition, isTemp: Boolean): String = {
//    var needAdd: Boolean = false
//    var varName = expectedName
//    if(localVariables.contains(varName)) {
//      var i = 1
//      if(isTemp) {
//        while (localVariables.contains(varName)) {
//          varName = expectedName + i
//          i += 1
//          needAdd = true
//        }
//        localVariables(varName) = varType
//      } else {
//        varName = varDeclNameMap.getOrElseUpdate(expectedName, expectedName)
//        while (localVariables.getOrElseUpdate(varName, varType) != varType) {
//          varName = varName + i
//          i += 1
//          needAdd = true
//        }
//        varDeclNameMap(expectedName) = varName
//      }
//    } else {
//      needAdd = true
//    }
//    if(needAdd) {
//      val vType = handleJawaType(varType, typPos)
//      val vdf = VarDefSymbol(Token(Tokens.ID, namePos, varName.apostrophe))(namePos)
//      val lvd = LocalVarDeclaration(Some(vType), vdf)(namePos)
//      localVariables(varName) = vType.typ
//      localVarDeclarations += lvd
//    }
//    varName
//  }
//
//  private def getVariableType(varName: String, pos: JawaPosition, isTemp: Boolean): JawaType = {
//    val name = if(isTemp) {
//      varName
//    } else {
//      varDeclNameMap.getOrElse(varName, varName)
//    }
//    localVariables.getOrElse(name, throw Java2JawaException(pos, s"Type should already been set for variable: $name"))
//  }
//
//  //************************ Local Variable management End ***********************
//
//  //******************************************************************************
//  //                         Scope management
//  //******************************************************************************
//
//  var scopes: IList[MMap[String, String]] = ilistEmpty
//  var varDeclNameMap: MMap[String, String] = mmapEmpty ++ getParams(ownerSig).map { case (name, _) => name -> name}
//
//  def scopeStart(): Unit = {
//    scopes = varDeclNameMap :: scopes
//    varDeclNameMap = mmapEmpty ++ varDeclNameMap
//  }
//
//  def scopeEnd(): Unit = {
//    varDeclNameMap.clear()
//    varDeclNameMap = scopes.head
//    scopes = scopes.tail
//  }
//
//  //************************* Scope management End *******************************
//
//  //******************************************************************************
//  //                         Location and label management
//  //******************************************************************************
//
//  var lineCount: Int = 0
//
//  trait LocPresentation {
//    def index: Int
//    def pos: JawaPosition
//  }
//  case class Loc(num: Int, index: Int, pos: JawaPosition) extends LocPresentation
//  case class Label(label: String, index: Int, pos: JawaPosition) extends LocPresentation
//  private val statements: MList[(LocPresentation, JawaStatement)] = mlistEmpty
//  val catchClauses: MList[JawaCatchClause] = mlistEmpty
//
//  def locations: IList[Location] = {
//    checkVoidReturn()
//    val digits: Int = if (lineCount == 0) 1 else 1 + Math.floor(Math.log10(Math.abs(lineCount))).toInt
//    val format = "#L%%0%dd.".format(digits)
//    statements.map { case (presentation, statement) =>
//      val locStr = presentation match {
//        case Loc(num, _, _) =>
//          format.format(num)
//        case Label(l, _, _) =>
//          s"#$l."
//      }
//      val lds = LocationDefSymbol(Token(Tokens.LOCATION_ID, presentation.pos, locStr))(presentation.pos)
//      lds.locationIndex = presentation.index
//      Location(lds, statement)(presentation.pos)
//    }.toList
//  }
//
//  object LabelType extends Enumeration {
//    val NORMAL, DO, WHILE, FOR, SWITCH, IF, ELSE, IF_END, TRY, CATCH_BLOCK, FINALLY, CATCH = Value
//  }
//
//  var labelCount: Int = 0
//  val labelMap: MMap[LabelType.Value, Int] = mmapEmpty
//
//  private def updateLabel(t: LabelType.Value): Unit = {
//    labelMap(t) = labelMap.getOrElse(t, 0) + 1
//  }
//
//  private def getLabel(t: LabelType.Value, start: Boolean): String = {
//    val num = labelMap.getOrElseUpdate(t, 0)
//    val label = t match {
//      case LabelType.NORMAL => "Label"
//      case LabelType.IF => "If"
//      case LabelType.ELSE => "Else"
//      case LabelType.IF_END => "If_end"
//      case LabelType.DO =>
//        if(start) {
//          "Do_start_"
//        } else {
//          "Do_end_"
//        }
//      case LabelType.WHILE =>
//        if(start) {
//          "While_start_"
//        } else {
//          "While_end_"
//        }
//      case LabelType.FOR =>
//        if(start) {
//          "For_start_"
//        } else {
//          "For_end_"
//        }
//      case LabelType.SWITCH =>
//        if(start) {
//          "Switch_start_"
//        } else {
//          "Switch_end_"
//        }
//      case LabelType.TRY =>
//        if(start) {
//          "Try_start_"
//        } else {
//          "Try_end_"
//        }
//      case LabelType.CATCH_BLOCK =>
//        if(start) {
//          "Catchblock_start_"
//        } else {
//          "Catchblock_end_"
//        }
//      case LabelType.CATCH =>
//        if(start) {
//          "Catch_start_"
//        } else {
//          "Catch_end_"
//        }
//      case LabelType.FINALLY =>
//        if(start) {
//          "Finally_start_"
//        } else {
//          "Finally_end_"
//        }
//    }
//    s"$label$num"
//  }
//
//  private def getNormalLabel: String = {
//    val num = labelMap.getOrElseUpdate(LabelType.NORMAL, 0)
//    updateLabel(LabelType.NORMAL)
//    s"Label$num"
//  }
//
//  private def createLocation(pos: JawaPosition, statement: JawaStatement): Unit = {
//    statements += ((Loc(lineCount, lineCount + labelCount, pos), statement))
//    lineCount += 1
//  }
//
//  private def getLabel(label: String): String = {
//    if(Keywords.isKeyWord(label)) {
//      s"${label}_label"
//    } else {
//      label
//    }
//  }
//
//  private def createLabel(pos: JawaPosition, label: String): Unit = {
//    val l = getLabel(label)
//    statements += ((Label(l, lineCount + labelCount, pos), EmptyStatement(mlistEmpty)(pos)))
//    labelCount += 1
//  }
//
//  private def checkVoidReturn(): Unit = {
//    if(ownerSig.getReturnType == JavaKnowledge.VOID) {
//      var needVoidReturn = false
//      statements.lastOption match {
//        case Some((_, s)) =>
//          if(!s.isInstanceOf[ReturnStatement] && !s.isInstanceOf[ThrowStatement]) {
//            needVoidReturn = true
//          }
//        case None =>
//          needVoidReturn = true
//      }
//      if(needVoidReturn) {
//        val kindKey = Token(Tokens.ID, ownerPos, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, ownerPos, "void"))(ownerPos)
//        val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(ownerPos)
//        val rs = ReturnStatement(None, List(annotation))(ownerPos)
//        createLocation(ownerPos, rs)
//      }
//    }
//  }
//
//  //********************** Location and label management End *********************
//
//  //***********************************************************************************************
//  //                                          Visit Statements
//  //***********************************************************************************************
//
//  private def createIfStatement(vs: VarSymbol, op: Token, locationSymbol: LocationSymbol, range: JawaPosition): IfStatement = {
//    val typ = getVariableType(vs.varName, vs.pos, isTemp = true)
//    val right: Either[VarSymbol, Either[LiteralExpression, NullExpression]] = if(typ.isObject) {
//      Right(Right(NullExpression(Token(Tokens.NULL, vs.pos, "null"))(vs.pos)))
//    } else {
//      Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, vs.pos, "0"))(vs.pos)))
//    }
//    val biExpr = BinaryExpression(vs, op, right)(range)
//    IfStatement(biExpr, locationSymbol)(range)
//  }
//
//  /**
//    * java:
//    *   assert check : message;
//    *
//    * jawa:
//    *   result := check;
//    *   if result != 0 then goto Label;
//    *   msg := message;
//    *   assertionError:= new java.lang.AssertionError(msg);
//    *   throw assertionError;
//    *   Label:
//    */
//  override def visit(as: AssertStmt, arg: Void): Unit = {
//    isLeft = false
//    val as_range = as.toRange
//    as.getCheck.accept(this, arg)
//    val vs = resultHolder
//    val label = getNormalLabel
//    val ifStmt = createIfStatement(vs, Token(Tokens.OP, as_range, "!="), LocationSymbol(Token(Tokens.ID, as_range, label))(as_range), as_range)
//    createLocation(as_range, ifStmt)
//    as.getMessage.ifPresent { m =>
//      isLeft = false
//      m.accept(this, arg)
//    }
//    // create AssertionError
//    val assertType = new JawaType("java.lang.AssertionError")
//    val assertVarName = checkAndAddVariable(assertType, as_range, "assertion_error", as_range, isTemp = true)
//    val assertVarSymbol = VarSymbol(Token(Tokens.ID, as_range, assertVarName.apostrophe))(as_range)
//    val assertNameExp = VariableNameExpression(assertVarSymbol)(as_range)
//    val assertTypeSymbol = TypeSymbol(Token(Tokens.ID, as_range, assertType.jawaName.apostrophe))(as_range)
//    val assertNewExp = NewExpression(JawaTypeAst(assertTypeSymbol, ilistEmpty)(as_range))(as_range)
//    val assertAssign = AssignmentStatement(assertNameExp, assertNewExp, ilistEmpty)(as_range)
//    createLocation(as_range, assertAssign)
//
//    // create AssertionError init
//    val assertInitVarSymbols: MList[VarSymbol] = mlistEmpty
//    as.getMessage.ifPresent { msg =>
//      isLeft = false
//      msg.accept(this, arg)
//      assertInitVarSymbols += resultHolder
//    }
//    val assertInitCall = generateCall(None, assertType, "<init>", as_range, Some(assertVarSymbol), assertInitVarSymbols.toList, "direct")
//    createLocation(as_range, assertInitCall)
//
//    // create throw statement
//    val assertThrow = ThrowStatement(assertVarSymbol)(as_range)
//    createLocation(as_range, assertThrow)
//
//    createLabel(as_range, label)
//  }
//
//  override def visit(bs: BlockStmt, arg: Void): Unit = {
//    scopeStart()
//    bs.getStatements.forEach{ stmt =>
//      isLeft = true
//      stmt.accept(this, arg)
//    }
//    scopeEnd()
//  }
//
//  //******************************************************************************
//  //                         Loop, switch, break, continue
//  //******************************************************************************
//
//  private var startLabels: IList[String] = ilistEmpty
//  private var endLabels: IList[String] = ilistEmpty
//  private def startLabel: String = startLabels.headOption.getOrElse(throw Java2JawaException(NoPosition, "Access label before init."))
//  private def endLabel: String = endLabels.headOption.getOrElse(throw Java2JawaException(NoPosition, "Access label before init."))
//  private def pushLabel(t: LabelType.Value): Unit = {
//    val be = getLabel(t, start = true)
//    val af = getLabel(t, start = false)
//    startLabels = be :: startLabels
//    endLabels = af :: endLabels
//    updateLabel(t)
//  }
//  private def popLabel(): Unit = {
//    startLabels = startLabels.tail
//    endLabels = endLabels.tail
//  }
//
//  private def getIfLabels: (String, String, String) = {
//    val if_label = getLabel(LabelType.IF, start = true)
//    val else_label = getLabel(LabelType.ELSE, start = true)
//    val if_end_label = getLabel(LabelType.IF_END, start = true)
//    updateLabel(LabelType.IF)
//    updateLabel(LabelType.ELSE)
//    updateLabel(LabelType.IF_END)
//    (if_label, else_label, if_end_label)
//  }
//
//  private def getTryLabels: (String, String, String, String, String, String) = {
//    val try_start_label = getLabel(LabelType.TRY, start = true)
//    val try_end_label = getLabel(LabelType.TRY, start = false)
//    val catchblock_start_label = getLabel(LabelType.CATCH_BLOCK, start = true)
//    val catchblock_end_label = getLabel(LabelType.CATCH_BLOCK, start = false)
//    val finally_start_label = getLabel(LabelType.FINALLY, start = true)
//    val finally_end_label = getLabel(LabelType.FINALLY, start = false)
//    updateLabel(LabelType.TRY)
//    updateLabel(LabelType.CATCH_BLOCK)
//    updateLabel(LabelType.FINALLY)
//    (try_start_label, try_end_label, catchblock_start_label, catchblock_end_label, finally_start_label, finally_end_label)
//  }
//
//  /**
//    * java:
//    *   break abc;
//    *
//    * jawa:
//    *   goto abc;
//    */
//  override def visit(bs: BreakStmt, arg: Void): Unit = {
//    val bs_range = bs.toRange
//    var l = endLabel
//    bs.getLabel.ifPresent(label => l = getLabel(s"${label.getIdentifier}_end"))
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, bs_range, l))(bs_range))(bs_range)
//    createLocation(bs_range, goto)
//  }
//
//  /**
//    * java:
//    *   continue abc;
//    *
//    * jawa:
//    *   goto abc;
//    */
//  override def visit(cs: ContinueStmt, arg: Void): Unit = {
//    val cs_range = cs.toRange
//    var l = startLabel
//    cs.getLabel.ifPresent(label => l = getLabel(s"${label.getIdentifier}_start"))
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, cs_range, l))(cs_range))(cs_range)
//    createLocation(cs_range, goto)
//  }
//
//  /**
//    * java:
//    *   do {
//    *     body;
//    *   } while (cond);
//    *
//    * jawa:
//    *   Do_start:
//    *   body;
//    *   temp:= cond;
//    *   if temp != 0 then goto Do_start;
//    *   Do_end:
//    */
//  override def visit(ds: DoStmt, arg: Void): Unit = {
//    val ds_range = ds.toRange
//    pushLabel(LabelType.DO)
//
//    // start label
//    createLabel(ds_range, startLabel)
//
//    // body
//    ds.getBody.accept(this, arg)
//
//    // condition
//    isLeft = false
//    ds.getCondition.accept(this, arg)
//    val cond_res = resultHolder
//
//    val cond_range = ds.getCondition.toRange
//    val if_stmt = createIfStatement(cond_res, Token(Tokens.OP, cond_range, "!="), LocationSymbol(Token(Tokens.ID, ds_range, startLabel))(ds_range), ds_range)
//    createLocation(cond_range, if_stmt)
//
//    // end label
//    createLabel(ds_range, endLabel)
//
//    popLabel()
//  }
//
//  /**
//    * java:
//    *   for(init; cond; update) {
//    *     body
//    *   }
//    *
//    * jawa:
//    *   temp:= init;
//    *   For_start:
//    *   temp2:= cond;
//    *   if temp2 == 0 then goto For_end;
//    *   body;
//    *   update;
//    *   goto For_start;
//    *   For_end:
//    *
//    * java:
//    *   for(;;) {}
//    *
//    * jawa:
//    *   For_start:
//    *   goto For_start;
//    *   For_end:
//    */
//  override def visit(fs: ForStmt, arg: Void): Unit = {
//    val fs_range = fs.toRange
//    pushLabel(LabelType.FOR)
//
//    // init
//    fs.getInitialization.forEach{ init =>
//      isLeft = false
//      init.accept(this, arg)
//    }
//
//    // start label
//    createLabel(fs_range, startLabel)
//
//    // cond (if exists)
//    fs.getCompare.ifPresent{ c =>
//      isLeft = false
//      c.accept(this, arg)
//      val cond_res = resultHolder
//      val cond_range = c.toRange
//      val if_stmt = createIfStatement(cond_res, Token(Tokens.OP, cond_range, "=="), LocationSymbol(Token(Tokens.ID, fs_range, endLabel))(fs_range), fs_range)
//      createLocation(cond_range, if_stmt)
//    }
//
//    // body
//    fs.getBody.accept(this, arg)
//
//    // update
//    fs.getUpdate.forEach{ u =>
//      isLeft = false
//      u.accept(this, arg)
//    }
//
//    // goto
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, fs_range, startLabel))(fs_range))(fs_range)
//    createLocation(fs_range, goto)
//
//    // end label
//    createLabel(fs_range, endLabel)
//    popLabel()
//  }
//
//  /**
//    * java:
//    *   for(Object o: objects) {
//    *     body
//    *   }
//    *
//    * jawa:
//    *   temp:= objects;
//    *   len:= length @variable temp;
//    *   int_temp:= 0;
//    *   For_start:
//    *   if int_temp > len then goto For_end;
//    *   o:= temp[int];
//    *   body;
//    *   int_temp:= int_temp + 1;
//    *   goto For_start;
//    *   For_end:
//    */
//  override def visit(fs: ForeachStmt, arg: Void): Unit = {
//    val fs_range = fs.toRange
//    pushLabel(LabelType.FOR)
//
//    // iterable
//    isLeft = false
//    fs.getIterable.accept(this, arg)
//    val temp = resultHolder
//
//    // length
//    val len = checkAndAddVariable(JavaKnowledge.INT, temp.pos, generateTempVarName(JavaKnowledge.INT), temp.pos, isTemp = true)
//    val len_vs = VarSymbol(Token(Tokens.ID, temp.pos, len.apostrophe))(temp.pos)
//    val length = LengthExpression(temp)(temp.pos)
//    val len_assign = AssignmentStatement(VariableNameExpression(len_vs)(len_vs.pos), length, ilistEmpty)(temp.pos)
//    createLocation(temp.pos, len_assign)
//
//    // int_temp
//    val int_temp = checkAndAddVariable(JavaKnowledge.INT, temp.pos, generateTempVarName(JavaKnowledge.INT), temp.pos, isTemp = true)
//    val int_temp_vs = createIntAssignment(int_temp, 0, fs.getIterable.toRange)
//
//    // start label
//    createLabel(fs_range, startLabel)
//
//    // if
//    val be = BinaryExpression(int_temp_vs, Token(Tokens.OP, int_temp_vs.pos, ">="), Left(len_vs))(int_temp_vs.pos)
//    val is = IfStatement(be, LocationSymbol(Token(Tokens.ID, int_temp_vs.pos, endLabel))(int_temp_vs.pos))(int_temp_vs.pos)
//    createLocation(int_temp_vs.pos, is)
//
//    // set var
//    isLeft = true
//    fs.getVariable.accept(this, arg)
//    val lhs = LHS
//    val idx_exp = IndexingExpression(temp, List(IndexingSuffix(Left(int_temp_vs))(lhs.pos)))(lhs.pos)
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    val array_typ = getVariableType(temp.varName, temp.pos, isTemp = true)
//    val idx_typ = JawaType(array_typ.baseType, array_typ.dimensions - 1)
//    if (idx_typ.isObject) {
//      val kindKey = Token(Tokens.ID, temp.pos, "kind")
//      val kindValue = TokenValue(Token(Tokens.ID, temp.pos, "object"))(temp.pos)
//      annotations += JawaAnnotation(kindKey, Some(kindValue))(temp.pos)
//    }
//    val assign = AssignmentStatement(lhs, idx_exp, annotations.toList)(lhs.pos)
//    createLocation(lhs.pos, assign)
//
//    // body
//    fs.getBody.accept(this, arg)
//
//    // int_temp++
//    val inc_be = BinaryExpression(int_temp_vs, Token(Tokens.OP, int_temp_vs.pos, "+"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, int_temp_vs.pos, "1"))(int_temp_vs.pos))))(int_temp_vs.pos)
//    val inc_assig = AssignmentStatement(VariableNameExpression(int_temp_vs)(int_temp_vs.pos), inc_be, ilistEmpty)(int_temp_vs.pos)
//    createLocation(int_temp_vs.pos, inc_assig)
//
//    // goto
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, fs_range, startLabel))(fs_range))(fs_range)
//    createLocation(fs_range, goto)
//
//    // end label
//    createLabel(fs_range, endLabel)
//    popLabel()
//  }
//
//  /**
//    * java:
//    *   label: stmt;
//    *
//    * jawa:
//    *   label_start:
//    *   stmt;
//    *   label_end:
//    */
//  override def visit(ls: LabeledStmt, arg: Void): Unit = {
//    val label_start = getLabel(s"${ls.getLabel.getIdentifier}_start")
//    val label_end = getLabel(s"${ls.getLabel.getIdentifier}_end")
//
//    createLabel(ls.getLabel.toRange, label_start)
//    ls.getStatement.accept(this, arg)
//    createLabel(ls.getLabel.toRange, label_end)
//  }
//
//  /**
//    * java:
//    *   switch(x) {
//    *     case 1:
//    *     case 2:
//    *       stmts1;
//    *     default:
//    *       stmts2;
//    *   }
//    *
//    * jawa:
//    *   temp:= x;
//    *   switch temp
//    *            | 1 => goto Label1
//    *            | 2 => goto Label2
//    *            | else => goto Label3;
//    *   Label1:
//    *   Label2:
//    *     stmts1;
//    *   Label3:
//    *     stmts2;
//    *   Switch_end:
//    *
//    * java:
//    *   switch(x) {
//    *     case "1":
//    *     case "2":
//    *       stmts1;
//    *     default:
//    *       stmts2;
//    *   }
//    *
//    * jawa:
//    *   temp:= x;
//    *   int_temp:= -1;
//    *   call hc_temp:= `hashCode`(temp)  @signature `Ljava/lang/Object;.hashCode:()I` @kind virtual;
//    *   switch hc_temp
//    *           | 49 => goto Label1
//    *           | 50 => goto Label2
//    *           | else => goto Label3;
//    *   Label1:
//    *   temp1:= "1";
//    *   call bool_temp1:= `equals`(temp, temp1) @ signature `Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z` @kind virtual;
//    *   if bool_temp1 == 0 then goto Label3;
//    *   int_temp:= 0;
//    *   goto Label3;
//    *   Label2:
//    *   temp2:= "2";
//    *   call bool_temp2:= `equals`(temp, temp2) @ signature `Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z` @kind virtual;
//    *   if bool_temp2 == 0 then goto Label3;
//    *   int_temp:= 1;
//    *   Label3:
//    *   switch int_temp
//    *            | 0 => goto Label4
//    *            | 1 => goto Label5
//    *            | else => goto Label6;
//    *   Label4:
//    *   Label5:
//    *     stmts1;
//    *   Label6:
//    *     stmts2;
//    *   Switch_end:
//    */
//  override def visit(ss: SwitchStmt, arg: Void): Unit = {
//    val ss_range = ss.toRange
//    pushLabel(LabelType.SWITCH)
//
//    isLeft = false
//    ss.getSelector.accept(this, arg)
//    var temp = resultHolder
//
//    val cases: MList[SwitchCase] = mlistEmpty
//    var default: Option[SwitchDefaultCase] = None
//    val stmtList: MList[(String, NodeList[Statement])] = mlistEmpty
//
//    val typ = getVariableType(temp.varName, temp.pos, isTemp = true)
//    if(typ == JavaKnowledge.STRING) {
//      // handle string case
//      val int_temp = createIntAssignment("int_temp", -1, ss_range)
//
//      // hashCode call
//      val hc_temp = checkAndAddVariable(JavaKnowledge.INT, ss_range, generateTempVarName(JavaKnowledge.INT), ss_range, isTemp = true)
//      val hc_temp_vs = VarSymbol(Token(Tokens.ID, ss_range, hc_temp.apostrophe))(ss_range)
//      val hc_temp_vne = VariableNameExpression(hc_temp_vs)(hc_temp_vs.pos)
//      val hc_call = generateCall(Some(hc_temp_vne), JavaKnowledge.STRING, "hashCode", hc_temp_vne.pos, Some(temp), ilistEmpty, "virtual")
//      createLocation(hc_temp_vne.pos, hc_call)
//
//      // switch hashCode
//      val hc_cases: MList[SwitchCase] = mlistEmpty
//      var hc_default: Option[SwitchDefaultCase] = None
//      val hcList: MList[(String, JawaPosition, LiteralExpression, NodeList[Statement])] = mlistEmpty
//      var hc_default_label: Option[(String, NodeList[Statement])] = None
//      ss.getEntries.forEach { en =>
//        val en_range = en.toRange
//        var label: Option[LiteralExpression] = None
//        en.getLabel.ifPresent {
//          case l: LiteralExpr =>
//            label = Some(getLiteralExpression(l))
//          case l: Expression =>
//            throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
//        }
//        val target = getNormalLabel
//        val location = LocationSymbol(Token(Tokens.ID, en_range, target))(en_range)
//        label match {
//          case Some(l) =>
//            hcList += ((target, en_range, l, en.getStatements))
//            hc_cases += SwitchCase(Token(Tokens.INTEGER_LITERAL, en_range, l.getString.hashCode.toString), location)(en_range)
//          case None => // default case
//            hc_default_label = Some(target, en.getStatements)
//            hc_default = Some(SwitchDefaultCase(location)(en_range))
//        }
//      }
//
//      val hc_label_end = hc_default_label match {
//        case Some((hdl, _)) => hdl
//        case None => getNormalLabel
//      }
//
//      if(hc_default.isEmpty) {
//        hc_default = Some(SwitchDefaultCase(LocationSymbol(Token(Tokens.ID, ss_range, hc_label_end))(ss_range))(ss_range))
//      }
//      val hc_switch = SwitchStatement(hc_temp_vs, hc_cases.toList, hc_default)(ss_range)
//      createLocation(ss_range, hc_switch)
//
//      // handle each string equals
//      var idx: Int = 0
//      hcList.foreach {
//        case (label, pos, str, stmts) =>
//          createLabel(pos, label)
//          val boolean_temp = checkAndAddVariable(JavaKnowledge.BOOLEAN, pos, generateTempVarName(JavaKnowledge.BOOLEAN), pos, isTemp = true)
//          val boolean_temp_vs = VarSymbol(Token(Tokens.ID, pos, boolean_temp.apostrophe))(pos)
//          val boolean_temp_vne = VariableNameExpression(boolean_temp_vs)(pos)
//          val string_temp = checkAndAddVariable(JavaKnowledge.STRING, pos, generateTempVarName(JavaKnowledge.STRING), pos, isTemp = true)
//          val string_temp_vs = VarSymbol(Token(Tokens.ID, pos, string_temp.apostrophe))(pos)
//          val string_temp_vne = VariableNameExpression(string_temp_vs)(pos)
//          val kindKey = Token(Tokens.ID, pos, "kind")
//          val kindValue = TokenValue(Token(Tokens.ID, pos, "object"))(pos)
//          val annotation = JawaAnnotation(kindKey, Some(kindValue))(pos)
//          val string_assign = AssignmentStatement(string_temp_vne, str, List(annotation))(pos)
//          createLocation(pos, string_assign)
//          val call = generateCall(Some(boolean_temp_vne), JavaKnowledge.STRING, "equals", pos, Some(temp), List(string_temp_vs), "virtual")
//          createLocation(pos, call)
//          val is = createIfStatement(boolean_temp_vs, Token(Tokens.OP, pos, "=="), LocationSymbol(Token(Tokens.ID, pos, hc_label_end))(pos), pos)
//          createLocation(pos, is)
//          val int_assign = AssignmentStatement(VariableNameExpression(int_temp)(pos), LiteralExpression(Token(Tokens.INTEGER_LITERAL, pos, idx.toString))(pos), ilistEmpty)(pos)
//          createLocation(pos, int_assign)
//          val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, pos, hc_label_end))(pos))(pos)
//          createLocation(pos, goto)
//          val target = getNormalLabel
//          stmtList += ((target, stmts))
//          val location = LocationSymbol(Token(Tokens.ID, pos, target))(pos)
//          cases += SwitchCase(Token(Tokens.INTEGER_LITERAL, pos, idx.toString), location)(pos)
//          idx += 1
//      }
//      createLabel(ss_range, hc_label_end)
//
//      hc_default_label match {
//        case Some((_, stmts)) =>
//          val target = getNormalLabel
//          stmtList += ((target, stmts))
//          val location = LocationSymbol(Token(Tokens.ID, ss_range, target))(ss_range)
//          default = Some(SwitchDefaultCase(location)(ss_range))
//        case None =>
//      }
//      temp = int_temp
//    } else {
//      ss.getEntries.forEach{ en =>
//        val en_range = en.toRange
//        var label: Option[Token] = None
//        en.getLabel.ifPresent {
//          case l: LiteralExpr =>
//            label = Some(getLiteralToken(l))
//          case l: Expression =>
//            throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
//        }
//        val target = getNormalLabel
//        stmtList += ((target, en.getStatements))
//        val location = LocationSymbol(Token(Tokens.ID, en_range, target))(en_range)
//        label match {
//          case Some(l) =>
//            cases += SwitchCase(l, location)(en_range)
//          case None => // default case
//            default = Some(SwitchDefaultCase(location)(en_range))
//        }
//      }
//
//    }
//
//    if(default.isEmpty) {
//      default = Some(SwitchDefaultCase(LocationSymbol(Token(Tokens.ID, ss_range, endLabel))(ss_range))(ss_range))
//    }
//    val switch = SwitchStatement(temp, cases.toList, default)(ss_range)
//    createLocation(ss_range, switch)
//    stmtList.foreach {
//      case (label, stmts) =>
//        createLabel(ss_range, label)
//        stmts.forEach(s => s.accept(this, arg))
//    }
//
//    createLabel(ss_range, endLabel)
//    popLabel()
//  }
//
//  /**
//    * java:
//    *   while(cond) {
//    *     stmt;
//    *   }
//    *
//    * jawa:
//    *   While_start:
//    *   temp:= cond;
//    *   if temp == 0 then goto While_end;
//    *   stmt;
//    *   goto While_start;
//    *   While_end:
//    */
//  override def visit(ws: WhileStmt, arg: Void): Unit = {
//    val ws_range = ws.toRange
//    pushLabel(LabelType.WHILE)
//
//    // start label
//    createLabel(ws_range, startLabel)
//
//    // condition
//    isLeft = false
//    ws.getCondition.accept(this, arg)
//    val cond_res = resultHolder
//
//    val cond_range = ws.getCondition.toRange
//    val if_stmt = createIfStatement(cond_res, Token(Tokens.OP, cond_range, "=="), LocationSymbol(Token(Tokens.ID, ws_range, endLabel))(ws_range), ws_range)
//    createLocation(cond_range, if_stmt)
//
//    // body
//    ws.getBody.accept(this, arg)
//
//    // goto
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, ws_range, startLabel))(ws_range))(ws_range)
//    createLocation(ws_range, goto)
//
//    // end label
//    createLabel(ws_range, endLabel)
//
//    popLabel()
//  }
//
//  //************************ Loop, switch, break, continue End *******************
//
//  override def visit(es: EmptyStmt, arg: Void): Unit = {
//    createLocation(es.toRange, EmptyStatement(mlistEmpty)(es.toRange))
//  }
//
//  /**
//    * java:
//    *   super(15);
//    *
//    * jawa:
//    *   arg = 15;
//    *   call `<init>`(arg) @signature `LC;.<init>:(I)V` @kind direct;
//    */
//  override def visit(ecis: ExplicitConstructorInvocationStmt, arg: Void): Unit = {
//    val args: MList[VarSymbol] = mlistEmpty
//    ecis.getArguments.forEach { argument =>
//      isLeft = false
//      argument.accept(this, arg)
//      args += resultHolder
//    }
//    val classType = if(ecis.isThis) {
//      ownerSig.getClassType
//    } else {
//      superType
//    }
//    val call = generateCall(None, classType, "<init>", ecis.toRange, Some(thisVar), args.toList, "direct")
//    createLocation(ecis.toRange, call)
//  }
//
//  override def visit(es: ExpressionStmt, arg: Void): Unit = {
//    isLeft = false
//    es.getExpression.accept(this, arg)
//  }
//
//  /**
//    * java:
//    *   if(cond1) {
//    *     body1;
//    *   } else if(cond2) {
//    *     body2;
//    *   } else {
//    *     body3;
//    *   }
//    *
//    * jawa:
//    *   If1:
//    *   temp1:= cond1;
//    *   if temp1 == 0 then goto Else_start1;
//    *   body1;
//    *
//    *   goto Else_end1;
//    *
//    *   Else1:
//    *
//    *   If2:
//    *   temp2:= cond2;
//    *   if cond2 == 0 then goto Else_start2;
//    *   body2;
//    *
//    *   goto If_end2;
//    *
//    *   Else2:
//    *   body3;
//    *
//    *   If_end2:
//    *
//    *   If_end1:
//    */
//  override def visit(is: IfStmt, arg: Void): Unit = {
//    val is_range = is.toRange
//    val (if_label, else_label, if_end_label) = getIfLabels
//
//    createLabel(is_range, if_label)
//
//    // cond
//    isLeft = false
//    is.getCondition.accept(this, arg)
//    val cond_res = resultHolder
//    val cond_range = is.getCondition.toRange
//
//    val end_label = if(is.getElseStmt.isPresent) {
//      else_label
//    } else {
//      if_end_label
//    }
//    val if_stmt = createIfStatement(cond_res, Token(Tokens.OP, cond_range, "=="), LocationSymbol(Token(Tokens.ID, is_range, end_label))(is_range), is_range)
//    createLocation(cond_range, if_stmt)
//
//    // body
//    is.getThenStmt.accept(this, arg)
//
//    is.getElseStmt.ifPresent { es =>
//      // goto end
//      val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, is_range, if_end_label))(is_range))(is_range)
//      createLocation(is_range, goto)
//
//      // else
//      createLabel(is_range, else_label)
//      es.accept(this, arg)
//    }
//    createLabel(is_range, if_end_label)
//  }
//
//  override def visit(lcds: LocalClassDeclarationStmt, arg: Void): Unit = {
//    val anonCr = new ClassResolver(j2j, Some(ownerSig.getClassType), cr.innerLevel + 1, lcds.getClassDeclaration, false, Some(getLocalClassNum(lcds.getClassDeclaration.getNameAsString)), isStatic)
//    val anon = anonCr.process()
//    global.loadJavaClass(anon.typ, sourceFile)
//    localClasses(lcds.getClassDeclaration.getNameAsString) = anon.typ
//  }
//
//  /**
//    * java:
//    *   return exp;
//    *
//    * jawa:
//    *   temp:= exp;
//    *   return temp;
//    */
//  override def visit(rs: ReturnStmt, arg: Void): Unit = {
//    var retVs: Option[VarSymbol] = None
//    rs.getExpression.ifPresent{ exp =>
//      isLeft = false
//      exp.accept(this, arg)
//      retVs = Some(resultHolder)
//    }
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    retVs match {
//      case Some(_) =>
//        if(ownerSig.getReturnType.isObject) {
//          val kindKey = Token(Tokens.ID, rs.toRange, "kind")
//          val kindValue = TokenValue(Token(Tokens.ID, rs.toRange, "object"))(rs.toRange)
//          annotations += JawaAnnotation(kindKey, Some(kindValue))(rs.toRange)
//        }
//      case None =>
//        val kindKey = Token(Tokens.ID, rs.toRange, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, rs.toRange, "void"))(rs.toRange)
//        annotations += JawaAnnotation(kindKey, Some(kindValue))(rs.toRange)
//    }
//    val reStat = ReturnStatement(retVs, annotations.toList)(rs.toRange)
//    createLocation(rs.toRange, reStat)
//  }
//
//  //******************************************************************************
//  //                         Try, throw, Synchronized
//  //******************************************************************************
//
//  private def addExceptionHandler(typ: JawaType, pos: JawaPosition, start: String, end: String, target: String): Unit = {
//    val ex_typ_ast = handleJawaType(typ, pos)
//    val range = CatchRange(LocationSymbol(Token(Tokens.ID, pos, start))(pos), LocationSymbol(Token(Tokens.ID, pos, end))(pos))(pos)
//    val cc = JawaCatchClause(ex_typ_ast, range, LocationSymbol(Token(Tokens.ID, pos, target))(pos))(pos)
//    catchClauses += cc
//  }
//
//  /**
//    * java:
//    *   synchronized (var) { body }
//    *
//    * jawa:
//    *   temp:= var;
//    *   monitorenter temp;
//    *   try_start1:
//    *   body;
//    *   monitorexit temp;
//    *   try_end1:
//    *   goto synchronized_end;
//    *   try_start2:
//    *   catch1:
//    *   Throwable_temp:= Exception  @kind object @type `java.lang.Throwable`;
//    *   monitorexit temp;
//    *   try_end2:
//    *   throw Throwable_temp;
//    *   synchronized_end:
//    *
//    *   catch `java.lang.Throwable` @[try_start1..try_end1] goto catch1;
//    *   catch `java.lang.Throwable` @[try_start2..try_end2] goto catch1;
//    */
//  override def visit(ss: SynchronizedStmt, arg: Void): Unit = {
//    val ss_range = ss.toRange
//    isLeft = false
//    ss.getExpression.accept(this, arg)
//    val vs = resultHolder
//
//    // monitor enter
//    val menter = MonitorStatement(Token(Tokens.MONITOR_ENTER, ss_range, "monitorenter"), vs)(ss_range)
//    createLocation(ss_range, menter)
//
//    // body
//    ss.getBody.accept(this, arg)
//
//    // monitor exit
//    val mexit = MonitorStatement(Token(Tokens.MONITOR_ENTER, ss_range, "monitorexit"), vs)(ss_range)
//    createLocation(ss_range, mexit)
//  }
//
//  /**
//    * java:
//    *   throw x;
//    *
//    * jawa:
//    *   temp:= x;
//    *   throw temp;
//    */
//  override def visit(ts: ThrowStmt, arg: Void): Unit = {
//    val ts_range = ts.toRange
//    isLeft = false
//    ts.getExpression.accept(this, arg)
//    val vs = resultHolder
//    val tstmt = ThrowStatement(vs)(ts_range)
//    createLocation(ts_range, tstmt)
//  }
//
//  private def handleResources(resources: NodeList[Expression], body: BlockStmt, count: Int): NodeList[Statement] = {
//    val stmts = new NodeList[Statement]()
//    val head = resources.remove(0)
//    stmts.add(new ExpressionStmt(head))
//
//    val res_expr: Expression = head match {
//      case vde: VariableDeclarationExpr =>
//        new NameExpr(vde.getVariables.get(0).getName)
//      case e => e
//    }
//
//    // Throwable = null
//    val t_type = JavaParser.parseClassOrInterfaceType("Throwable")
//    val t_name = s"throwable$count"
//    val t_vd = new VariableDeclarator(t_type, t_name, new NullLiteralExpr())
//    val t_ex = new VariableDeclarationExpr(t_vd)
//    stmts.add(new ExpressionStmt(t_ex))
//
//    // try { ... } catch { ... }
//
//    val try_block: BlockStmt = if(resources.isEmpty) {
//      body
//    } else {
//      new BlockStmt(handleResources(resources, body, count + 1))
//    }
//
//    // catch
//    val catch_name = "t"
//    val catch_param = new Parameter(t_type, catch_name)
//    val catch_body_stmts = new NodeList[Statement]()
//    val assign = new AssignExpr(new NameExpr(t_name), new NameExpr(catch_name), AssignExpr.Operator.ASSIGN)
//    catch_body_stmts.add(new ExpressionStmt(assign))
//    val throw_ = new ThrowStmt(new NameExpr(t_name))
//    catch_body_stmts.add(throw_)
//    val catch_body: BlockStmt = new BlockStmt(catch_body_stmts)
//    val catch_clause: CatchClause = new CatchClause(catch_param, catch_body)
//    val catch_clauses = new NodeList[CatchClause]()
//    catch_clauses.add(catch_clause)
//
//    // finally
//    val if1_cond = new BinaryExpr(res_expr, new NullLiteralExpr(), BinaryExpr.Operator.NOT_EQUALS)
//
//    val if2_cond = new BinaryExpr(new NameExpr(t_name), new NullLiteralExpr(), BinaryExpr.Operator.NOT_EQUALS)
//    val mcall2: MethodCallExpr = new MethodCallExpr(res_expr, "close")
//    val try2_stmts = new NodeList[Statement]()
//    try2_stmts.add(new ExpressionStmt(mcall2))
//    val try2_block: BlockStmt = new BlockStmt(try2_stmts)
//
//    val catch2_body_stmts = new NodeList[Statement]()
//    val mcall_suppressed_args: NodeList[Expression] = new NodeList[Expression]()
//    mcall_suppressed_args.add(new NameExpr(catch_name))
//    val mcall_suppressed: MethodCallExpr = new MethodCallExpr(new NameExpr(t_name), "addSuppressed", mcall_suppressed_args)
//    catch2_body_stmts.add(new ExpressionStmt(mcall_suppressed))
//    val catch2_body: BlockStmt = new BlockStmt(catch2_body_stmts)
//
//    val catch2_clause: CatchClause = new CatchClause(catch_param, catch2_body)
//    val catch2_clauses = new NodeList[CatchClause]()
//    catch2_clauses.add(catch2_clause)
//    val try2 = new TryStmt(try2_block, catch2_clauses, null)
//    val then2_stmts = new NodeList[Statement]()
//    then2_stmts.add(try2)
//    val then2: BlockStmt = new BlockStmt(then2_stmts)
//
//    val else2_stmts = new NodeList[Statement]()
//    else2_stmts.add(new ExpressionStmt(mcall2))
//    val else2: BlockStmt = new BlockStmt(else2_stmts)
//    val if2_stmt = new IfStmt(if2_cond, then2, else2)
//    val then1_stmts = new NodeList[Statement]()
//    then1_stmts.add(if2_stmt)
//    val then1: BlockStmt = new BlockStmt(then1_stmts)
//    val if1_stmt = new IfStmt(if1_cond, then1, null)
//    val finally_stmts = new NodeList[Statement]()
//    finally_stmts.add(if1_stmt)
//    val finally_block: BlockStmt = new BlockStmt(finally_stmts)
//    val try_stmt = new TryStmt(try_block, catch_clauses, finally_block)
//    stmts.add(try_stmt)
//    stmts
//  }
//
//  /**
//    * java:
//    *   try {
//    *     body1;
//    *   }
//    *   catch (Exception e) {
//    *     body2;
//    *   }
//    *
//    * jawa:
//    *   Try_start:
//    *   body1;
//    *   Try_end:
//    *   goto Catchblock_end;
//    *   Catchblock_start:
//    *   Catch_start:
//    *   temp:= Exception @type `java.lang.Exception`;
//    *   body2;
//    *   Catch_end:
//    *   Catchblock_end:
//    *
//    *   catch `java.lang.Exception` @[Try_start..Try_end] goto Catch_start;
//    *
//    * java:
//    *   try {
//    *     body1;
//    *   }
//    *   catch (Exception e) {
//    *     body2;
//    *   } finally {
//    *     body3;
//    *   }
//    *
//    * jawa:
//    *   Try_start:
//    *   body1;
//    *   Try_end:
//    *
//    *   body3;
//    *
//    *   goto Catchblock_end;
//    *
//    *   Catchblock_start:
//    *
//    *   Catch_start:
//    *   temp:= Exception @type `java.lang.Exception`;
//    *   body2;
//    *   Catch_end:
//    *
//    *   body3;
//    *
//    *   Catchblock_end:
//    *
//    *   goto Finally_end;
//    *
//    *   Finally_start:
//    *   temp:= Exception @type `java.lang.Throwable`;
//    *   body3;
//    *   throw temp;
//    *   Finally_end:
//    *
//    *   catch `java.lang.Exception` @[Try_start..Try_end] goto Catch_start;
//    *   catch `java.lang.Throwable` @[Try_start..Try_end] goto Finally_start;
//    *   catch `java.lang.Throwable` @[Catch_start..Catch_end] goto Finally_start;
//    *
//    * java 8-9 with resources:
//    *   try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
//    *        GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
//    *     gzip.write("TEST".getBytes("UTF-8"));
//    *   } catch (IOException ioe) {
//    *     ioe.printStackTrace();
//    *   }
//    *
//    * change to java old first:
//    *   try {
//    *     final GZIPOutputStream gzip = new GZIPOutputStream(System.out);
//    *     Throwable gzipEx = null;
//    *     try {
//    *       gzip.write("TEST".getBytes("UTF-8"));
//    *     } catch (Throwable t) {
//    *       gzipEx = t;
//    *       throw t;
//    *     } finally {
//    *       if (gzip != null) {
//    *         if (gzipEx != null) {
//    *           try {
//    *             gzip.close();
//    *           } catch (Throwable t) {
//    *             gzipEx.addSuppressed(t);
//    *           }
//    *         } else {
//    *           gzip.close();
//    *         }
//    *       }
//    *     }
//    *   } catch (IOException ioe) {
//    *     ioe.printStackTrace();
//    *   }
//    */
//  override def visit(ts: TryStmt, arg: Void): Unit = {
//    val ts_range = ts.toRange
//    val (try_start_label, try_end_label, catchblock_start_label, catchblock_end_label, finally_start_label, finally_end_label) = getTryLabels
//    val end_label = if(ts.getFinallyBlock.isPresent) {
//      finally_end_label
//    } else {
//      catchblock_end_label
//    }
//
//    createLabel(ts_range, try_start_label)
//
//    if(ts.getResources.isEmpty) {
//      ts.getTryBlock.accept(this, arg)
//    } else {
//      // handle resources
//      handleResources(ts.getResources, ts.getTryBlock, 0).forEach{ stmt =>
//        stmt.accept(this, arg)
//      }
//    }
//
//    createLabel(ts_range, try_end_label)
//
//    ts.getFinallyBlock.ifPresent { fin =>
//      fin.accept(this, arg)
//    }
//
//    // goto
//    val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, ts_range, end_label))(ts_range))(ts_range)
//    createLocation(ts_range, goto)
//
//    val cc_labels: MList[(String, String)] = mlistEmpty
//    if(ts.getCatchClauses.isNonEmpty) {
//
//      // catch block start
//      createLabel(ts_range, catchblock_start_label)
//
//      ts.getCatchClauses.forEach { cc =>
//        val catch_start_label = getLabel(LabelType.CATCH, start = true)
//        val catch_end_label = getLabel(LabelType.CATCH, start = false)
//        cc_labels += ((catch_start_label, catch_end_label))
//        updateLabel(LabelType.CATCH)
//
//        // catch start
//        createLabel(ts_range, catch_start_label)
//        val ex_types = handleTypes(cc.getParameter.getType)
//        val ex_type = global.join(ex_types.map(t => t.typ).toSet)
//
//        val ex_name = checkAndAddVariable(ex_type, cc.getParameter.getType.toRange, cc.getParameter.getNameAsString, cc.getParameter.getName.toRange, isTemp = false)
//        val ex_vs = VarSymbol(Token(Tokens.ID, ts_range, ex_name.apostrophe))(ts_range)
//        val ex_vne = VariableNameExpression(ex_vs)(ts_range)
//        val ex_typ_ast = handleJawaType(ex_type, ts_range)
//        val ex_expr = ExceptionExpression(TypeExpression(ex_typ_ast)(ts_range))(ts_range)
//        val ex_assign = AssignmentStatement(ex_vne, ex_expr, ilistEmpty)(ts_range)
//        createLocation(ts_range, ex_assign)
//
//        // catch body
//        cc.getBody.accept(this, arg)
//
//        ex_types.foreach { typ =>
//          addExceptionHandler(typ.typ, typ.pos, try_start_label, try_end_label, catch_start_label)
//        }
//
//
//        // catch end
//        createLabel(ts_range, catch_end_label)
//
//        ts.getFinallyBlock.ifPresent { fin =>
//          fin.accept(this, arg)
//        }
//
//        // goto
//        val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, ts_range, end_label))(ts_range))(ts_range)
//        createLocation(ts_range, goto)
//      }
//
//      // catch block end
//      createLabel(ts_range, catchblock_end_label)
//    }
//
//    ts.getFinallyBlock.ifPresent{ fin =>
//      val fin_range = fin.toRange
//      createLabel(fin_range, finally_start_label)
//
//      val ex_name = checkAndAddVariable(ExceptionCenter.THROWABLE, fin_range, generateTempVarName(ExceptionCenter.THROWABLE), fin_range, isTemp = true)
//      val ex_vs = VarSymbol(Token(Tokens.ID, ts_range, ex_name.apostrophe))(ts_range)
//      val ex_vne = VariableNameExpression(ex_vs)(ts_range)
//      val ex_typ_ast = handleJawaType(ExceptionCenter.THROWABLE, ts_range)
//      val ex_expr = ExceptionExpression(TypeExpression(ex_typ_ast)(ts_range))(ts_range)
//      val ex_assign = AssignmentStatement(ex_vne, ex_expr, ilistEmpty)(ts_range)
//      createLocation(ts_range, ex_assign)
//
//      fin.accept(this, arg)
//
//      val ts = ThrowStatement(ex_vs)(fin_range)
//      createLocation(fin_range, ts)
//
//      createLabel(fin_range, finally_end_label)
//
//      addExceptionHandler(ExceptionCenter.THROWABLE, fin_range, try_start_label, try_end_label, finally_start_label)
//      cc_labels.foreach { case (cc_start, cc_end) =>
//        addExceptionHandler(ExceptionCenter.THROWABLE, fin_range, cc_start, cc_end, finally_start_label)
//      }
//    }
//
//  }
//
//  //*********************** Try, throw, Synchronized *****************
//
//  //***********************************************************************************************
//  //                                          Visit Expression
//  //***********************************************************************************************
//
//  private var resultHolder: VarSymbol = _
//  private var LHS: JawaExpression with LHS = _
//  // Toggle to control generate resultHolder or LHS
//  private var isLeft = false
//
//
//  private def generateCall(lhsOpt: Option[VariableNameExpression], sig: Signature, namePos: JawaPosition, recv: Option[VarSymbol], args: IList[VarSymbol], kind: String): CallStatement = {
//    val mns = MethodNameSymbol(Token(Tokens.ID, namePos, sig.methodName.apostrophe))(namePos)
//    mns.signature = sig
//    val arguments = recv match {
//      case Some(vs) => vs :: args
//      case None => args
//    }
//    val rhs = CallRhs(mns, arguments)(namePos)
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    // add singature annotation
//    val signatureKey = Token(Tokens.ID, namePos, "signature")
//    val signatureValue = TokenValue(Token(Tokens.ID, namePos, sig.signature.apostrophe))(namePos)
//    annotations += JawaAnnotation(signatureKey, Some(signatureValue))(namePos)
//    // add kind annotation
//    val accessFlagKey = Token(Tokens.ID, namePos, "kind")
//    val accessFlagValue = TokenValue(Token(Tokens.ID, namePos, kind))(namePos)
//    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(namePos)
//    CallStatement(lhsOpt, rhs, annotations.toList)(namePos)
//  }
//
//  private def resolveMethod(classType: JawaType, methodName: String, namePos: JawaPosition, args: IList[VarSymbol]): Try[JawaMethod] = {
//    val clazz = global.getClassOrResolve(classType)
//    val argTypes = args.map(arg => getVariableType(arg.varName, arg.pos, isTemp = true))
//    clazz.getMethodByNameAndArgTypes(methodName, argTypes) match {
//      case Some(m) => Success(m)
//      case None => Failure(Java2JawaException(namePos, s"Could not find method $methodName with argTypes $argTypes in class $classType"))
//    }
//  }
//
//  private def generateCall(lhsOpt: Option[VariableNameExpression], classType: JawaType, methodName: String, namePos: JawaPosition, recv: Option[VarSymbol], args: IList[VarSymbol], kind: String): CallStatement = {
//    val method = resolveMethod(classType, methodName, namePos, args) match {
//      case Success(m) => m
//      case Failure(e) => throw e
//    }
//    val sig = method.getSignature
//    generateCall(lhsOpt, sig, namePos, recv, args, kind)
//  }
//
//  private def buildString(vses: IList[VarSymbol], pos: JawaPosition): VarSymbol = {
//    // StringBuilder sb = new StringBuilder();
//    val sb = new JawaType("java.lang.StringBuilder")
//    val sb_var = checkAndAddVariable(sb, pos, generateTempVarName(sb), pos, isTemp = true)
//    val sb_vs = VarSymbol(Token(Tokens.ID, pos, sb_var.apostrophe))(pos)
//    val sb_vne = VariableNameExpression(sb_vs)(pos)
//    val sb_typ_ast = handleJawaType(sb, pos)
//    val sb_new = NewExpression(sb_typ_ast)(pos)
//    val sb_assign = AssignmentStatement(sb_vne, sb_new, ilistEmpty)(pos)
//    createLocation(pos, sb_assign)
//    val init_call = generateCall(None, sb, "<init>", pos, Some(sb_vs), ilistEmpty, "direct")
//    createLocation(pos, init_call)
//
//    vses.foreach { vs =>
//      // sb.append();
//      val c = generateCall(None, sb, "append", vs.pos, Some(sb_vs), List(vs), "virtual")
//      createLocation(vs.pos, c)
//    }
//
//    // temp = sb.toString();
//    val temp = checkAndAddVariable(JavaKnowledge.STRING, pos, generateTempVarName(JavaKnowledge.STRING), pos, isTemp = true)
//    val temp_vs = VarSymbol(Token(Tokens.ID, pos, temp.apostrophe))(pos)
//    val temp_vne = VariableNameExpression(temp_vs)(pos)
//    val toString_c = generateCall(Some(temp_vne), new Signature("Ljava/lang/StringBuilder;.toString:()Ljava/lang/String;"), pos, Some(sb_vs), ilistEmpty, "virtual")
//    createLocation(pos, toString_c)
//    temp_vs
//  }
//
//  //*********************************************************************
//  //                       LiteralExpr
//  //*********************************************************************
//
//  private def processLiteralExpr(l: LiteralExpr): VarSymbol = {
//    val (varName, typ) = l match {
//      case _ : BooleanLiteralExpr => ("boolean_temp", JavaKnowledge.BOOLEAN)
//      case _ : CharLiteralExpr => ("char_temp", JavaKnowledge.CHAR)
//      case _ : DoubleLiteralExpr => ("double_temp", JavaKnowledge.DOUBLE)
//      case _ : IntegerLiteralExpr => ("int_temp", JavaKnowledge.INT)
//      case _ : LongLiteralExpr => ("long_temp", JavaKnowledge.LONG)
//      case _ : NullLiteralExpr => ("Object_temp", JavaKnowledge.OBJECT)
//      case _ : StringLiteralExpr => ("String_temp", JavaKnowledge.STRING)
//      case _ => throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
//    }
//    VarSymbol(Token(Tokens.ID, l.toRange, checkAndAddVariable(typ, l.toRange, varName, l.toRange, isTemp = true).apostrophe))(l.toRange)
//  }
//
//  private def getLiteralToken(l: LiteralExpr): Token = {
//    l match {
//      case ble: BooleanLiteralExpr =>
//        val n = if(ble.getValue) "1I" else "0I"
//        Token(Tokens.INTEGER_LITERAL, l.toRange, n)
//      case cle: CharLiteralExpr =>
//        Token(Tokens.INTEGER_LITERAL, l.toRange, cle.getValue)
//      case dle: DoubleLiteralExpr =>
//        Token(Tokens.FLOATING_POINT_LITERAL, l.toRange, dle.getValue)
//      case ile: IntegerLiteralExpr =>
//        Token(Tokens.INTEGER_LITERAL, l.toRange, ile.getValue)
//      case lle: LongLiteralExpr =>
//        Token(Tokens.INTEGER_LITERAL, l.toRange, lle.getValue)
//      case sle: StringLiteralExpr =>
//        Token(Tokens.STRING_LITERAL, l.toRange, sle.getValue.doublequotes)
//      case _ => throw Java2JawaException(l.toRange, s"${l.getClass} is not handled by jawa: $l, please contact author: fgwei521@gmail.com")
//    }
//  }
//
//  private def getLiteralExpression(l: LiteralExpr): LiteralExpression = {
//    LiteralExpression(getLiteralToken(l))(l.toRange)
//  }
//
//  /**
//    * java:
//    *   false
//    *
//    * jawa:
//    *   result := 0
//    */
//  override def visit(l: BooleanLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: CharLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: DoubleLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: IntegerLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: LongLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: NullLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le = NullExpression(Token(Tokens.NULL, l.toRange, "null"))(l.toRange)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  override def visit(l: StringLiteralExpr, arg: Void): Unit = {
//    val left = processLiteralExpr(l)
//    val le: LiteralExpression = getLiteralExpression(l)
//    val be = AssignmentStatement(VariableNameExpression(left)(l.toRange), le, ilistEmpty)(l.toRange)
//    createLocation(l.toRange, be)
//    resultHolder = left
//  }
//
//  //*********************************************************************
//  //                       LiteralExpr End
//  //*********************************************************************
//
//  private def createIntAssignment(name: String, lit: Int, pos: JawaPosition): VarSymbol = {
//    val vs = VarSymbol(Token(Tokens.ID, pos, checkAndAddVariable(JavaKnowledge.INT, pos, name, pos, isTemp = true).apostrophe))(pos)
//    val vne = VariableNameExpression(vs)(pos)
//    val litexp = LiteralExpression(Token(Tokens.INTEGER_LITERAL, pos, lit.toString))(pos)
//    val dimension_assign = AssignmentStatement(vne, litexp, ilistEmpty)(pos)
//    createLocation(pos, dimension_assign)
//    vs
//  }
//
//  /**
//    * java:
//    *   new arr[1][2];
//    *
//    * jawa:
//    *   temp1:= 1;
//    *   temp2:= 2;
//    *   temp:= new arr[temp1, temp2];
//    *
//    * java:
//    *   new arr[][]{{1, 2}, {x, 4}};
//    *
//    * jawa:
//    *   temp:= new arr[] [2];
//    *   temp1:= new arr[2];
//    *   temp1:= (1, 2) @kind object;
//    *   temp2:= new arr[2];
//    *   temp2[0]:= temp_x;
//    *   temp2[1]:= 4;
//    *   temp[0]:= temp1;
//    *   temp[1]:= temp2;
//    */
//  override def visit(ace: ArrayCreationExpr, arg: Void): Unit = {
//    val arrBaseType = handleType(ace.getElementType)
//    val arrType = JawaType.addDimensions(arrBaseType.typ, ace.getLevels.size())
//    if(ace.getInitializer.isPresent) {
//      val init = ace.getInitializer.get()
//      val init_range = init.toRange
//      val dimensions = init.getValues.size()
//      val dimensions_vs = createIntAssignment("int_temp", dimensions, init_range)
//      val arr_type1 = JawaType(arrType.baseType, arrType.dimensions - 1)
//      val nae = NewArrayExpression(handleJawaType(arr_type1, init_range), List(dimensions_vs))(init_range)
//      val nae_temp_name = checkAndAddVariable(arrType, init_range, generateTempVarName(arrType), init_range, isTemp = true)
//      val nae_temp_vs = VarSymbol(Token(Tokens.ID, init_range, nae_temp_name.apostrophe))(init_range)
//      val nae_temp_vne = VariableNameExpression(nae_temp_vs)(init_range)
//      val nae_assign = AssignmentStatement(nae_temp_vne, nae, ilistEmpty)(init_range)
//      createLocation(init_range, nae_assign)
//      resultHolder = nae_temp_vs
//      isLeft = false
//      init.accept(this, arg)
//    } else {
//      val vss: MList[VarSymbol] = mlistEmpty
//      ace.getLevels.forEach{ l =>
//        l.getDimension.ifPresent{ d =>
//          isLeft = false
//          d.accept(this, arg)
//          vss += resultHolder
//        }
//      }
//      val typeRange = ace.getElementType.toRange
//      val temp = checkAndAddVariable(arrType, typeRange, generateTempVarName(arrType), typeRange, isTemp = true)
//      val temp_vs = VarSymbol(Token(Tokens.ID, typeRange, temp.apostrophe))(typeRange)
//      val temp_vne = VariableNameExpression(temp_vs)(typeRange)
//      val nae = NewArrayExpression(arrBaseType, vss.toList)(ace.toRange)
//      val assign = AssignmentStatement(temp_vne, nae, ilistEmpty)(ace.toRange)
//      createLocation(typeRange, assign)
//      resultHolder = temp_vs
//    }
//  }
//
//  override def visit(aie: ArrayInitializerExpr, arg: Void): Unit = {
//    val base_vs = resultHolder
//    val base_typ = getVariableType(base_vs.varName, base_vs.pos, isTemp = true)
//    val aie_range = aie.toRange
//    var allLiteral = true
//    val constants: MList[LiteralExpression] = mlistEmpty
//    var allInit = false
//    aie.getValues.forEach{
//      case ble: BooleanLiteralExpr =>
//        val le = getLiteralExpression(ble)
//        constants += le
//      case cle: CharLiteralExpr =>
//        val le = getLiteralExpression(cle)
//        constants += le
//      case dle: DoubleLiteralExpr =>
//        val le = getLiteralExpression(dle)
//        constants += le
//      case ile: IntegerLiteralExpr =>
//        val le = getLiteralExpression(ile)
//        constants += le
//      case lle: LongLiteralExpr =>
//        val le = getLiteralExpression(lle)
//        constants += le
//      case _ : ArrayInitializerExpr =>
//        allLiteral = false
//        allInit = true // If one is init all should be init.
//      case _ =>
//        allLiteral = false
//    }
//
//    if(allLiteral) {
//      val tuple_exp = TupleExpression(constants.toList)(aie_range)
//      val kindKey = Token(Tokens.ID, aie_range, "kind")
//      val kindValue = TokenValue(Token(Tokens.ID, aie_range, "object"))(aie_range)
//      val assign_stmt = AssignmentStatement(VariableNameExpression(base_vs)(base_vs.pos), tuple_exp, List(JawaAnnotation(kindKey, Some(kindValue))(kindKey.pos)))(aie_range)
//      createLocation(aie_range, assign_stmt)
//    } else {
//      var rh = base_vs
//      aie.getValues.forEach{ v =>
//        if(allInit) {
//          val dimensions = v.asInstanceOf[ArrayInitializerExpr].getValues.size()
//          val dimensions_vs = createIntAssignment("int_temp", dimensions, aie_range)
//          val arr_type1 = JawaType(base_typ.baseType, base_typ.dimensions - 1)
//          val nae_temp_name = checkAndAddVariable(arr_type1, aie_range, generateTempVarName(arr_type1), aie_range, isTemp = true)
//          val nae_temp_vs = VarSymbol(Token(Tokens.ID, aie_range, nae_temp_name.apostrophe))(aie_range)
//          val nae_temp_vne = VariableNameExpression(nae_temp_vs)(aie_range)
//          val arr_type2 = JawaType(arr_type1.baseType, arr_type1.dimensions - 1)
//          val nae = NewArrayExpression(handleJawaType(arr_type2, aie_range), List(dimensions_vs))(aie_range)
//          val nae_assign = AssignmentStatement(nae_temp_vne, nae, ilistEmpty)(aie_range)
//          createLocation(aie_range, nae_assign)
//          rh = nae_temp_vs
//        }
//        val idx = aie.getValues.indexOf(v)
//        val idx_vs = createIntAssignment("int_temp", idx, aie_range)
//        val idx_exp = IndexingExpression(base_vs, List(IndexingSuffix(Left(idx_vs))(aie_range)))(aie_range)
//        isLeft = false
//        resultHolder = rh
//        v.accept(this, arg)
//        val vs = resultHolder
//        val vs_type = JawaType(base_typ.baseType, base_typ.dimensions - 1)
//        val annotations: MList[JawaAnnotation] = mlistEmpty
//        if (vs_type.isObject) {
//          val kindKey = Token(Tokens.ID, aie_range, "kind")
//          val kindValue = TokenValue(Token(Tokens.ID, aie_range, "object"))(aie_range)
//          annotations += JawaAnnotation(kindKey, Some(kindValue))(aie_range)
//        }
//        val value_assign = AssignmentStatement(idx_exp, VariableNameExpression(vs)(aie_range), annotations.toList)(aie_range)
//        createLocation(aie_range, value_assign)
//      }
//
//    }
//    resultHolder = base_vs
//  }
//
//  /**
//    * java:
//    *   arr[0][1];
//    *
//    * jawa:
//    *   temp1:= 0;
//    *   temp_arr1:= arr[temp1];
//    *   temp2:= 1;
//    *   temp:= temp_arr1[temp2];
//    */
//  override def visit(aae: ArrayAccessExpr, arg: Void): Unit = {
//    val left = isLeft
//    val aae_range = aae.toRange
//    isLeft = false
//    aae.getName.accept(this, arg)
//    val name_vs = resultHolder
//    isLeft = false
//    aae.getIndex.accept(this, arg)
//    val idx_vs = resultHolder
//    val name_type = getVariableType(name_vs.varName, name_vs.pos, isTemp = true)
//    val temp_type = JawaType(name_type.baseType, name_type.dimensions - 1)
//    val temp_name = checkAndAddVariable(temp_type, aae_range, generateTempVarName(temp_type), aae_range, isTemp = true)
//    val temp_vs = VarSymbol(Token(Tokens.ID, aae_range, temp_name.apostrophe))(aae_range)
//    val idx_exp = IndexingExpression(name_vs, List(IndexingSuffix(Left(idx_vs))(aae_range)))(aae_range)
//    if(left) {
//      LHS = idx_exp
//    } else {
//      val annotations: MList[JawaAnnotation] = mlistEmpty
//      if (temp_type.isObject) {
//        val kindKey = Token(Tokens.ID, aae_range, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, aae_range, "object"))(aae_range)
//        annotations += JawaAnnotation(kindKey, Some(kindValue))(aae_range)
//      }
//      val assign_stmt = AssignmentStatement(VariableNameExpression(temp_vs)(aae_range), idx_exp, annotations.toList)(aae_range)
//      createLocation(aae_range, assign_stmt)
//      resultHolder = temp_vs
//    }
//  }
//
//  /**
//    * java:
//    *   left = right;
//    *
//    * jawa:
//    *   temp1:= right;
//    *   left:= temp;
//    *   temp:= left;
//    *
//    * java:
//    *   left += right;
//    *
//    * jawa:
//    *   temp1:= right;
//    *   temp2:= left;
//    *   left:= temp2 + temp1;
//    *   temp:= left;
//    */
//  override def visit(ae: AssignExpr, arg: Void): Unit = {
//    val ae_range = ae.toRange
//    val left = isLeft
//    isLeft = false
//    ae.getValue.accept(this, arg)
//    val temp1 = resultHolder
//    val temp1Type = getVariableType(temp1.varName, temp1.pos, isTemp = true)
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    val rhs: JawaExpression with RHS = ae.getOperator match {
//      case AssignExpr.Operator.ASSIGN =>
//        if(temp1Type.isObject) {
//          val kindKey = Token(Tokens.ID, ae_range, "kind")
//          val kindValue = TokenValue(Token(Tokens.ID, ae_range, "object"))(ae_range)
//          annotations += JawaAnnotation(kindKey, Some(kindValue))(ae_range)
//        }
//        VariableNameExpression(temp1)(ae_range)
//      case op =>
//        isLeft = false
//        ae.getTarget.accept(this, arg)
//        val temp2 = resultHolder
//        val opStr = op match {
//          case AssignExpr.Operator.AND => "^&"
//          case AssignExpr.Operator.DIVIDE => "/"
//          case AssignExpr.Operator.LEFT_SHIFT => "^<"
//          case AssignExpr.Operator.MINUS => "-"
//          case AssignExpr.Operator.MULTIPLY => "*"
//          case AssignExpr.Operator.OR => "^|"
//          case AssignExpr.Operator.PLUS => "+"
//          case AssignExpr.Operator.REMAINDER => "%%"
//          case AssignExpr.Operator.SIGNED_RIGHT_SHIFT => "^>"
//          case AssignExpr.Operator.UNSIGNED_RIGHT_SHIFT => "^>>"
//          case AssignExpr.Operator.XOR => "^~"
//          case _ => throw Java2JawaException(ae_range, s"Unhandled operator $op, please contact author: fgwei521@gmail.com")
//        }
//        if(temp1Type == JavaKnowledge.STRING) {
//          val vs = buildString(List(temp2, temp1), ae_range)
//          VariableNameExpression(vs)(ae_range)
//        } else {
//          BinaryExpression(temp2, Token(Tokens.OP, ae_range, opStr), Left(temp1))(ae_range)
//        }
//    }
//    isLeft = true
//    ae.getTarget.accept(this, arg)
//    val assign = AssignmentStatement(LHS, rhs, annotations.toList)(ae_range)
//    createLocation(ae_range, assign)
//    if(!left) {
//      val tempName = checkAndAddVariable(temp1Type, ae_range, generateTempVarName(temp1Type), ae_range, isTemp = true)
//      val tempVar = VarSymbol(Token(Tokens.ID, ae_range, tempName.apostrophe))(ae_range)
//      val tempannotations: MList[JawaAnnotation] = mlistEmpty
//      if (temp1Type.isObject) {
//        val kindKey = Token(Tokens.ID, ae_range, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, ae_range, "object"))(ae_range)
//        tempannotations += JawaAnnotation(kindKey, Some(kindValue))(ae_range)
//      }
//      val tempAssign = AssignmentStatement(VariableNameExpression(tempVar)(ae_range), LHS, tempannotations.toList)(ae_range)
//      createLocation(ae_range, tempAssign)
//      resultHolder = tempVar
//    }
//  }
//
//  /**
//    * java:
//    *   a + b
//    *
//    * jawa:
//    *   temp1:= a;
//    *   temp2:= b;
//    *   temp3:= temp1 + temp2;
//    *
//    * java:
//    *   a == b
//    *
//    * jawa:
//    *   temp1:= a;
//    *   temp2:= b;
//    *   if temp1 != temp2 then goto Label1:
//    *   temp3:= 1;
//    *   goto Label2;
//    *   Label1:
//    *   temp3:= 0;
//    *   Label2:
//    */
//  override def visit(be: BinaryExpr, arg: Void): Unit = {
//    val be_range = be.toRange
//
//    var allPlus = true
//    def getParts(part: BinaryExpr): IList[Expression] = {
//      val parts: MList[Expression] = mlistEmpty
//      if(part.getOperator != BinaryExpr.Operator.PLUS) {
//        allPlus = false
//        return parts.toList
//      }
//      part.getLeft match {
//        case e: BinaryExpr =>
//          parts ++= getParts(e)
//        case e: Expression =>
//          parts += e
//      }
//      part.getRight match {
//        case e: BinaryExpr =>
//          parts ++= getParts(e)
//        case e: Expression =>
//          parts += e
//      }
//      parts.toList
//    }
//
//    val parts = getParts(be)
//
//    if(allPlus) {
//      var anyString = false
//      val vses = parts.map { part =>
//        isLeft = false
//        part.accept(this, arg)
//        val vs = resultHolder
//        val typ = getVariableType(vs.varName, be_range, isTemp = true)
//        if(typ == JavaKnowledge.STRING) {
//          anyString = true
//        }
//        vs
//      }
//      if(anyString) {
//        resultHolder = buildString(vses, be_range)
//      } else {
//        vses.headOption match {
//          case Some(head) =>
//            var left_vs = head
//            vses.tail.foreach { right_vs =>
//              val left_typ = getVariableType(left_vs.varName, left_vs.pos, isTemp = true)
//              val binExp = BinaryExpression(left_vs, Token(Tokens.OP, be_range, "+"), Left(right_vs))(be_range)
//              val temp3_name = checkAndAddVariable(left_typ, be_range, generateTempVarName(left_typ), be_range, isTemp = true)
//              val temp3_vs = VarSymbol(Token(Tokens.ID, be_range, temp3_name.apostrophe))(be_range)
//              val assignStmt = AssignmentStatement(VariableNameExpression(temp3_vs)(be_range), binExp, ilistEmpty)(be_range)
//              createLocation(be_range, assignStmt)
//              left_vs = temp3_vs
//            }
//            resultHolder = left_vs
//          case None =>
//        }
//      }
//    } else {
//      isLeft = false
//      be.getLeft.accept(this, arg)
//      val temp1 = resultHolder
//      isLeft = false
//      be.getRight.accept(this, arg)
//      val temp2 = resultHolder
//      val op: Either[String, String] = be.getOperator match {
//        case BinaryExpr.Operator.AND => Right("^&")
//        case BinaryExpr.Operator.BINARY_AND => Right("^&")
//        case BinaryExpr.Operator.BINARY_OR => Right("^|")
//        case BinaryExpr.Operator.DIVIDE => Right("/")
//        case BinaryExpr.Operator.EQUALS => Left("==")
//        case BinaryExpr.Operator.GREATER => Left(">")
//        case BinaryExpr.Operator.GREATER_EQUALS => Left(">=")
//        case BinaryExpr.Operator.LEFT_SHIFT => Right("^<")
//        case BinaryExpr.Operator.LESS => Left("<")
//        case BinaryExpr.Operator.LESS_EQUALS => Left("<=")
//        case BinaryExpr.Operator.MINUS => Right("-")
//        case BinaryExpr.Operator.MULTIPLY => Right("*")
//        case BinaryExpr.Operator.NOT_EQUALS => Left("!=")
//        case BinaryExpr.Operator.OR => Right("^|")
//        case BinaryExpr.Operator.PLUS => Right("+")
//        case BinaryExpr.Operator.REMAINDER => Right("%%")
//        case BinaryExpr.Operator.SIGNED_RIGHT_SHIFT => Right("^>")
//        case BinaryExpr.Operator.UNSIGNED_RIGHT_SHIFT => Right("^>>")
//        case BinaryExpr.Operator.XOR => Right("^~")
//      }
//      op match {
//        case Left(o) =>
//          val biExpr = BinaryExpression(temp1, Token(Tokens.OP, be_range, o), Left(temp2))(be_range)
//          val label = getNormalLabel
//          val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, be_range, label))(be_range))(be_range)
//          createLocation(be_range, ifStmt)
//          val temp3Name = checkAndAddVariable(JavaKnowledge.BOOLEAN, be_range, "boolean_temp", be_range, isTemp = true)
//          val temp3Var = VarSymbol(Token(Tokens.ID, be_range, temp3Name.apostrophe))(be_range)
//          val assignStmt1 = AssignmentStatement(VariableNameExpression(temp3Var)(be_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, be_range, "0"))(be_range), ilistEmpty)(be_range)
//          createLocation(be_range, assignStmt1)
//          val label2 = getNormalLabel
//          val gotoStmt = GotoStatement(LocationSymbol(Token(Tokens.ID, be_range, label2))(be_range))(be_range)
//          createLocation(be_range, gotoStmt)
//          createLabel(be_range, label)
//          val assignStmt2 = AssignmentStatement(VariableNameExpression(temp3Var)(be_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, be_range, "1"))(be_range), ilistEmpty)(be_range)
//          createLocation(be_range, assignStmt2)
//          createLabel(be_range, label2)
//          resultHolder = temp3Var
//        case Right(o) =>
//          val typ = getVariableType(temp1.varName, temp1.pos, isTemp = true)
//          val binExp = BinaryExpression(temp1, Token(Tokens.OP, be_range, o), Left(temp2))(be_range)
//          val temp3Name = checkAndAddVariable(typ, be_range, generateTempVarName(typ), be_range, isTemp = true)
//          val temp3Var = VarSymbol(Token(Tokens.ID, be_range, temp3Name.apostrophe))(be_range)
//          val assignStmt = AssignmentStatement(VariableNameExpression(temp3Var)(be_range), binExp, ilistEmpty)(be_range)
//          createLocation(be_range, assignStmt)
//          resultHolder = temp3Var
//      }
//    }
//  }
//
//  /**
//    * java:
//    *   Data a = (Data) o;
//    *
//    * jawa:
//    *   temp:= o;
//    *   temp2:= (Data) temp;
//    *   a:= temp2;
//    */
//  override def visit(ce: CastExpr, arg: Void): Unit = {
//    val ce_range = ce.toRange
//    isLeft = false
//    ce.getExpression.accept(this, arg)
//    val temp = resultHolder
//    handleTypes(ce.getType).foreach { cast_type =>
//      val cexp = CastExpression(cast_type, temp)(ce_range)
//      val temp2Name = checkAndAddVariable(cast_type.typ, ce_range, generateTempVarName(cast_type.typ), ce_range, isTemp = true)
//      val temp2Var = VarSymbol(Token(Tokens.ID, ce_range, temp2Name.apostrophe))(ce_range)
//      val temp2annotations: MList[JawaAnnotation] = mlistEmpty
//      if (cast_type.typ.isObject) {
//        val kindKey = Token(Tokens.ID, ce_range, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, ce_range, "object"))(ce_range)
//        temp2annotations += JawaAnnotation(kindKey, Some(kindValue))(ce_range)
//      }
//      val cast_assign = AssignmentStatement(VariableNameExpression(temp2Var)(ce_range), cexp, temp2annotations.toList)(ce_range)
//      createLocation(ce_range, cast_assign)
//      resultHolder = temp2Var
//    }
//  }
//
//  /**
//    * java:
//    *   Object.class;
//    *
//    * jawa:
//    *   temp:= constclass @type `Object` @kind object;
//    */
//  override def visit(ce: ClassExpr, arg: Void): Unit = {
//    val ce_range = ce.toRange
//    val tempName = checkAndAddVariable(JavaKnowledge.CLASS, ce_range, generateTempVarName(JavaKnowledge.CLASS), ce_range, isTemp = true)
//    val tempVar = VarSymbol(Token(Tokens.ID, ce_range, tempName.apostrophe))(ce_range)
//    val cc = ConstClassExpression(TypeExpression(handleType(ce.getType))(ce_range))(ce_range)
//    val kindKey = Token(Tokens.ID, ce_range, "kind")
//    val kindValue = TokenValue(Token(Tokens.ID, ce_range, "object"))(ce_range)
//    val ce_assign = AssignmentStatement(VariableNameExpression(tempVar)(ce_range), cc, List(JawaAnnotation(kindKey, Some(kindValue))(ce_range)))(ce_range)
//    createLocation(ce_range, ce_assign)
//    resultHolder = tempVar
//  }
//
//  /**
//    * java:
//    *   i ? a : b;
//    *
//    * jawa:
//    *   temp:= i;
//    *   if temp != 0 then goto Label1;
//    *   temp1:= a;
//    *   goto Label2;
//    *   Label1:
//    *   temp1:= b;
//    *   Label2:
//    */
//  override def visit(ce: ConditionalExpr, arg: Void): Unit = {
//    val ce_range = ce.toRange
//
//    isLeft = false
//    ce.getCondition.accept(this, arg)
//    val temp = resultHolder
//    val label = getNormalLabel
//    val ifStmt = createIfStatement(temp, Token(Tokens.OP, temp.pos, "=="), LocationSymbol(Token(Tokens.ID, ce_range, label))(ce_range), ce_range)
//    createLocation(ce_range, ifStmt)
//
//    isLeft = false
//    ce.getThenExpr.accept(this, arg)
//    val result1 = resultHolder
//    val temp1_type = getVariableType(result1.varName, result1.pos, isTemp = true)
//    val temp1_name = checkAndAddVariable(temp1_type, ce_range, generateTempVarName(temp1_type), ce_range, isTemp = true)
//    val temp1_var = VarSymbol(Token(Tokens.ID, ce_range, temp1_name.apostrophe))(ce_range)
//    val assignStmt1 = AssignmentStatement(VariableNameExpression(temp1_var)(ce_range), VariableNameExpression(result1)(ce_range), ilistEmpty)(ce_range)
//    createLocation(ce_range, assignStmt1)
//
//    val label2 = getNormalLabel
//    val gotoStmt = GotoStatement(LocationSymbol(Token(Tokens.ID, ce_range, label2))(ce_range))(ce_range)
//    createLocation(ce_range, gotoStmt)
//
//    createLabel(ce_range, label)
//    isLeft = false
//    ce.getElseExpr.accept(this, arg)
//    val result2 = resultHolder
//    val assignStmt2 = AssignmentStatement(VariableNameExpression(temp1_var)(ce_range), VariableNameExpression(result2)(ce_range), ilistEmpty)(ce_range)
//    createLocation(ce_range, assignStmt2)
//
//    createLabel(ce_range, label2)
//    resultHolder = temp1_var
//  }
//
//  /**
//    * java (left):
//    *   person.name = v;
//    *
//    * jawa:
//    *   temp := person;
//    *   temp.name := v;
//    *
//    * java (right):
//    *   v = person.name;
//    *
//    * jawa:
//    *   temp := person;
//    *   temp2 := temp.name;
//    *   v := temp2;
//    */
//  override def visit(fae: FieldAccessExpr, arg: Void): Unit = {
//    val left = isLeft
//    resolveScope(fae.getScope) match {
//      case Left(baseType) =>
//        val clazz = global.getClassOrResolve(baseType)
//        clazz.getField(fae.getNameAsString) match {
//          case Some(f) =>
//            val typeExp = TypeExpression(handleJawaType(f.typ, fae.toRange))(fae.toRange)
//            val exp = if(f.isStatic) {
//              StaticFieldAccessExpression(FieldNameSymbol(Token(Tokens.ID, fae.toRange, s"@@${f.FQN.fqn}".apostrophe))(fae.toRange), typeExp)(fae.toRange)
//            } else {
//              isLeft = false
//              fae.getScope.accept(this, arg)
//              val temp = resultHolder
//              AccessExpression(temp, FieldNameSymbol(Token(Tokens.ID, fae.getName.toRange, f.FQN.fqn.apostrophe))(fae.getName.toRange), typeExp)(fae.getName.toRange)
//            }
//            if(left) {
//              LHS = exp
//            } else {
//              val temp2_name = checkAndAddVariable(f.typ, fae.toRange, s"field_${f.getName}", fae.toRange, isTemp = true)
//              val temp2_var = VarSymbol(Token(Tokens.ID, fae.toRange, temp2_name.apostrophe))(fae.toRange)
//              val temp2_vne = VariableNameExpression(temp2_var)(temp2_var.pos)
//              val annotations: MList[JawaAnnotation] = mlistEmpty
//              if (f.typ.isObject) {
//                val kindKey = Token(Tokens.ID, temp2_vne.pos, "kind")
//                val kindValue = TokenValue(Token(Tokens.ID, temp2_vne.pos, "object"))(temp2_vne.pos)
//                annotations += JawaAnnotation(kindKey, Some(kindValue))(kindKey.pos)
//              }
//              val assign_stmt = AssignmentStatement(temp2_vne, exp, annotations.toList)(temp2_vne.pos)
//              createLocation(temp2_vne.pos, assign_stmt)
//              resultHolder = temp2_var
//            }
//          case None =>
//            throw Java2JawaException(fae.toRange, s"Could not find field ${fae.getNameAsString} from ${baseType.jawaName}")
//        }
//      case Right(pkg) =>
//        throw Java2JawaException(fae.toRange, s"Array access on package is not allowed. Package name: ${pkg.toPkgString(".")}")
//    }
//  }
//
//  /**
//    * java:
//    *   d instanceof Data;
//    *
//    * jawa:
//    *   temp:= d;
//    *   temp2:= instanceof @variable temp @type `Data`;
//    */
//  override def visit(ie: InstanceOfExpr, arg: Void): Unit = {
//    val ie_range = ie.toRange
//    isLeft = false
//    ie.getExpression.accept(this, arg)
//    val temp = resultHolder
//    val temp2Name = checkAndAddVariable(JavaKnowledge.BOOLEAN, ie_range, generateTempVarName(JavaKnowledge.BOOLEAN), ie_range, isTemp = true)
//    val temp2Var = VarSymbol(Token(Tokens.ID, ie_range, temp2Name.apostrophe))(ie_range)
//    val type_ast = handleType(ie.getType)
//    val ioe = InstanceOfExpression(temp, TypeExpression(type_ast)(ie_range))(ie_range)
//    val ie_assign = AssignmentStatement(VariableNameExpression(temp2Var)(ie_range), ioe, ilistEmpty)(ie_range)
//    createLocation(ie_range, ie_assign)
//    resultHolder = temp2Var
//  }
//
//  override def visit(le: LambdaExpr, arg: Void): Unit = {
//    // TODO: handle lambda
//  }
//
//  /**
//    * java:
//    *   foo(arg1, arg3);
//    *
//    * jawa:
//    *   temp1:= arg1;
//    *   temp2:= arg2;
//    *   call temp:= `foo`(temp1, temp2) @signature `Lx;.foo:(Ly;Lz;)La;` @kind virtual;
//    */
//  override def visit(mce: MethodCallExpr, arg: Void): Unit = {
//    val name_range = mce.getName.toRange
//    var ownerType = ownerSig.getClassType
//    mce.getScope.ifPresent{ s =>
//      resolveScope(s) match {
//        case Left(typ) =>
//          ownerType = typ
//        case Right(pkg) =>
//          throw Java2JawaException(s.toRange, s"MethodCallExpr scope should not be package. Package name: ${pkg.toPkgString(".")}")
//      }
//    }
//    val methodName = mce.getNameAsString
//    val args: MList[VarSymbol] = mlistEmpty
//    mce.getArguments.forEach{ argument =>
//      isLeft = false
//      argument.accept(this, arg)
//      args += resultHolder
//    }
//    val method: JawaMethod = resolveMethod(ownerType, methodName, mce.toRange, args.toList) match {
//      case Success(m) => m
//      case Failure(_) =>
//        // Check if its static imported method
//        val argTypes = args.map(arg => getVariableType(arg.varName, arg.pos, isTemp = true))
//        imports.getStaticMethod(methodName, argTypes.toList) match {
//          case Some(m) => m
//          case None => throw Java2JawaException(mce.toRange, s"Could not resolve method call $mce")
//        }
//    }
//    var recv: Option[VarSymbol] = None
//    var kind = if(method.getDeclaringClass.isInterface) "interface" else "virtual"
//    if(method.isStatic) {
//      kind = "static"
//    } else {
//      if(mce.getScope.isPresent) {
//        val scope = mce.getScope.get()
//        if(scope.isInstanceOf[SuperExpr]) {
//          kind = "super"
//        }
//        isLeft = false
//        scope.accept(this, arg)
//        recv = Some(resultHolder)
//      } else {
//        recv = Some(thisVar)
//      }
//    }
//    var temp_vns: Option[VariableNameExpression] = None
//    method.getReturnType match {
//      case t if t == JavaKnowledge.VOID =>
//        resultHolder = null
//      case t =>
//        val temp_name = checkAndAddVariable(t, name_range, generateTempVarName(t), name_range, isTemp = true)
//        val temp_vs = VarSymbol(Token(Tokens.ID, name_range, temp_name.apostrophe))(name_range)
//        resultHolder = temp_vs
//        temp_vns = Some(VariableNameExpression(temp_vs)(name_range))
//    }
//    val cs = generateCall(temp_vns, method.getSignature, name_range, recv, args.toList, kind)
//    createLocation(name_range, cs)
//  }
//
//  override def visit(mre: MethodReferenceExpr, arg: Void): Unit = {
//    // TODO: handle lambda
//  }
//
//  /**
//    * java (left):
//    *   name:= v;
//    *
//    * jawa:
//    *   name:= v;
//    *
//    * java (right):
//    *   v:= name
//    *
//    * jawa:
//    *   v:= name;
//    *
//    */
//  override def visit(ne: NameExpr, arg: Void): Unit = {
//    val ne_range = ne.toRange
//    val clazz = global.getClassOrResolve(ownerSig.getClassType)
//    val ifField = clazz.getField(ne.getNameAsString) match {
//      case Some(f) =>
//        Some(f)
//      case None =>
//        imports.getStaticField(ne)
//    }
//    ifField match {
//      case Some(f) =>
//        val typeExp = TypeExpression(handleJawaType(f.typ, ne_range))(ne_range)
//        val exp = if(f.isStatic) {
//          StaticFieldAccessExpression(FieldNameSymbol(Token(Tokens.ID, ne_range, s"@@${f.FQN.fqn}".apostrophe))(ne_range), typeExp)(ne_range)
//        } else {
//          AccessExpression(thisVar, FieldNameSymbol(Token(Tokens.ID, ne.getName.toRange, f.FQN.fqn.apostrophe))(ne_range), typeExp)(ne_range)
//        }
//        if(isLeft) {
//          LHS = exp
//        } else {
//          val temp = checkAndAddVariable(f.typ, ne_range, s"field_${f.getName}", ne_range, isTemp = true)
//          val tempVs = VarSymbol(Token(Tokens.ID, ne_range, temp.apostrophe))(ne_range)
//          val annotations: MList[JawaAnnotation] = mlistEmpty
//          if (f.isObject) {
//            val kindKey = Token(Tokens.ID, ne_range, "kind")
//            val kindValue = TokenValue(Token(Tokens.ID, ne_range, "object"))(ne_range)
//            annotations += JawaAnnotation(kindKey, Some(kindValue))(ne_range)
//          }
//          val assign = AssignmentStatement(VariableNameExpression(tempVs)(ne_range), exp, annotations.toList)(ne_range)
//          createLocation(ne_range, assign)
//          resultHolder = tempVs
//        }
//      case None =>
//        val var_type = getVariableType(ne.getNameAsString, ne_range, isTemp = false)
//        val var_name = checkAndAddVariable(var_type, ne_range, ne.getNameAsString, ne_range, isTemp = false)
//        val vs = VarSymbol(Token(Tokens.ID, ne_range, var_name.apostrophe))(ne_range)
//        if(isLeft) {
//          val name = VariableNameExpression(vs)(vs.pos)
//          LHS = name
//        } else {
//          val temp = checkAndAddVariable(var_type, ne_range, generateTempVarName(var_type), ne_range, isTemp = true)
//          val tempVs = VarSymbol(Token(Tokens.ID, ne_range, temp.apostrophe))(ne_range)
//          val annotations: MList[JawaAnnotation] = mlistEmpty
//          if (var_type.isObject) {
//            val kindKey = Token(Tokens.ID, ne_range, "kind")
//            val kindValue = TokenValue(Token(Tokens.ID, ne_range, "object"))(ne_range)
//            annotations += JawaAnnotation(kindKey, Some(kindValue))(ne_range)
//          }
//          val assign = AssignmentStatement(VariableNameExpression(tempVs)(ne_range), VariableNameExpression(vs)(ne_range), annotations.toList)(ne_range)
//          createLocation(ne_range, assign)
//          resultHolder = tempVs
//        }
//    }
//  }
//
//  /**
//    * java:
//    *   new A().new Data(arg1, arg2);
//    *
//    * jawa:
//    *   temp:= new A$Data;
//    *   temp2:= new A;
//    *   call <init>(temp2) @kind direct;
//    *   call class_temp:=  `java.lang.Object.getClass`(temp2) @signature `Ljava/lang/Object;.getClass:()Ljava/lang/Class;` @kind virtual;
//    *
//    *   arg1_temp:= arg1;
//    *   arg2_temp:= arg2;
//    *   call <init>(temp, temp2, arg1_temp, arg2_temp) @kind direct;
//    */
//  override def visit(oce: ObjectCreationExpr, arg: Void): Unit = {
//    val oce_range = oce.toRange
//    var typ = resolveScope(oce) match {
//      case Left(t) => t
//      case Right(pkg) =>
//        throw Java2JawaException(oce.getType.toRange, s"ObjectCreationExpr should not be package. Package name: ${pkg.toPkgString(".")}")
//    }
//    oce.getAnonymousClassBody.ifPresent{ acb =>
//      val anonName = getAnonymousClassName
//      val anonCid = new ClassOrInterfaceDeclaration
//      val staticContext = if(oce.getScope.isPresent) {
//        false
//      } else {
//        isStatic
//      }
//      if(staticContext) {
//        anonCid.addModifier(Modifier.FINAL)
//      }
//      anonCid.setName(anonName)
//      val clazz = global.getClassOrResolve(typ)
//      if(clazz.isInterface) {
//        anonCid.addImplementedType(typ.canonicalName)
//      } else {
//        anonCid.addExtendedType(typ.canonicalName)
//      }
//      anonCid.setMembers(acb)
//      val anonCr = new ClassResolver(j2j, Some(ownerSig.getClassType), cr.innerLevel + 1, anonCid, true, None, staticContext)
//      val anon = anonCr.process()
//      typ = anon.typ
//      global.loadJavaClass(typ, sourceFile)
//    }
//    val baseTypeSymbol = TypeSymbol(Token(Tokens.ID, oce.getType.toRange, typ.jawaName.apostrophe))(oce.getType.toRange)
//    val temp = checkAndAddVariable(typ, oce_range, generateTempVarName(typ), oce_range, isTemp = true)
//    val temp_var = VarSymbol(Token(Tokens.ID, baseTypeSymbol.pos, temp.apostrophe))(baseTypeSymbol.pos)
//    val temp_vne = VariableNameExpression(temp_var)(baseTypeSymbol.pos)
//    val newExp = NewExpression(JawaTypeAst(baseTypeSymbol, ilistEmpty)(baseTypeSymbol.pos))(temp_vne.pos)
//    val assign_stmt = AssignmentStatement(temp_vne, newExp, ilistEmpty)(temp_vne.pos)
//    createLocation(oce_range, assign_stmt)
//
//    var outer_vs: Option[VarSymbol] = if(!isStatic && JavaKnowledge.isInnerClass(typ) && JavaKnowledge.getOuterTypeFrom(typ) == ownerSig.getClassType) {
//      Some(thisVar)
//    } else {
//      None
//    }
//
//    val args: MList[VarSymbol] = mlistEmpty
//    oce.getScope.ifPresent{ s =>
//      isLeft = false
//      s.accept(this, arg)
//      val outerVar = resultHolder
//      val class_temp = checkAndAddVariable(JavaKnowledge.CLASS, oce_range, "class_temp", oce_range, isTemp = true)
//      val lhs = VariableNameExpression(VarSymbol(Token(Tokens.ID, oce_range, class_temp.apostrophe))(oce_range))(oce_range)
//      val call = generateCall(Some(lhs), JavaKnowledge.OBJECT, "getClass", oce_range, Some(outerVar), ilistEmpty, "virtual")
//      createLocation(oce_range, call)
//      outer_vs = Some(outerVar)
//    }
//    args ++= outer_vs
//    oce.getArguments.forEach{ argument =>
//      isLeft = false
//      argument.accept(this, arg)
//      args += resultHolder
//    }
//    val init_call = generateCall(None, typ, "<init>", assign_stmt.pos, Some(temp_var), args.toList, "direct")
//    createLocation(oce_range, init_call)
//    resultHolder = temp_var
//  }
//
//  override def visit(thisExp: ThisExpr, arg: Void): Unit = {
//    resultHolder = thisVar
//  }
//
//  /**
//    * java:
//    *   i++;
//    *
//    * jawa:
//    *   temp:= i;
//    *   i:= temp + 1;
//    *
//    * java:
//    *   ++i;
//    *
//    * jawa:
//    *   temp:= i;
//    *   temp:= temp + 1;
//    *   i:= temp;
//    *
//    * java:
//    *   -i;
//    *
//    * jawa:
//    *   temp:= i;
//    *   temp:= -temp;
//    *
//    * java:
//    *   ~i;
//    *
//    * jawa:
//    *   temp:= i;
//    *   temp:= ~temp;
//    *
//    * java:
//    *   !b;
//    *
//    * jawa:
//    *   temp:= b;
//    *   if temp != 0 then goto Label1;
//    *   temp:= 1;
//    *   goto Label2;
//    *   Label1:
//    *   temp:= 0;
//    *   Label2:
//    */
//  override def visit(ue: UnaryExpr, arg: Void): Unit = {
//    val ue_range = ue.toRange
//    isLeft = false
//    ue.getExpression.accept(this, arg)
//    val temp = resultHolder
//    ue.getOperator match {
//      case UnaryExpr.Operator.POSTFIX_DECREMENT =>
//        isLeft = true
//        ue.getExpression.accept(this, arg)
//        val lhs = LHS
//        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "-"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
//        val be_assign = AssignmentStatement(lhs, be, ilistEmpty)(ue_range)
//        createLocation(ue_range, be_assign)
//      case UnaryExpr.Operator.POSTFIX_INCREMENT =>
//        isLeft = true
//        ue.getExpression.accept(this, arg)
//        val lhs = LHS
//        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "+"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
//        val be_assign = AssignmentStatement(lhs, be, ilistEmpty)(ue_range)
//        createLocation(ue_range, be_assign)
//      case UnaryExpr.Operator.PREFIX_DECREMENT =>
//        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "-"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
//        val temp_vne = VariableNameExpression(temp)(ue_range)
//        val be_assign = AssignmentStatement(temp_vne, be, ilistEmpty)(ue_range)
//        createLocation(ue_range, be_assign)
//        isLeft = true
//        ue.getExpression.accept(this, arg)
//        val lhs = LHS
//        val assign = AssignmentStatement(lhs, temp_vne, ilistEmpty)(ue_range)
//        createLocation(ue_range, assign)
//      case UnaryExpr.Operator.PREFIX_INCREMENT =>
//        val be = BinaryExpression(temp, Token(Tokens.OP, ue_range, "+"), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range))))(ue_range)
//        val temp_vne = VariableNameExpression(temp)(ue_range)
//        val be_assign = AssignmentStatement(temp_vne, be, ilistEmpty)(ue_range)
//        createLocation(ue_range, be_assign)
//        isLeft = true
//        ue.getExpression.accept(this, arg)
//        val lhs = LHS
//        val assign = AssignmentStatement(lhs, temp_vne, ilistEmpty)(ue_range)
//        createLocation(ue_range, assign)
//      case UnaryExpr.Operator.BITWISE_COMPLEMENT =>
//        val uexpr = UnaryExpression(Token(Tokens.OP, ue_range, "~"), temp)(ue_range)
//        val assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), uexpr, ilistEmpty)(ue_range)
//        createLocation(ue_range, assign)
//      case UnaryExpr.Operator.LOGICAL_COMPLEMENT =>
//        val biExpr = BinaryExpression(temp, Token(Tokens.OP, ue_range, "!="), Right(Left(LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "0"))(ue_range))))(ue_range)
//        val label = getNormalLabel
//        val ifStmt = IfStatement(biExpr, LocationSymbol(Token(Tokens.ID, ue_range, label))(ue_range))(ue_range)
//        createLocation(ue_range, ifStmt)
//        val true_assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "1"))(ue_range), ilistEmpty)(ue_range)
//        createLocation(ue_range, true_assign)
//        val label2 = getNormalLabel
//        val goto = GotoStatement(LocationSymbol(Token(Tokens.ID, ue_range, label2))(ue_range))(ue_range)
//        createLocation(ue_range, goto)
//        createLabel(ue_range, label)
//        val false_assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), LiteralExpression(Token(Tokens.INTEGER_LITERAL, ue_range, "0"))(ue_range), ilistEmpty)(ue_range)
//        createLocation(ue_range, false_assign)
//        createLabel(ue_range, label2)
//      case UnaryExpr.Operator.MINUS =>
//        val uexpr = UnaryExpression(Token(Tokens.OP, ue_range, "-"), temp)(ue_range)
//        val assign = AssignmentStatement(VariableNameExpression(temp)(ue_range), uexpr, ilistEmpty)(ue_range)
//        createLocation(ue_range, assign)
//      case UnaryExpr.Operator.PLUS =>
//      case _ =>
//        throw Java2JawaException(ue_range, s"Unhandled operator for unary expr: $ue")
//    }
//    resultHolder = temp
//  }
//
//  /**
//    * java:
//    *   int i = 1;
//    *
//    * jawa:
//    *   `int` i;
//    *
//    *   temp:= 1;
//    *   i:= temp;
//    *
//    * java:
//    *   Data d = new Data();
//    *
//    * jawa:
//    *   `Data` d;
//    *
//    *   temp := new `Data`;
//    *   call `<init>`(temp) @signature `LData;.<init>:()V` @kind direct;
//    *   d := temp;
//    */
//  override def visit(vde: VariableDeclarationExpr, arg: Void): Unit = {
//    vde.getVariables.forEach(v => v.accept(this, arg))
//  }
//
//  override def visit(vd: VariableDeclarator, arg: Void): Unit = {
//    val vd_range = vd.toRange
//    val varType = handleType(vd.getType)
//    val varName = checkAndAddVariable(varType.typ, vd.getName.toRange, vd.getNameAsString, vd.getName.toRange, isTemp = false)
//    val vs = VarSymbol(Token(Tokens.ID, vd.getName.toRange, varName.apostrophe))(vd.getName.toRange)
//    val vne = VariableNameExpression(vs)(vd.getName.toRange)
//    if(isLeft) {
//      LHS = vne
//    }
//    vd.getInitializer.ifPresent { init =>
//      isLeft = false
//      init.accept(this, arg)
//      val annotations: MList[JawaAnnotation] = mlistEmpty
//      if (varType.typ.isObject) {
//        val kindKey = Token(Tokens.ID, vd_range, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, vd_range, "object"))(vd_range)
//        annotations += JawaAnnotation(kindKey, Some(kindValue))(vd_range)
//      }
//      val assignStmt = AssignmentStatement(vne, VariableNameExpression(resultHolder)(vd_range), annotations.toList)(vd_range)
//      createLocation(vd_range, assignStmt)
//      resultHolder = vs
//    }
//  }
//
//  private def resolveScope(scope: Expression): Either[JawaType, JawaPackage] = {
//    scope match {
//      case ne: NameExpr =>
//        // If its a local variable
//        val name = varDeclNameMap.getOrElse(ne.getNameAsString, ne.getNameAsString)
//        localVariables.get(name) match {
//          case Some(typ) => Left(typ)
//          case None =>
//            // If its a field
//            val thisClass = global.getClassOrResolve(ownerSig.getClassType)
//            thisClass.getField(name) match {
//              case Some(f) =>
//                Left(f.getType)
//              case None =>
//                // If its a static field from static import
//                imports.getStaticField(ne) match {
//                  case Some(f) => Left(f.typ)
//                  case None =>
//                    imports.findTypeOpt(name) match {
//                      case Some(typ) => Left(typ)
//                      case None => // it must be a package part
//                        Right(JawaPackage(name, None))
//                    }
//                }
//            }
//        }
//      case fae: FieldAccessExpr =>
//        resolveScope(fae.getScope) match {
//          case Left(typ) =>
//            val clazz = global.getClassOrResolve(typ)
//            clazz.getField(fae.getNameAsString) match {
//              case Some(f) => Left(f.typ)
//              case None => throw Java2JawaException(fae.getName.toRange, s"Field ${fae.getNameAsString} not found from class ${typ.jawaName}.")
//            }
//          case Right(pkg) =>
//            imports.findTypeOpt(s"${pkg.toPkgString(".")}.${fae.getNameAsString}") match {
//              case Some(typ) => Left(typ)
//              case None => Right(JawaPackage(fae.getNameAsString, Some(pkg)))
//            }
//        }
//      case aae: ArrayAccessExpr =>
//        resolveScope(aae.getName) match {
//          case Left(typ) =>
//            Left(JawaType(typ.baseType, typ.dimensions - 1))
//          case Right(pkg) =>
//            throw Java2JawaException(scope.toRange, s"Array access on package is not allowed. Package name: ${pkg.toPkgString(".")}")
//        }
//      case ace: ArrayCreationExpr =>
//        localClasses.get(ace.createdType().asString()) match {
//          case Some(t) =>
//            Left(t)
//          case None =>
//            Left(imports.findType(ace.createdType()))
//        }
//      case _: ClassExpr =>
//        Left(JavaKnowledge.CLASS)
//      case ee: EnclosedExpr =>
//        resolveScope(ee.getInner)
//      case mce: MethodCallExpr =>
//        val baseType = if(mce.getScope.isPresent) {
//          resolveScope(mce.getScope.get()) match {
//            case Left(typ) =>
//              typ
//            case Right(pkg) =>
//              throw Java2JawaException(scope.toRange, s"Method call on package is not allowed. Package name: ${pkg.toPkgString(".")}")
//          }
//        } else {
//          ownerSig.getClassType
//        }
//        var argTypes: MList[JawaType] = mlistEmpty
//        mce.getArguments.forEach{ arg =>
//          resolveScope(arg) match {
//            case Left(argTyp) =>
//              argTypes += argTyp
//            case Right(pkg) =>
//              throw Java2JawaException(scope.toRange, s"Arg should not be package. Package name: ${pkg.toPkgString(".")}")
//          }
//        }
//        val clazz = global.getClassOrResolve(baseType)
//        clazz.getMethodByNameAndArgTypes(mce.getNameAsString, argTypes.toList) match {
//          case Some(m) =>
//            Left(m.getReturnType)
//          case None =>
//            throw Java2JawaException(scope.toRange, s"Could not find method with name: ${mce.getNameAsString}, arg types: ${argTypes.mkString(", ")}")
//        }
//      case oce: ObjectCreationExpr =>
//        var baseTypOpt: Option[JawaType] = None
//        oce.getScope.ifPresent{ s =>
//          val typ = resolveScope(s)
//          typ match {
//            case Left(t) =>
//              baseTypOpt = Some(t)
//            case Right(pkg) =>
//              throw Java2JawaException(scope.toRange, s"Scope for ObjectCreationExpr should not be package. Package name: ${pkg.toPkgString(".")}")
//          }
//        }
//        baseTypOpt match {
//          case Some(bt) =>
//            val className = s"${bt.baseTyp}$$${oce.getType.getNameAsString}"
//            Left(imports.findType(className, oce.getType.toRange))
//          case None =>
//            localClasses.get(oce.getType.getNameAsString) match {
//              case Some(t) =>
//                Left(t)
//              case None =>
//                Left(imports.findType(oce.getType))
//            }
//        }
//      case _: SuperExpr =>
//        Left(superType)
//      case _: ThisExpr =>
//        Left(ownerSig.getClassType)
//      case _ =>
//        throw Java2JawaException(scope.toRange, s"Unsupported scope expression: $scope")
//    }
//  }
//}