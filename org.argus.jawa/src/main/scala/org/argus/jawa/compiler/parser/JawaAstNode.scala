/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.parser

import org.argus.jawa.compiler.lexer.Token
import org.argus.jawa.compiler.lexer.Tokens._
import org.argus.jawa.compiler.util.CaseClassReflector
import org.argus.jawa.core.{DefaultReporter, JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.{NoPosition, Position}
import org.argus.jawa.core.util._

import scala.language.implicitConversions

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
sealed trait JawaAstNode extends CaseClassReflector with JavaKnowledge {

  def tokens: IList[Token]

  def firstTokenOption: Option[Token] = tokens.headOption

  lazy val lastTokenOption: Option[Token] = tokens.lastOption

  def firstToken: Token = firstTokenOption.get

  lazy val lastToken: Token = lastTokenOption.get
  
  //for CompilationUnit it will be null
  var enclosingTopLevelClass: TypeDefSymbol = _

  protected trait Flattenable {
    def tokens: IList[Token]
  }
  
  def getAllChildrenInclude: IList[JawaAstNode] = {
    this :: getAllChildren
  }
  
  def getAllChildren: IList[JawaAstNode] = {
    val allAsts: MList[JawaAstNode] = mlistEmpty
    val worklist: MList[JawaAstNode] = mlistEmpty
    allAsts += this
    allAsts ++= this.immediateChildren
    worklist ++= this.immediateChildren
    while(worklist.nonEmpty){
      val node = worklist.remove(0)
      allAsts ++= node.immediateChildren
      worklist ++= node.immediateChildren
    }
    allAsts.toList
  }

  def isEmpty: Boolean = tokens.isEmpty

  protected implicit def astNodeToFlattenable(node: JawaAstNode): Flattenable = new Flattenable { val tokens: IList[Token] = node.tokens }
  protected implicit def listToFlattenable[T](list: IList[T])(implicit ev$1: T => Flattenable): Flattenable = new Flattenable { val tokens: List[Token] = list flatMap { _.tokens } }
  protected implicit def optionToFlattenable[T](option: Option[T])(implicit ev$1: T => Flattenable): Flattenable = new Flattenable { val tokens: List[Token] = option.toList flatMap { _.tokens } }
  protected implicit def pairToFlattenable[T1, T2](pair: (T1, T2))(implicit ev$1: T1 => Flattenable, ev$2: T2 => Flattenable): Flattenable = new Flattenable { val tokens: List[Token] = pair._1.tokens ::: pair._2.tokens }
  protected implicit def tripleToFlattenable[T1, T2, T3](triple: (T1, T2, T3))(implicit ev$1: T1 => Flattenable, ev$2: T2 => Flattenable, ev$3: T3 => Flattenable): Flattenable = new Flattenable { val tokens: List[Token] = triple._1.tokens ++ triple._2.tokens ++ triple._3.tokens }
  protected implicit def eitherToFlattenable[T1, T2](either: T1 Either T2)(implicit ev$1: T1 => Flattenable, ev$2: T2 => Flattenable): Flattenable = new Flattenable {
    val tokens: IList[Token] = either match {
      case Left(f)  => f.tokens
      case Right(f) => f.tokens
    }
  }
  protected implicit def tokenToFlattenable(token: Token): Flattenable = new Flattenable { val tokens = List(token) }

  protected def flatten(flattenables: Flattenable*): IList[Token] = flattenables.toList flatMap { _.tokens }

  def immediateChildren: IList[JawaAstNode] = productIterator.toList flatten immediateAstNodes

  private def immediateAstNodes(n: Any): IList[JawaAstNode] = n match {
    case a: JawaAstNode            => List(a)
    case _: Token                  => Nil
    case Some(x)                   => immediateAstNodes(x)
    case xs: IList[_]              => xs flatMap { immediateAstNodes }
    case Left(x)                   => immediateAstNodes(x)
    case Right(x)                  => immediateAstNodes(x)
    case (l, r)                    => immediateAstNodes(l) ++ immediateAstNodes(r)
    case (x, y, z)                 => immediateAstNodes(x) ++ immediateAstNodes(y) ++ immediateAstNodes(z)
    case true | false | Nil | None => Nil
  }

  def toCode: String = {
    val sb: StringBuilder = new StringBuilder
    val (startline, startcolumn) = firstTokenOption match {
      case Some(ft) => (ft.line, ft.column)
      case None => (0, 0)
    }
    var prevline: Int = 0
    var prevcolumn: Int = 0
    tokens.foreach {
      token =>
        val line = token.line - startline
        val column = if(token.line == 0) token.column - startcolumn else token.column
        if(line != prevline) prevcolumn = 0
        val text = token.rawText
        for(_ <- 1 to line - prevline){
          sb.append("\n")
        }
        for(_ <- 1 to column - prevcolumn){
          sb.append(" ")
        }
        prevline = line
        prevcolumn = column + token.length
        sb.append(text)
    }
    sb.toString
  }
  
  /**
   * Returns range of tokens in the node, or None if there are no tokens in the node
   */
  def rangeOpt: Option[Range] =
    if (tokens.isEmpty)
      None
    else {
      val firstIndex = tokens.head.pos.start
      val lastIndex = tokens.last.lastCharacterOffset
      Some(Range(firstIndex, lastIndex - firstIndex + 1))
    }

  def pos: Position = {
    if(tokens.isEmpty) NoPosition
    else {
      val firstIndex = tokens.head.pos.start
      val lastIndex = tokens.last.lastCharacterOffset
      Position.range(firstToken.file, firstIndex, lastIndex - firstIndex + 1)
    }
  }
}

sealed trait ParsableAstNode extends JawaAstNode

case class CompilationUnit(
    topDecls: IList[ClassOrInterfaceDeclaration], 
    eofToken: Token) extends ParsableAstNode {
  lazy val tokens: IList[Token] = flatten(topDecls, eofToken)
  def localTypResolved: Boolean = topDecls.forall(_.methods.forall(_.resolvedBody.locals.forall(_.typOpt.isDefined)))
}

sealed trait Declaration extends JawaAstNode {
  def annotations: IList[Annotation]
  def accessModifier: String = {
    annotations.find { a => a.key == "AccessFlag" || a.key == "Access" } match{
      case Some(a) => a.value
      case None => ""
    }
  }
}

sealed trait JawaSymbol extends JawaAstNode {
  def id: Token
}

sealed trait DefSymbol extends JawaSymbol

sealed trait RefSymbol extends JawaSymbol

sealed trait ClassSym {
  def typ: JawaType
}
sealed trait MethodSym {
  def signature: Signature
}
sealed trait FieldSym{
  def FQN: String
  def baseType: JawaType
  def fieldName: String
}
sealed trait VarSym{
  def varName: String
  def owner: MethodDeclaration
}
sealed trait LocationSym{
  def location: String
  var locationIndex: Int = 0
  def owner: MethodDeclaration
}

case class TypeDefSymbol(id: Token) extends DefSymbol with ClassSym {
  lazy val tokens: IList[Token] = flatten(id)
  def typ: JawaType = getTypeFromName(id.text)
}

case class TypeSymbol(id: Token) extends RefSymbol with ClassSym {
  lazy val tokens: IList[Token] = flatten(id)
  def typ: JawaType = getTypeFromName(id.text)
}

case class MethodDefSymbol(id: Token) extends DefSymbol with MethodSym {
  lazy val tokens: IList[Token] = flatten(id)
  def baseType: JawaType = getClassTypeFromMethodFullName(id.text)
  var signature: Signature = _
  def methodName: String = getMethodNameFromMethodFullName(id.text)
}

case class MethodNameSymbol(id: Token) extends RefSymbol with MethodSym {
  lazy val tokens: IList[Token] = flatten(id)
  def baseType: JawaType = getClassTypeFromMethodFullName(id.text)
  var signature: Signature = _
  def methodName: String = getMethodNameFromMethodFullName(id.text)
}

case class FieldDefSymbol(id: Token) extends DefSymbol with FieldSym {
  lazy val tokens: IList[Token] = flatten(id)
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
}

case class FieldNameSymbol(id: Token) extends RefSymbol with FieldSym {
  lazy val tokens: IList[Token] = flatten(id)
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
}

case class SignatureSymbol(id: Token) extends RefSymbol with MethodSym {
  lazy val tokens: IList[Token] = flatten(id)
  def signature: Signature = new Signature(id.text)
  def methodName: String = signature.methodName
}

case class VarDefSymbol(id: Token) extends DefSymbol with VarSym {
  lazy val tokens: IList[Token] = flatten(id)
  def varName: String = id.text
  var owner: MethodDeclaration = _
}

case class VarSymbol(id: Token) extends RefSymbol with VarSym {
  lazy val tokens: IList[Token] = flatten(id)
  def varName: String = id.text
  var owner: MethodDeclaration = _
}

/**
 * LocationSymbol is following form: #L00001. or just #
 */
case class LocationDefSymbol(id: Token) extends DefSymbol with LocationSym {
  lazy val tokens: IList[Token] = flatten(id)
  def location: String = {
    if(id.text == "#") id.text
    else id.text.substring(1, id.text.length() - 1)
  }
  var owner: MethodDeclaration = _
}

/**
 * JumpLocationSymbol is following form: L00001
 */
case class LocationSymbol(id: Token) extends RefSymbol with LocationSym {
  lazy val tokens: IList[Token] = flatten(id)
  def location: String = id.text
  var owner: MethodDeclaration = _
}

case class ClassOrInterfaceDeclaration(
                                        dclToken: Token,
                                        cityp: TypeDefSymbol,
                                        annotations: IList[Annotation],
                                        extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses],
                                        instanceFieldDeclarationBlock: InstanceFieldDeclarationBlock,
                                        staticFields: IList[StaticFieldDeclaration],
                                        methods: IList[MethodDeclaration]) extends Declaration with ParsableAstNode {
  lazy val tokens: IList[Token] = flatten(dclToken, cityp, annotations, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields, methods)
  def isInterface: Boolean = {
    annotations.exists { a => a.key == "kind" && a.value == "interface" }
  }
  def parents: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.parents; case None => ilistEmpty}
  def superClassOpt: Option[JawaType] = extendsAndImplementsClausesOpt match{case Some(e) => e.superClassOpt; case None => None}
  def interfaces: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.interfaces; case None => ilistEmpty}
  def fields: IList[Field with Declaration] = instanceFieldDeclarationBlock.instanceFields ++ staticFields
  def instanceFields: IList[InstanceFieldDeclaration] = instanceFieldDeclarationBlock.instanceFields
  def typ: JawaType = cityp.typ
}

case class Annotation(
    at: Token,
    annotationID: Token,
    annotationValueOpt: Option[AnnotationValue]) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(at, annotationID, annotationValueOpt)
  def key: String = annotationID.text
  def value: String = annotationValueOpt.map(_.value).getOrElse("")
}

sealed trait AnnotationValue extends JawaAstNode {
  def value: String
}

case class TypeExpressionValue(
    typExp: TypeExpression) extends AnnotationValue {
  lazy val tokens: IList[Token] = flatten(typExp)
  def value: String = typExp.typ.name
}

case class SymbolValue(
    sym: JawaSymbol) extends AnnotationValue {
  lazy val tokens: IList[Token] = flatten(sym)
  def value: String = sym.id.text
}

case class TokenValue(
    token: Token) extends AnnotationValue {
  lazy val tokens: IList[Token] = flatten(token)
  def value: String = token.text
}

case class ExtendsAndImplementsClauses(
    extendsAndImplementsToken: Token,
    parentTyps: IList[(ExtendAndImplement, Option[Token])]) extends JawaAstNode {
  require(parentTyps.count(_._1.isExtend) <= 1)
  lazy val tokens: IList[Token] = flatten(extendsAndImplementsToken, parentTyps)
  def parents: IList[JawaType] = parentTyps.map(_._1.typ)
  def superClassOpt: Option[JawaType] = parentTyps.find(_._1.isExtend).map(_._1.typ)
  def interfaces: IList[JawaType] = parentTyps.filter(_._1.isImplement).map(_._1.typ)
}

case class ExtendAndImplement(
    parenttyp: TypeSymbol,
    annotations: IList[Annotation])extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(parenttyp, annotations)
  def typ: JawaType = parenttyp.typ
  def isExtend: Boolean = annotations.exists { a => a.key == "kind" && a.value == "class" }
  def isImplement: Boolean = annotations.exists { a => a.key == "kind" && a.value == "interface" }
}

sealed trait Field extends JawaAstNode {
  def typ: Type
  def fieldSymbol: FieldDefSymbol
  def FQN: String
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def isStatic: Boolean
}

case class InstanceFieldDeclarationBlock(
    lbrace: Token,
    instanceFields: IList[InstanceFieldDeclaration],
    rbrace: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lbrace, instanceFields, rbrace)
}

case class InstanceFieldDeclaration(
    typ: Type, 
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation], 
    semi: Token) extends Field with Declaration {
  lazy val tokens: IList[Token] = flatten(typ, fieldSymbol, annotations, semi)
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = false
}

case class StaticFieldDeclaration(
    staticFieldToken: Token, 
    typ: Type, 
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation], 
    semi: Token) extends Field with Declaration {
  lazy val tokens: IList[Token] = flatten(staticFieldToken, typ, fieldSymbol, annotations, semi)
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = true
}

case class TypeExpression(hat: Token, typ_ : Type) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(hat, typ_)
  def typ: JawaType = typ_.typ
}

case class Type(base: Either[TypeSymbol, Token], typeFragments: IList[TypeFragment]) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(base, typeFragments)
  def dimentions: Int = typeFragments.size
  def baseType: JawaType = 
    base match {
      case Left(ts) => ts.typ
      case Right(t) => getTypeFromName(t.text)
    }
  def typ: JawaType = getType(baseType.baseTyp, dimentions)
}

case class TypeFragment(lbracket: Token, rbracket: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lbracket, rbracket)
}

case class MethodDeclaration(
    dclToken: Token,
    returnType: Type,
    methodSymbol: MethodDefSymbol,
    paramClause: ParamClause,
    annotations: IList[Annotation],
    var body: Body) extends Declaration with ParsableAstNode {
  lazy val tokens: IList[Token] = flatten(dclToken, returnType, methodSymbol, paramClause, annotations, body)
  def isConstructor: Boolean = isJawaConstructor(name)
  def name: String = methodSymbol.id.text.substring(methodSymbol.id.text.lastIndexOf(".") + 1)
  def owner: String = annotations.find { a => a.key == "owner" }.get.value
  def signature: Signature = new Signature(annotations.find { a => a.key == "signature" }.get.value)
  def thisParam: Option[Param] = paramClause.thisParam
  def param(i: Int): Param = paramClause.param(i)
  def paramList: IList[Param] = paramClause.paramlist
  def resolvedBody: ResolvedBody = body match {
    case rb: ResolvedBody => rb
    case ub: UnresolvedBody =>
      body = ub.resolve
      body.asInstanceOf[ResolvedBody]
  }
}

case class ParamClause(
    lparen: Token,
    params: IList[(Param, Option[Token])], 
    rparen: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lparen, params, rparen)
  def thisParam: Option[Param] = params.find { x => x._1.isThis }.map(_._1)
  def param(i: Int): Param =
    i match {
      case n if n >= 0 && n < paramlist.size => paramlist(n)
      case _ => throw new IndexOutOfBoundsException("List size " + paramlist.size + " but index " + i)
    }
  def paramlist: IList[Param] = params.filterNot(_._1.isThis).map(_._1)
}

case class Param(
    typ: Type, 
    paramSymbol: VarDefSymbol, 
    annotations: IList[Annotation]) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(typ, paramSymbol, annotations)
  def isThis: Boolean = annotations.exists { a => a.key == "kind" && a.value == "this" }
  def isObject: Boolean = annotations.exists { a => a.key == "kind" && (a.value == "this" || a.value == "object") }
  def name: String = paramSymbol.id.text
}

sealed trait Body extends ParsableAstNode

case class UnresolvedBody(bodytokens: IList[Token]) extends Body {
  lazy val tokens: IList[Token] = flatten(bodytokens)
  def resolve: ResolvedBody = JawaParser.parse[Body](tokens, resolveBody = true, new DefaultReporter, classOf[Body]) match {
    case Left(body) => body.asInstanceOf[ResolvedBody]
    case Right(t) => throw t
  }
}

case class ResolvedBody(
    lbrace: Token, 
    locals: IList[LocalVarDeclaration], 
    locations: IList[Location], 
    catchClauses: IList[CatchClause], 
    rbrace: Token) extends Body {
  lazy val tokens: IList[Token] = flatten(lbrace, locals, locations, catchClauses, rbrace)
  def getCatchClauses(index: Int): IList[CatchClause] = {
    catchClauses.filter{
      cc =>
        index >= cc.range.fromLocation.locationIndex && index <= cc.range.toLocation.locationIndex
    }
  }
  def location(locUri: String): Location = locations.find(l => l.locationUri.equals(locUri)).get
  def location(locIndex: Int): Location = locations(locIndex)
}

case class LocalVarDeclaration(
    typOpt: Option[Type],
    varSymbol: VarDefSymbol,
    semi: Token) extends Declaration {
  lazy val tokens: IList[Token] = flatten(typOpt, varSymbol, semi)
  def annotations: IList[Annotation] = ilistEmpty
  def typ: JawaType = typOpt match {
    case Some(t) => t.typ
    case None => JAVA_TOPLEVEL_OBJECT_TYPE
  }
}

case class Location(
    locationSymbol: LocationDefSymbol, 
    statement: Statement, 
    semiOpt: Option[Token]) extends ParsableAstNode {
  lazy val tokens: IList[Token] = flatten(locationSymbol, statement, semiOpt)
  def locationUri: String = {
    if(locationSymbol.id.length <= 1) ""
    else locationSymbol.location
  }
  def locationIndex: Int = locationSymbol.locationIndex
}

/**
  * Statements:
  *   Assignment
  *   EmptyStatement
  *   MonitorStatement
  *   Jump
  *   ThrowStatement
  */
sealed trait Statement extends JawaAstNode

/**
  * Jumps:
  *   CallStatement
  *   GotoStatement
  *   IfStatement
  *   ReturnStatement
  *   SwitchStatement
  */
sealed trait Jump extends Statement

/**
  * Assignments:
  *   AssignmentStatement
  *   CallStatement
  */
sealed trait Assignment extends Statement {
  def getLhs: Option[Expression with LHS]
  def getRhs: Expression with RHS
}

case class CallStatement(
    callToken: Token, 
    lhsOpt: Option[CallLhs],
    rhs: CallRhs,
    annotations: IList[Annotation]) extends Assignment with Jump {
  lazy val tokens: IList[Token] = flatten(callToken, lhsOpt, rhs, annotations)
  //default is virtual call
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("virtual")
  def signature: Signature = new Signature(annotations.find { a => a.key == "signature" }.get.value)
  def classDescriptor: String = annotations.find { a => a.key == "classDescriptor" }.get.value
  def isStatic: Boolean = kind == "static"
  def isVirtual: Boolean = kind == "virtual"
  def isSuper: Boolean = kind == "super"
  def isDirect: Boolean = kind == "direct"
  def isInterface: Boolean = kind == "interface"
  def recvVarOpt: Option[VarSymbol] = if(isStatic) None else Some(rhs.argClause.varSymbols.head._1)
  def argVars: IList[VarSymbol] = if(isStatic) rhs.argClause.varSymbols.map(_._1) else rhs.argClause.varSymbols.tail.map(_._1)
  def argVar(i: Int): VarSymbol = {
    i match {
      case n if n >= 0 && n < argVars.size => argVars(n)
      case _ => throw new IndexOutOfBoundsException("List size " + argVars.size + " but index " + i)
    }
  }
  def recvOpt: Option[String] = if(isStatic) None else Some(rhs.argClause.arg(0))
  def args: IList[String] = if(isStatic) rhs.argClause.varSymbols.map(_._1.id.text) else rhs.argClause.varSymbols.tail.map(_._1.id.text)
  def arg(i: Int): String = {
    i match {
      case n if n >= 0 && n < args.size => args(n)
      case _ => throw new IndexOutOfBoundsException("List size " + args.size + " but index " + i)
    }
  }

  override def getLhs: Option[Expression with LHS] = lhsOpt
  override def getRhs: Expression with RHS = rhs
}

case class CallLhs(
    lhs: VarSymbol,
    assignOP: Token) extends Expression with LHS {
  lazy val tokens: IList[Token] = flatten(lhs, assignOP)
}

case class CallRhs(
    methodNameSymbol: MethodNameSymbol,
    argClause: ArgClause) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(methodNameSymbol, argClause)
}

case class ArgClause(
    lparen: Token, 
    varSymbols: IList[(VarSymbol, Option[Token])],
    rparen: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lparen, varSymbols, rparen)
  def arg(i: Int): String =
    i match {
      case n if n >= 0 && n < varSymbols.size => varSymbols(n)._1.id.text
      case _ => throw new IndexOutOfBoundsException("List size " + varSymbols.size + " but index " + i)
    }
}

case class AssignmentStatement(
    lhs: Expression with LHS,
    assignOP: Token,
    rhs: Expression with RHS,
    annotations: IList[Annotation]) extends Assignment {
  lazy val tokens: IList[Token] = flatten(lhs, assignOP, rhs, annotations)
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse({if(rhs.isInstanceOf[NewExpression])"object" else ""})
  def typOpt: Option[JawaType] = annotations.find { a => a.key == "type" }.map(_.annotationValueOpt.get.asInstanceOf[TypeExpressionValue].typExp.typ)

  override def getLhs: Option[Expression with LHS] = Some(lhs)

  override def getRhs: Expression with RHS = rhs
}

case class ThrowStatement(
    throwToken: Token,
    varSymbol: VarSymbol) extends Statement {
  lazy val tokens: IList[Token] = flatten(throwToken, varSymbol)
}

case class IfStatement(
    ifToken: Token,
    cond: BinaryExpression,
    thengoto: (Token, Token),
    targetLocation: LocationSymbol) extends Jump {
  lazy val tokens: IList[Token] = flatten(ifToken, cond, thengoto, targetLocation)
}

case class GotoStatement(
    goto: Token,
    targetLocation: LocationSymbol) extends Jump {
  lazy val tokens: IList[Token] = flatten(goto, targetLocation)
}

case class SwitchStatement(
    switchToken: Token,
    condition: VarSymbol,
    cases: IList[SwitchCase],
    defaultCaseOpt: Option[SwitchDefaultCase]) extends Jump {
  lazy val tokens: IList[Token] = flatten(switchToken, condition, cases, defaultCaseOpt)
}

case class SwitchCase(
    bar: Token,
    constant: Token,
    arrow: Token,
    goto: Token,
    targetLocation: LocationSymbol) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(bar, constant, arrow, goto, targetLocation)
}

case class SwitchDefaultCase(
    bar: Token,
    elseToken: Token,
    arrow: Token,
    goto: Token,
    targetLocation: LocationSymbol) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(bar, elseToken, arrow, goto, targetLocation)
}

case class ReturnStatement(
    returnToken: Token,
    varOpt: Option[VarSymbol],
    annotations: IList[Annotation]) extends Jump {
  lazy val tokens: IList[Token] = flatten(returnToken, varOpt, annotations)
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("")
}

case class MonitorStatement(
    at: Token,
    monitor: Token,
    varSymbol: VarSymbol) extends Statement {
  lazy val tokens: IList[Token] = flatten(at, monitor, varSymbol)
  def isEnter: Boolean = monitor.tokenType == MONITOR_ENTER
  def isExit: Boolean = monitor.tokenType == MONITOR_EXIT
}

case class EmptyStatement(
    annotations: IList[Annotation]) extends Statement {
  lazy val tokens: IList[Token] = flatten(annotations)
}

sealed trait Expression extends JawaAstNode

/** LHS expressions:
  *   AccessExpression
  *   CallLhs
  *   IndexingExpression
  *   NameExpression
  */
sealed trait LHS

/** LHS expressions:
  *   AccessExpression
  *   BinaryExpression
  *   CallRhs
  *   CastExpression
  *   CmpExpression
  *   ConstClassExpression
  *   ExceptionExpression
  *   IndexingExpression
  *   InstanceofExpression
  *   LengthExpression
  *   LiteralExpression
  *   NameExpression
  *   NewExpression
  *   NullExpression
  *   TupleExpression
  *   UnaryExpression
  */
sealed trait RHS

case class NameExpression(
    varSymbol: Either[VarSymbol, FieldNameSymbol] // FieldNameSymbol here is static fields
    ) extends Expression with LHS with RHS {
  lazy val tokens: IList[Token] = flatten(varSymbol)
  def name: String = 
    varSymbol match {
      case Left(v) => v.varName
      case Right(f) => f.FQN
    }
  def isStatic: Boolean = varSymbol.isRight
}

case class ExceptionExpression(
    exception: Token) extends Expression with RHS {
  var typ: JawaType = _
  lazy val tokens: IList[Token] = flatten(exception)
}

case class NullExpression(
    nul: Token) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(nul)
}

case class ConstClassExpression(
    const_class: Token,
    at: Token,
    typeToken: Token,
    typExp: TypeExpression) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(const_class, at, typeToken, typExp)
}

case class LengthExpression(
    length: Token,
    at: Token,
    variable: Token,
    varSymbol: VarSymbol) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(length, at, variable, varSymbol)
}

case class IndexingExpression(
    varSymbol: VarSymbol,
    indices: IList[IndexingSuffix]) extends Expression with LHS with RHS {
  lazy val tokens: IList[Token] = flatten(varSymbol, indices)
  def base: String = varSymbol.varName
  def dimentions: Int = indices.size
}

case class IndexingSuffix(
    lbracket: Token,
    index: Either[VarSymbol, LiteralExpression],
    rbracket: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lbracket, index, rbracket)
}
    
case class AccessExpression(
    varSymbol: VarSymbol,
    dot: Token,
    fieldSym: FieldNameSymbol) extends Expression with LHS with RHS {
  lazy val tokens: IList[Token] = flatten(varSymbol, dot, fieldSym)
  def base: String = varSymbol.varName
  def fieldName: String = fieldSym.fieldName
}

case class TupleExpression(
    lparen: Token,
    constants: IList[(LiteralExpression, Option[Token])],
    rparen: Token) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(lparen, constants, rparen)
  def integers: IList[Int] = constants.map(_._1.getInt)
}

case class CastExpression(
    lparen: Token,
    typ: Type,
    rparen: Token,
    varSym: VarSymbol) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(lparen, typ, rparen, varSym)
  def varName: String = varSym.varName
}

case class NewExpression(
    newToken: Token,
    base: Either[TypeSymbol, Token],
    typeFragmentsWithInit: IList[TypeFragmentWithInit]) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(newToken, base, typeFragmentsWithInit)
  def dimensions: Int = typeFragmentsWithInit.size
  def baseType: JawaType =
    base match {
      case Left(ts) => ts.typ
      case Right(t) => getTypeFromName(t.text)
    }
  def typ: JawaType = getType(baseType.baseTyp, dimensions)
}

case class TypeFragmentWithInit(lbracket: Token, varSymbols: IList[(VarSymbol, Option[Token])], rbracket: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(lbracket, varSymbols, rbracket)
  def varNames: IList[String] = varSymbols.map(_._1.varName)
  def varName(i: Int): String = varNames(i)
}

case class InstanceofExpression(
    instanceof: Token,
    at1: Token,
    variable: Token,
    varSymbol: VarSymbol,
    at2: Token,
    typeToken: Token,
    typExp: TypeExpression) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(instanceof, at1, variable, varSymbol, at2, typeToken, typExp)
}

case class LiteralExpression(
  constant: Token) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(constant)
  private def getLiteral: String = {
    val lit = constant.text
    constant.tokenType match {
      case STRING_LITERAL =>
        lit.substring(1, lit.length() - 1)
      case FLOATING_POINT_LITERAL =>
        lit match {
          case x if x.endsWith("F") => x.substring(0, x.length() - 1)
          case x if x.endsWith("D") => x.substring(0, x.length() - 1)
          case _ => lit
        }
      case INTEGER_LITERAL =>
        lit match {
          case x if x.endsWith("I") => x.substring(0, x.length() - 1)
          case x if x.endsWith("L") => x.substring(0, x.length() - 1)
          case _ => lit
        }
      case CHARACTER_LITERAL =>
        lit
      case _ =>
        "0"
    }
  }
  def isString: Boolean = constant.tokenType == STRING_LITERAL
  def isInt: Boolean = constant.tokenType == INTEGER_LITERAL && !constant.text.endsWith("L")
  def isLong: Boolean = constant.tokenType == INTEGER_LITERAL && !constant.text.endsWith("I")
  def isFloat: Boolean = constant.tokenType == FLOATING_POINT_LITERAL && !constant.text.endsWith("D")
  def isDouble: Boolean = constant.tokenType == FLOATING_POINT_LITERAL && !constant.text.endsWith("F")
  def getInt: Int = getLiteral.toInt
  def getLong: Long = getLiteral.toLong
  def getFloat: Float = getLiteral.toFloat
  def getDouble: Double = getLiteral.toDouble
  def getString: String = getLiteral
}

case class UnaryExpression(
  op: Token,
  unary: VarSymbol)
    extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(op, unary)
}

case class BinaryExpression(
  left: VarSymbol,
  op: Token,
  right: Either[VarSymbol, Either[LiteralExpression, NullExpression]])
    extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(left, op, right)
}

case class CmpExpression(
    cmp: Token,
    lparen: Token,
    var1Symbol: VarSymbol,
    comma: Token,
    var2Symbol: VarSymbol,
    rparen: Token) extends Expression with RHS {
  lazy val tokens: IList[Token] = flatten(cmp, lparen, var1Symbol, comma, var2Symbol, rparen)
  def paramType: JawaType = {
    cmp.text match {
      case "fcmpl" | "fcmpg" => JavaKnowledge.FLOAT
      case "dcmpl" | "dcmpg" => JavaKnowledge.DOUBLE
      case "lcmp" => JavaKnowledge.LONG
    }
  }
}

case class CatchClause(
    catchToken: Token,
    typ: Type,
    range: CatchRange,
    goto: Token,
    targetLocation: LocationSymbol,
    semi: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(catchToken, typ, range, goto, targetLocation, semi)
  def from: String = range.fromLocation.location
  def to: String = range.toLocation.location
}

case class CatchRange(
    at: Token,
    lbracket: Token,
    fromLocation: LocationSymbol,
    range: Token,
    toLocation: LocationSymbol,
    rbracket: Token) extends JawaAstNode {
  lazy val tokens: IList[Token] = flatten(at, lbracket, fromLocation, range, toLocation, rbracket)
}
