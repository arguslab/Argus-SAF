/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast

import org.argus.jawa.compiler.lexer.Token
import org.argus.jawa.compiler.lexer.Tokens._
import org.argus.jawa.compiler.parser._
import org.argus.jawa.compiler.util.CaseClassReflector
import org.argus.jawa.core.io.{NoPosition, Position}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{DefaultReporter, JavaKnowledge, JawaType, Signature}

import scala.language.implicitConversions

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
sealed trait JawaAstNode extends CaseClassReflector with JavaKnowledge {
  
  //for CompilationUnit it will be null
  var enclosingTopLevelClass: TypeDefSymbol = _
  
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
    case _: Position               => Nil
    case true | false | Nil | None => Nil
  }

  def toCode: String

  var pos: Position = NoPosition
}

sealed trait ParsableAstNode extends JawaAstNode

case class CompilationUnit(topDecls: IList[ClassOrInterfaceDeclaration]) extends ParsableAstNode {
  def localTypResolved: Boolean = topDecls.forall(_.methods.forall(_.resolvedBody.locals.forall(_.typOpt.isDefined)))
  def toCode: String = topDecls.map{td => td.toCode}.mkString("\n")
}

sealed trait Declaration extends JawaAstNode {
  def annotations: IList[Annotation]
  def accessModifier: String = {
    annotations.find { a => a.key == "AccessFlag" } match{
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
  def typ: JawaType = getTypeFromJawaName(id.text)
  def toCode: String = id.rawText
}

case class TypeSymbol(id: Token) extends RefSymbol with ClassSym {
  def typ: JawaType = getTypeFromJawaName(id.text)
  def toCode: String = id.rawText
}

case class MethodDefSymbol(id: Token) extends DefSymbol with MethodSym {
  def baseType: JawaType = signature.getClassType
  var signature: Signature = _
  def methodName: String = id.text
  def toCode: String = id.rawText
}

case class MethodNameSymbol(id: Token) extends RefSymbol with MethodSym {
  def baseType: JawaType = signature.getClassType
  var signature: Signature = _
  def methodName: String = id.text
  def toCode: String = id.rawText
}

case class FieldDefSymbol(id: Token) extends DefSymbol with FieldSym {
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def toCode: String = id.rawText
}

case class FieldNameSymbol(id: Token) extends RefSymbol with FieldSym {
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def toCode: String = id.rawText
}

case class SignatureSymbol(id: Token) extends RefSymbol with MethodSym {
  def signature: Signature = new Signature(id.text)
  def methodName: String = signature.methodName
  def toCode: String = id.rawText
}

case class VarDefSymbol(id: Token) extends DefSymbol with VarSym {
  def varName: String = id.text
  var owner: MethodDeclaration = _
  def toCode: String = id.rawText
}

case class VarSymbol(id: Token) extends RefSymbol with VarSym {
  def varName: String = id.text
  var owner: MethodDeclaration = _
  def toCode: String = id.rawText
}

/**
 * LocationSymbol is following form: #L00001. or just #
 */
case class LocationDefSymbol(id: Token) extends DefSymbol with LocationSym {
  def location: String = {
    if(id.text == "#") id.text
    else id.text.substring(1, id.text.length() - 1)
  }
  var owner: MethodDeclaration = _
  def toCode: String = id.rawText
}

/**
 * JumpLocationSymbol is following form: L00001
 */
case class LocationSymbol(id: Token) extends RefSymbol with LocationSym {
  def location: String = id.text
  var owner: MethodDeclaration = _
  def toCode: String = id.rawText
}

case class ClassOrInterfaceDeclaration(
    cityp: TypeDefSymbol,
    annotations: IList[Annotation],
    extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses],
    instanceFieldDeclarationBlock: InstanceFieldDeclarationBlock,
    staticFields: IList[StaticFieldDeclaration],
    methods: IList[MethodDeclaration]) extends Declaration with ParsableAstNode {
  def isInterface: Boolean = {
    annotations.exists { a => a.key == "kind" && a.value == "interface" }
  }
  def parents: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.parents case None => ilistEmpty}
  def superClassOpt: Option[JawaType] = extendsAndImplementsClausesOpt match{case Some(e) => e.superClassOpt case None => None}
  def interfaces: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.interfaces case None => ilistEmpty}
  def fields: IList[Field with Declaration] = instanceFieldDeclarationBlock.instanceFields ++ staticFields
  def instanceFields: IList[InstanceFieldDeclaration] = instanceFieldDeclarationBlock.instanceFields
  def typ: JawaType = cityp.typ
  def toCode: String = {
    val staticPart = if(staticFields.isEmpty) "" else s"${staticFields.map(sf => sf.toCode).mkString("\n")}\n"
    val methodPart = if(methods.isEmpty) "" else s"${methods.map(m => m.toCode).mkString("\n")}"
    s"record ${cityp.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}${extendsAndImplementsClausesOpt match {case Some(eic) => " " + eic.toCode case None => ""}}\n${instanceFieldDeclarationBlock.toCode}\n$staticPart$methodPart"
  }
}

case class Annotation(
    annotationID: Token,
    annotationValueOpt: Option[AnnotationValue]) extends JawaAstNode {
  def key: String = annotationID.text
  def value: String = annotationValueOpt.map(_.value).getOrElse("")
  def toCode: String = {
    s"@${annotationID.rawText}${annotationValueOpt match {case Some(av) => " " + av.toCode case None => ""}}"
  }
}

sealed trait AnnotationValue extends JawaAstNode {
  def value: String
}

case class TypeExpressionValue(
    typExp: TypeExpression) extends AnnotationValue {
  def value: String = typExp.typ.name
  def toCode: String = typExp.toCode
}

case class SymbolValue(
    sym: JawaSymbol) extends AnnotationValue {
  def value: String = sym.id.text
  def toCode: String = sym.toCode
}

case class TokenValue(
    token: Token) extends AnnotationValue {
  def value: String = token.text
  def toCode: String = token.rawText
}

case class StatementValue(statements: IList[Statement]) extends AnnotationValue {
  def value: String = statements.map{statement => statement.toCode}.mkString(", ")
  def toCode: String = s"($value)"
}

case class ExtendsAndImplementsClauses(parentTyps: IList[ExtendAndImplement]) extends JawaAstNode {
  require(parentTyps.count(t => t.isExtend) <= 1)
  def parents: IList[JawaType] = parentTyps.map(t => t.typ)
  def superClassOpt: Option[JawaType] = parentTyps.find(t => t.isExtend).map(t => t.typ)
  def interfaces: IList[JawaType] = parentTyps.filter(t => t.isImplement).map(t => t.typ)
  def toCode: String = s"extends ${parentTyps.map(t => t.toCode).mkString(", ")}"
}

case class ExtendAndImplement(
    parentTyp: TypeSymbol,
    annotations: IList[Annotation])extends JawaAstNode {
  def typ: JawaType = parentTyp.typ
  def isExtend: Boolean = annotations.exists { a => a.key == "kind" && a.value == "class" }
  def isImplement: Boolean = annotations.exists { a => a.key == "kind" && a.value == "interface" }
  def toCode: String = s"${parentTyp.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}"
}

sealed trait Field extends JawaAstNode {
  def typ: Type
  def fieldSymbol: FieldDefSymbol
  def FQN: String
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def isStatic: Boolean
}

case class InstanceFieldDeclarationBlock(instanceFields: IList[InstanceFieldDeclaration]) extends JawaAstNode {
  def toCode: String = {
    val instancePart = if(instanceFields.isEmpty) "" else s"\n  ${instanceFields.map(f => f.toCode).mkString("\n  ")}\n"
    s"{$instancePart}"
  }
}

case class InstanceFieldDeclaration(
    typ: Type, 
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation]) extends Field with Declaration {
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = false
  def toCode: String = s"${typ.toCode} ${fieldSymbol.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}".trim + ";"
}

case class StaticFieldDeclaration(
    typ: Type,
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation]) extends Field with Declaration {
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = true
  def toCode: String = s"global ${typ.toCode} ${fieldSymbol.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}".trim + ";"
}

case class TypeExpression(typ_ : Type) extends JawaAstNode {
  def typ: JawaType = typ_.typ
  def toCode: String = s"^${typ_.toCode}"
}

case class Type(base: Either[TypeSymbol, Token], typeFragments: IList[TypeFragment]) extends JawaAstNode {
  def dimensions: Int = typeFragments.size
  def baseType: JawaType = 
    base match {
      case Left(ts) => ts.typ
      case Right(t) => getTypeFromJawaName(t.text)
    }
  def typ: JawaType = getType(baseType.baseTyp, dimensions)
  def toCode: String = s"${base match {case Left(ts) => ts.toCode case Right(t) => t.rawText}}${typeFragments.map(tf => tf.toCode).mkString("")}"
}

case class TypeFragment(position: Position) extends JawaAstNode {
  pos = position
  def toCode: String = "[]"
}

case class MethodDeclaration(
    returnType: Type,
    methodSymbol: MethodDefSymbol,
    paramClause: ParamClause,
    annotations: IList[Annotation],
    var body: Body) extends Declaration with ParsableAstNode {
  def isConstructor: Boolean = isJawaConstructor(name)
  def name: String = methodSymbol.id.text.substring(methodSymbol.id.text.lastIndexOf(".") + 1)
  def owner: String = signature.getClassName
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
  def toCode: String = {
    s"procedure ${returnType.toCode} ${methodSymbol.toCode}${paramClause.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}\n${body.toCode}"
  }
}

case class ParamClause(params: IList[Param]) extends JawaAstNode {
  def thisParam: Option[Param] = params.find(x => x.isThis)
  def param(i: Int): Param =
    i match {
      case n if n >= 0 && n < paramlist.size => paramlist(n)
      case _ => throw new IndexOutOfBoundsException("List size " + paramlist.size + " but index " + i)
    }
  def paramlist: IList[Param] = params.filterNot(_.isThis)
  def toCode: String = s"(${params.map(p => p.toCode).mkString(", ")})"
}

case class Param(
    typ: Type, 
    paramSymbol: VarDefSymbol, 
    annotations: IList[Annotation]) extends JawaAstNode {
  def isThis: Boolean = annotations.exists { a => a.key == "kind" && a.value == "this" }
  def isObject: Boolean = annotations.exists { a => a.key == "kind" && (a.value == "this" || a.value == "object") }
  def name: String = paramSymbol.id.text
  def toCode: String = s"${typ.toCode} ${paramSymbol.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}"
}

sealed trait Body extends ParsableAstNode

case class UnresolvedBody(bodytokens: IList[Token]) extends Body {
  def resolve: ResolvedBody = JawaParser.parse[Body](bodytokens, resolveBody = true, new DefaultReporter, classOf[Body]) match {
    case Left(body) => body.asInstanceOf[ResolvedBody]
    case Right(t) => throw t
  }
  def toCode: String = "{}"
}

case class ResolvedBody(
    locals: IList[LocalVarDeclaration], 
    locations: IList[Location], 
    catchClauses: IList[CatchClause]) extends Body {
  def getCatchClauses(index: Int): IList[CatchClause] = {
    catchClauses.filter{ cc =>
      index >= cc.range.fromLocation.locationIndex && index <= cc.range.toLocation.locationIndex
    }
  }
  def location(locUri: String): Location = locations.find(l => l.locationUri.equals(locUri)).get
  def location(locIndex: Int): Location = locations(locIndex)
  def toCode: String = {
    val localPart = if(locals.isEmpty) "" else s"    ${locals.map(l => l.toCode).mkString("\n    ")}\n\n"
    val locationPart = if(locations.isEmpty) "" else s"    ${locations.map(l => l.toCode).mkString("\n    ")}\n"
    val ccPart = if(catchClauses.isEmpty) "" else s"    ${catchClauses.map(cc => cc.toCode).mkString("\n    ")}\n}"
    s"{$localPart$locationPart$ccPart}"
  }
}

case class LocalVarDeclaration(
    typOpt: Option[Type],
    varSymbol: VarDefSymbol) extends Declaration {
  def annotations: IList[Annotation] = ilistEmpty
  def typ: JawaType = typOpt match {
    case Some(t) => t.typ
    case None => JAVA_TOPLEVEL_OBJECT_TYPE
  }
  def toCode: String = s"${typOpt match {case Some(t) => t.toCode + " " case None => ""}}${varSymbol.toCode}"
}

case class Location(
    locationSymbol: LocationDefSymbol, 
    statement: Statement) extends ParsableAstNode {
  def locationUri: String = {
    if(locationSymbol.id.length <= 1) ""
    else locationSymbol.location
  }
  def locationIndex: Int = locationSymbol.locationIndex
  def toCode: String = "  " + s"${locationSymbol.toCode}  ${statement.toCode}".trim + ";"
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
    lhsOpt: Option[CallLhs],
    rhs: CallRhs,
    annotations: IList[Annotation]) extends Assignment with Jump {
  //default is virtual call
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("virtual")
  def signature: Signature = new Signature(annotations.find { a => a.key == "signature" }.get.value)
  def isStatic: Boolean = kind == "static"
  def isVirtual: Boolean = kind == "virtual"
  def isSuper: Boolean = kind == "super"
  def isDirect: Boolean = kind == "direct"
  def isInterface: Boolean = kind == "interface"
  def recvVarOpt: Option[VarSymbol] = if(isStatic) None else Some(rhs.argClause.varSymbols.head)
  def argVars: IList[VarSymbol] = if(isStatic) rhs.argClause.varSymbols else rhs.argClause.varSymbols.tail
  def argVar(i: Int): VarSymbol = {
    i match {
      case n if n >= 0 && n < argVars.size => argVars(n)
      case _ => throw new IndexOutOfBoundsException("List size " + argVars.size + " but index " + i)
    }
  }
  def recvOpt: Option[String] = if(isStatic) None else Some(rhs.argClause.arg(0))
  def args: IList[String] = if(isStatic) rhs.argClause.varSymbols.map(_.id.text) else rhs.argClause.varSymbols.tail.map(_.id.text)
  def arg(i: Int): String = {
    i match {
      case n if n >= 0 && n < args.size => args(n)
      case _ => throw new IndexOutOfBoundsException("List size " + args.size + " but index " + i)
    }
  }

  override def getLhs: Option[Expression with LHS] = lhsOpt
  override def getRhs: Expression with RHS = rhs
  def toCode: String = s"call ${lhsOpt match {case Some(lhs) => lhs.toCode + ":= " case None => ""}}${rhs.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}"
}

case class CallLhs(lhs: VarSymbol) extends Expression with LHS {
  def toCode: String = lhs.toCode
}

case class CallRhs(
    methodNameSymbol: MethodNameSymbol,
    argClause: ArgClause) extends Expression with RHS {
  def toCode: String = s"${methodNameSymbol.toCode}${argClause.toCode}"
}

case class ArgClause(varSymbols: IList[VarSymbol]) extends JawaAstNode {
  def arg(i: Int): String = i match {
    case n if n >= 0 && n < varSymbols.size => varSymbols(n).id.text
    case _ => throw new IndexOutOfBoundsException("List size " + varSymbols.size + " but index " + i)
  }
  def toCode: String = s"(${varSymbols.map(vs => vs.toCode).mkString(", ")})"
}

case class AssignmentStatement(
    lhs: Expression with LHS,
    rhs: Expression with RHS,
    annotations: IList[Annotation]) extends Assignment {
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse({if(rhs.isInstanceOf[NewExpression])"object" else ""})
  def typOpt: Option[JawaType] = annotations.find { a => a.key == "type" }.map(_.annotationValueOpt.get.asInstanceOf[TypeExpressionValue].typExp.typ)

  override def getLhs: Option[Expression with LHS] = Some(lhs)

  override def getRhs: Expression with RHS = rhs
  def toCode: String = s"${lhs.toCode}:= ${rhs.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}"
}

case class ThrowStatement(varSymbol: VarSymbol) extends Statement {
  def toCode: String = s"throw ${varSymbol.toCode}"
}

case class IfStatement(
    cond: BinaryExpression,
    targetLocation: LocationSymbol) extends Jump {
  def toCode: String = s"if ${cond.toCode} then goto ${targetLocation.toCode}"
}

case class GotoStatement(targetLocation: LocationSymbol) extends Jump {
  def toCode: String = s"goto ${targetLocation.toCode}"
}

case class SwitchStatement(
    condition: VarSymbol,
    cases: IList[SwitchCase],
    defaultCaseOpt: Option[SwitchDefaultCase]) extends Jump {
  def toCode: String = s"switch ${condition.toCode}\n              ${cases.map(c => c.toCode).mkString("\n              ")}${defaultCaseOpt match {case Some(d) => "\n              " + d.toCode case None => ""}}"
}

case class SwitchCase(
    constant: Token,
    targetLocation: LocationSymbol) extends JawaAstNode {
  def toCode: String = s"| ${constant.rawText} => goto ${targetLocation.toCode}"
}

case class SwitchDefaultCase(targetLocation: LocationSymbol) extends JawaAstNode {
  def toCode: String = s"| else => goto ${targetLocation.toCode}"
}

case class ReturnStatement(
    varOpt: Option[VarSymbol],
    annotations: IList[Annotation]) extends Jump {
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("")
  def toCode: String = s"return${varOpt match {case Some(v) => " " + v.toCode case None => ""}} ${annotations.map(anno => anno.toCode).mkString(" ")}"
}

case class MonitorStatement(
    monitor: Token,
    varSymbol: VarSymbol) extends Statement {
  def isEnter: Boolean = monitor.tokenType == MONITOR_ENTER
  def isExit: Boolean = monitor.tokenType == MONITOR_EXIT
  def toCode: String = s"@${monitor.rawText} ${varSymbol.toCode}"
}

case class EmptyStatement(
    annotations: IList[Annotation]) extends Statement {
  def toCode: String = annotations.map(anno => anno.toCode).mkString(" ")
}

sealed trait Expression extends JawaAstNode

/** LHS expressions:
  *   AccessExpression
  *   CallLhs
  *   IndexingExpression
  *   NameExpression
  */
sealed trait LHS

/** RHS expressions:
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
  def name: String = 
    varSymbol match {
      case Left(v) => v.varName
      case Right(f) => f.FQN
    }
  def isStatic: Boolean = varSymbol.isRight
  def toCode: String = varSymbol match {case Left(vs) => vs.toCode case Right(fs) => fs.toCode}
}

case class ExceptionExpression(position: Position) extends Expression with RHS {
  var typ: JawaType = _
  pos = position
  def toCode: String = "Exception"
}

case class NullExpression(nul: Token) extends Expression with RHS {
  def toCode: String = nul.rawText
}

case class ConstClassExpression(typExp: TypeExpression) extends Expression with RHS {
  def toCode: String = s"constclass @type ${typExp.toCode}"
}

case class LengthExpression(varSymbol: VarSymbol) extends Expression with RHS {
  def toCode: String = s"length @variable ${varSymbol.toCode}"
}

case class IndexingExpression(
    varSymbol: VarSymbol,
    indices: IList[IndexingSuffix]) extends Expression with LHS with RHS {
  def base: String = varSymbol.varName
  def dimensions: Int = indices.size
  def toCode: String = s"${varSymbol.toCode}${indices.map(i => i.toCode).mkString("")}"
}

case class IndexingSuffix(index: Either[VarSymbol, LiteralExpression]) extends JawaAstNode {
  def toCode: String = s"[${index match {case Left(vs) => vs.toCode case Right(le) => le.toCode}}]"
}
    
case class AccessExpression(
    varSymbol: VarSymbol,
    fieldSym: FieldNameSymbol) extends Expression with LHS with RHS {
  def base: String = varSymbol.varName
  def fieldName: String = fieldSym.fieldName
  def toCode: String = s"${varSymbol.toCode}.${fieldSym.toCode}"
}

case class TupleExpression(constants: IList[LiteralExpression]) extends Expression with RHS {
  def integers: IList[Int] = constants.map(c => c.getInt)
  def toCode: String = s"(${constants.map(c => c.toCode).mkString(", ")})"
}

case class CastExpression(
    typ: Type,
    varSym: VarSymbol) extends Expression with RHS {
  def varName: String = varSym.varName
  def toCode: String = s"(${typ.toCode}) ${varSym.toCode}"
}

case class NewExpression(
    base: Either[TypeSymbol, Token],
    typeFragmentsWithInit: IList[TypeFragmentWithInit]) extends Expression with RHS {
  def dimensions: Int = typeFragmentsWithInit.size
  def baseType: JawaType =
    base match {
      case Left(ts) => ts.typ
      case Right(t) => getTypeFromJawaName(t.text)
    }
  def typ: JawaType = getType(baseType.baseTyp, dimensions)
  def toCode: String = s"new ${base match {case Left(ts) => ts.toCode case Right(t) => t.rawText}}${typeFragmentsWithInit.map(tf => tf.toCode).mkString("")}"
}

case class TypeFragmentWithInit(varSymbols: IList[VarSymbol]) extends JawaAstNode {
  def varNames: IList[String] = varSymbols.map(_.varName)
  def varName(i: Int): String = varNames(i)
  def toCode: String = s"[${varSymbols.map(vs => vs.toCode).mkString(", ")}]"
}

case class InstanceOfExpression(
    varSymbol: VarSymbol,
    typExp: TypeExpression) extends Expression with RHS {
  def toCode: String = s"instanceof @variable ${varSymbol.toCode} @type ${typExp.toCode}"
}

case class LiteralExpression(constant: Token) extends Expression with RHS {
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
  def toCode: String = constant.rawText
}

case class UnaryExpression(
  op: Token,
  unary: VarSymbol)
    extends Expression with RHS {
  def toCode: String = s"${op.rawText}${unary.toCode}"
}

case class BinaryExpression(
  left: VarSymbol,
  op: Token,
  right: Either[VarSymbol, Either[LiteralExpression, NullExpression]])
    extends Expression with RHS {
  def toCode: String = s"${left.toCode} ${op.rawText} ${right match {case Left(vs) => vs.toCode case Right(ln) => ln match {case Left(le) => le.toCode case Right(ne) => ne.toCode}}}"
}

case class CmpExpression(
    cmp: Token,
    var1Symbol: VarSymbol,
    var2Symbol: VarSymbol) extends Expression with RHS {
  def paramType: JawaType = {
    cmp.text match {
      case "fcmpl" | "fcmpg" => JavaKnowledge.FLOAT
      case "dcmpl" | "dcmpg" => JavaKnowledge.DOUBLE
      case "lcmp" => JavaKnowledge.LONG
    }
  }
  def toCode: String = s"${cmp.rawText}(${var1Symbol.toCode}, ${var2Symbol.toCode})"
}

case class CatchClause(
    typ: Type,
    range: CatchRange,
    targetLocation: LocationSymbol) extends JawaAstNode {
  def from: String = range.fromLocation.location
  def to: String = range.toLocation.location
  def toCode: String = s"  catch ${typ.toCode} ${range.toCode} goto ${targetLocation.toCode};"
}

case class CatchRange(
    fromLocation: LocationSymbol,
    toLocation: LocationSymbol) extends JawaAstNode {
  def toCode: String = s"@[${fromLocation.toCode}..${toLocation.toCode}]"
}