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

import com.github.javaparser.ast.stmt.BlockStmt
import org.argus.jawa.core.ast.classfile.BytecodeInstructions
import org.argus.jawa.core.compiler.lexer.{Keywords, Token, Tokens}
import org.argus.jawa.core.compiler.lexer.Tokens._
import org.argus.jawa.core.compiler.parser._
import org.argus.jawa.core.compiler.util.CaseClassReflector
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.{DefaultReporter, NoPosition, Position}
import org.argus.jawa.core.util._

import scala.language.implicitConversions
import scala.util.{Failure, Success}

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
    case xs: MList[_]              => xs.toList flatMap { immediateAstNodes }
    case Left(x)                   => immediateAstNodes(x)
    case Right(x)                  => immediateAstNodes(x)
    case (l, r)                    => immediateAstNodes(l) ++ immediateAstNodes(r)
    case (x, y, z)                 => immediateAstNodes(x) ++ immediateAstNodes(y) ++ immediateAstNodes(z)
    case _: Position               => Nil
    case _: BlockStmt              => Nil
    case true | false | Nil | None => Nil
  }

  def toCode: String

  override def toString: FileResourceUri = s"$toCode@$pos"

  def pos: Position
}

sealed trait ParsableAstNode extends JawaAstNode

case class CompilationUnit(topDecls: IList[ClassOrInterfaceDeclaration])(implicit val pos: Position) extends ParsableAstNode {
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

case class TypeDefSymbol(id: Token)(implicit val pos: Position) extends DefSymbol with ClassSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  def typ: JawaType = getTypeFromJawaName(id.text)
  def toCode: String = id.rawText
}

case class TypeSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with ClassSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  def typ: JawaType = getTypeFromJawaName(id.text)
  def toCode: String = id.rawText
}

case class MethodDefSymbol(id: Token)(implicit val pos: Position) extends DefSymbol with MethodSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  var signature: Signature = _
  def baseType: JawaType = signature.getClassType
  def methodName: String = id.text
  def toCode: String = id.rawText
}

case class MethodNameSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with MethodSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  var signature: Signature = _
  def baseType: JawaType = signature.getClassType
  def methodName: String = id.text
  def toCode: String = id.rawText
}

case class FieldDefSymbol(id: Token)(implicit val pos: Position) extends DefSymbol with FieldSym {
  def this(name: String, pos: Position) = this(Token({if(name.contains("@@")) Tokens.STATIC_ID else Tokens.ID}, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def toCode: String = id.rawText
}

case class FieldNameSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with FieldSym {
  def this(name: String, pos: Position) = this(Token({if(name.contains("@@")) Tokens.STATIC_ID else Tokens.ID}, pos, s"`$name`"))(pos)
  def this(name: String) = this(name, NoPosition)
  def FQN: String = id.text.replaceAll("@@", "")
  def baseType: JawaType = getClassTypeFromFieldFQN(FQN)
  def fieldName: String = getFieldNameFromFieldFQN(FQN)
  def toCode: String = id.rawText
}

case class SignatureSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with MethodSym {
  def this(sig: String, pos: Position) = this(Token(Tokens.ID, pos, s"`$sig`"))(pos)
  def this(sig: String) = this(sig, NoPosition)
  def this(sig: Signature) = this(sig.signature)
  def signature: Signature = new Signature(id.text)
  def methodName: String = signature.methodName
  def toCode: String = id.rawText
}

case class VarDefSymbol(id: Token)(implicit val pos: Position) extends DefSymbol with VarSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, {if(Keywords.isKeyWord(name)) s"`$name`" else name}))(pos)
  def this(name: String) = this(name, NoPosition)
  var owner: MethodDeclaration = _
  def varName: String = id.text
  def toCode: String = id.rawText
}

case class VarSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with VarSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, {if(Keywords.isKeyWord(name)) s"`$name`" else name}))(pos)
  def this(name: String) = this(name, NoPosition)
  var owner: MethodDeclaration = _
  def varName: String = id.text
  def toCode: String = id.rawText
}

/**
 * LocationSymbol is following form: #L00001. or just #
 */
case class LocationDefSymbol(id: Token)(implicit val pos: Position) extends DefSymbol with LocationSym {
  def this(name: String, pos: Position) = this(Token(Tokens.LOCATION_ID, pos, s"#$name."))(pos)
  def this(name: String) = this(name, NoPosition)
  var owner: MethodDeclaration = _
  def location: String = {
    if(id.text == "#") id.text
    else id.text.substring(1, id.text.length() - 1)
  }
  def toCode: String = id.rawText
}

/**
 * JumpLocationSymbol is following form: L00001
 */
case class LocationSymbol(id: Token)(implicit val pos: Position) extends RefSymbol with LocationSym {
  def this(name: String, pos: Position) = this(Token(Tokens.ID, pos, name))(pos)
  def this(name: String) = this(name, NoPosition)
  var owner: MethodDeclaration = _
  def location: String = id.text
  def toCode: String = id.rawText
}

case class ClassOrInterfaceDeclaration(
    cityp: TypeDefSymbol,
    annotations: IList[Annotation],
    extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses],
    instanceFields: IList[InstanceFieldDeclaration],
    staticFields: IList[StaticFieldDeclaration],
    methods: IList[MethodDeclaration])(implicit val pos: Position) extends Declaration with ParsableAstNode {
  def isInterface: Boolean = {
    annotations.exists { a => a.key == "kind" && a.value == "interface" }
  }
  def parents: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.parents case None => ilistEmpty}
  def superClassOpt: Option[JawaType] = extendsAndImplementsClausesOpt match{case Some(e) => e.superClassOpt case None => None}
  def interfaces: IList[JawaType] = extendsAndImplementsClausesOpt match {case Some(e) => e.interfaces case None => ilistEmpty}
  def fields: IList[Field with Declaration] = instanceFields ++ staticFields
  def typ: JawaType = cityp.typ
  def toCode: String = {
    val instancePart = if(instanceFields.isEmpty) "" else s"\n  ${instanceFields.map(f => f.toCode).mkString("\n  ")}\n"
    val staticPart = if(staticFields.isEmpty) "" else s"${staticFields.map(sf => sf.toCode).mkString("\n")}\n"
    val methodPart = if(methods.isEmpty) "" else s"${methods.map(m => m.toCode).mkString("\n")}"
    s"record ${cityp.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}${extendsAndImplementsClausesOpt match {case Some(eic) => " " + eic.toCode case None => ""}}\n{$instancePart}\n$staticPart$methodPart"
  }
}

case class Annotation(
    annotationID: Token,
    annotationValueOpt: Option[AnnotationValue])(implicit val pos: Position) extends JawaAstNode {
  def this(key: String, valueOpt: Option[AnnotationValue]) = this(Token(Tokens.ID, NoPosition, key), valueOpt)(NoPosition)
  def this(key: String, value: AnnotationValue) = this(key, Some(value))
  def this(key: String) = this(key, None)
  def key: String = annotationID.text
  def value: String = annotationValueOpt.map(_.value).getOrElse("")
  def toCode: String = {
    s"@${annotationID.rawText}${annotationValueOpt match {case Some(av) => " " + av.toCode case None => ""}}"
  }
}

sealed trait AnnotationValue extends JawaAstNode {
  def value: String
}

case class TypeExpressionValue(typExp: TypeExpression)(implicit val pos: Position) extends AnnotationValue {
  def this(str: String, d: Int, pos: Position) = this(new TypeExpression(str, d, pos))(pos)
  def this(str: String, d: Int) = this(str, d, NoPosition)
  def this(str: String) = this(str, 0)
  def value: String = typExp.typ.name
  def toCode: String = typExp.toCode
}

case class SymbolValue(sym: JawaSymbol)(implicit val pos: Position) extends AnnotationValue {
  def value: String = sym.id.text
  def toCode: String = sym.toCode
}

case class TokenValue(token: Token)(implicit val pos: Position) extends AnnotationValue {
  def this(str: String, pos: Position) = this(Token(Tokens.ID, pos, str))(pos)
  def this(str: String) = this(str, NoPosition)
  def value: String = token.text
  def toCode: String = token.rawText
}

case class StatementValue(statements: IList[Statement])(implicit val pos: Position) extends AnnotationValue {
  def value: String = statements.map{statement => statement.toCode}.mkString(", ")
  def toCode: String = s"($value)"
}

case class ExtendsAndImplementsClauses(parentTyps: IList[ExtendAndImplement])(implicit val pos: Position) extends JawaAstNode {
  require(parentTyps.count(t => t.isExtend) <= 1)
  def parents: IList[JawaType] = parentTyps.map(t => t.typ)
  def superClassOpt: Option[JawaType] = parentTyps.find(t => t.isExtend).map(t => t.typ)
  def interfaces: IList[JawaType] = parentTyps.filter(t => t.isImplement).map(t => t.typ)
  def toCode: String = s"extends ${parentTyps.map(t => t.toCode).mkString(", ")}"
}

case class ExtendAndImplement(
    parentTyp: TypeSymbol,
    annotations: IList[Annotation])(implicit val pos: Position) extends JawaAstNode {
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

case class InstanceFieldDeclaration(
    typ: Type,
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation])(implicit val pos: Position) extends Field with Declaration {
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = false
  def toCode: String = s"${typ.toCode} ${fieldSymbol.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}".trim + ";"
}

case class StaticFieldDeclaration(
    typ: Type,
    fieldSymbol: FieldDefSymbol,
    annotations: IList[Annotation])(implicit val pos: Position) extends Field with Declaration {
  def FQN: String = fieldSymbol.FQN
  def isStatic: Boolean = true
  def toCode: String = s"global ${typ.toCode} ${fieldSymbol.toCode} ${annotations.map(anno => anno.toCode).mkString(" ")}".trim + ";"
}

case class TypeExpression(typ_ : Type)(implicit val pos: Position) extends JawaAstNode {
  def this(str: String, d: Int, pos: Position) = this(new Type(str, d, pos))(pos)
  def this(str: String, d: Int) = this(str, d, NoPosition)
  def this(str: String) = this(str, 0)
  def this(t: JawaType) = this(t.baseTyp, t.dimensions)
  def typ: JawaType = typ_.typ
  def toCode: String = s"^${typ_.toCode}"
}

case class Type(base: TypeSymbol, typeFragments: IList[TypeFragment])(implicit val pos: Position) extends JawaAstNode {
  def this(str: String, d: Int, pos: Position) = this(new TypeSymbol(str, pos), (0 until d).map(_ => TypeFragment()(pos)).toList)(pos)
  def this(str: String, d: Int) = this(str, d, NoPosition)
  def this(str: String) = this(str, 0)
  def this(t: JawaType) = this(t.baseTyp, t.dimensions)
  def dimensions: Int = typeFragments.size
  def baseType: JawaType =  base.typ
  def typ: JawaType = getType(baseType.baseTyp, dimensions)
  def toCode: String = s"${base.toCode}${typeFragments.map(tf => tf.toCode).mkString("")}"
}

case class TypeFragment()(implicit val pos: Position) extends JawaAstNode {
  def toCode: String = "[]"
}

case class MethodDeclaration(
    returnType: Type,
    methodSymbol: MethodDefSymbol,
    params: IList[Parameter],
    annotations: IList[Annotation],
    var body: Body)(implicit val pos: Position) extends Declaration with ParsableAstNode {
  def isConstructor: Boolean = isJawaConstructor(name)
  def name: String = methodSymbol.id.text.substring(methodSymbol.id.text.lastIndexOf(".") + 1)
  def owner: String = signature.getClassName
  def signature: Signature = new Signature(annotations.find { a => a.key == "signature" }.get.value)
  def thisParam: Option[Parameter] = params.find(x => x.isThis)
  def param(i: Int): Parameter = i match {
    case n if n >= 0 && n < paramList.size => paramList(n)
    case _ => throw new IndexOutOfBoundsException("List size " + paramList.size + " but index " + i)
  }
  def paramList: IList[Parameter] = params.filterNot(_.isThis)
  def resolvedBody: ResolvedBody = body match {
    case rb: ResolvedBody => rb
    case ub: Body with Unresolved =>
      body = ub.resolve(signature)
      body.asInstanceOf[ResolvedBody]
  }
  def toCode: String = {
    val annoPart = annotations.map(anno => anno.toCode).mkString(" ")
    s"procedure ${returnType.toCode} ${methodSymbol.toCode}(${params.map(p => p.toCode).mkString(", ")}) $annoPart".trim + "\n" + resolvedBody.toCode
  }
}

case class Parameter(
    typ: Type,
    paramSymbol: VarDefSymbol,
    annotations: IList[Annotation])(implicit val pos: Position) extends JawaAstNode {
  def this(t: JawaType, name: String, annotations: IList[Annotation]) = this(new Type(t), new VarDefSymbol(name), annotations)(NoPosition)
  def isThis: Boolean = annotations.exists { a => a.key == "kind" && a.value == "this" }
  def isObject: Boolean = annotations.exists { a => a.key == "kind" && (a.value == "this" || a.value == "object") }
  def name: String = paramSymbol.id.text
  def toCode: String = {
    val annoPart = annotations.map(anno => anno.toCode).mkString(" ")
    s"${typ.toCode} ${paramSymbol.toCode} $annoPart".trim
  }
}

sealed trait Body extends ParsableAstNode

sealed trait Unresolved {
  def resolve(sig: Signature): ResolvedBody
}

case class UnresolvedBodyJawa(bodytokens: IList[Token])(implicit val pos: Position) extends Body with Unresolved {
  def resolve(sig: Signature): ResolvedBody = JawaParser.parse[Body](bodytokens, resolveBody = true, new DefaultReporter, classOf[Body]) match {
    case Success(body) => body.asInstanceOf[ResolvedBody]
    case Failure(t) => throw t
  }
  def toCode: String = "{}"
}

//case class UnresolvedBodyJava(bodyBlock: BlockStmt)(implicit val pos: Position, cr: ClassResolver) extends Body with Unresolved {
//  def resolve(sig: Signature): ResolvedBody = {
//    cr.processBody(sig, bodyBlock)
//  }
//  def toCode: String = "{}"
//}

case class UnresolvedBodyBytecode(bytecode: BytecodeInstructions)(implicit val pos: Position) extends Body with Unresolved {
  def resolve(sig: Signature): ResolvedBody = {
    bytecode.genJawa
  }
  def toCode: String = "{}"
}

case class ResolvedBody(
    locals: IList[LocalVarDeclaration],
    locations: IList[Location],
    catchClauses: IList[CatchClause])(implicit val pos: Position) extends Body {
  def getCatchClauses(index: Int): IList[CatchClause] = {
    catchClauses.filter{ cc =>
      index >= cc.range.fromLocation.locationIndex && index <= cc.range.toLocation.locationIndex
    }
  }
  def location(locUri: String): Location = locations.find(l => l.locationUri.equals(locUri)).getOrElse(throw new RuntimeException(s"Location uri $locUri not found in \n$toCode"))
  def location(locIndex: Int): Location = locations.lift(locIndex).getOrElse(throw new RuntimeException(s"Location index $locIndex not found in \n$toCode"))
  def toCode: String = {
    val localPart = if(locals.isEmpty) "" else s"    ${locals.map(l => l.toCode).mkString("\n    ")}\n\n"
    val locationPart = if(locations.isEmpty) "" else s"    ${locations.map(l => l.toCode).mkString("\n    ")}\n\n"
    val ccPart = if(catchClauses.isEmpty) "" else s"    ${catchClauses.map(cc => cc.toCode).mkString("\n    ")}\n}"
    s"{\n$localPart$locationPart$ccPart}"
  }
}

case class LocalVarDeclaration(
    typOpt: Option[Type],
    varSymbol: VarDefSymbol)(implicit val pos: Position) extends Declaration {
  def this(t: JawaType, name: String) = this(Some(new Type(t)), new VarDefSymbol(name))(NoPosition)
  def annotations: IList[Annotation] = ilistEmpty
  def typ: JawaType = typOpt match {
    case Some(t) => t.typ
    case None => JavaKnowledge.OBJECT
  }
  def toCode: String = s"${typOpt match {case Some(t) => t.toCode + " " case None => ""}}${varSymbol.toCode};"
}

case class Location(
    locationSymbol: LocationDefSymbol,
    statement: Statement)(implicit val pos: Position) extends ParsableAstNode {
  def this(loc: String, statement: Statement) = this(new LocationDefSymbol(loc), statement)(NoPosition)
  def locationUri: String = {
    if(locationSymbol.id.length <= 1) ""
    else locationSymbol.location
  }
  def locationIndex: Int = locationSymbol.locationIndex
  def toCode: String = s"${locationSymbol.toCode}  ${statement.toCode}".trim
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
    lhsOpt: Option[VariableNameExpression],
    rhs: CallRhs,
    annotations: IList[Annotation])(implicit val pos: Position) extends Assignment with Jump {
  def this(retVar: Option[String], methodName: String, argNames: IList[String], sig: Signature, kind: String) =
    this(
      retVar.map(r => new VariableNameExpression(r)),
      new CallRhs(methodName, argNames),
      List(
        new Annotation("signature", SymbolValue(new SignatureSymbol(sig))(NoPosition)),
        new Annotation("kind", new TokenValue(kind))
      )
    )(NoPosition)
  //default is virtual call
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("virtual")
  def signature: Signature = new Signature(annotations.find { a => a.key == "signature" }.get.value)
  def isStatic: Boolean = kind == "static"
  def isVirtual: Boolean = kind == "virtual"
  def isSuper: Boolean = kind == "super"
  def isDirect: Boolean = kind == "direct"
  def isInterface: Boolean = kind == "interface"
  def recvVarOpt: Option[VarSymbol] = if(isStatic) None else Some(rhs.varSymbols.head)
  def argVars: IList[VarSymbol] = if(isStatic) rhs.varSymbols else rhs.varSymbols.tail
  def argVar(i: Int): VarSymbol = {
    i match {
      case n if n >= 0 && n < argVars.size => argVars(n)
      case _ => throw new IndexOutOfBoundsException("List size " + argVars.size + " but index " + i)
    }
  }
  def recvOpt: Option[String] = if(isStatic) None else Some(rhs.arg(0))
  def args: IList[String] = if(isStatic) rhs.varSymbols.map(_.id.text) else rhs.varSymbols.tail.map(_.id.text)
  def arg(i: Int): String = {
    i match {
      case n if n >= 0 && n < args.size => args(n)
      case _ => throw new IndexOutOfBoundsException("List size " + args.size + " but index " + i)
    }
  }

  override def getLhs: Option[Expression with LHS] = lhsOpt
  override def getRhs: Expression with RHS = rhs
  def toCode: String = {
    val lhsPart = lhsOpt match {
      case Some(lhs) => lhs.toCode + ":= "
      case None => ""
    }
    val rhsPart = rhs.toCode
    val annoPart = annotations.map(anno => anno.toCode).mkString(" ")
    s"call $lhsPart$rhsPart $annoPart".trim + ";"
  }
}

case class CallRhs(
    methodNameSymbol: MethodNameSymbol,
    varSymbols: IList[VarSymbol])(implicit val pos: Position) extends Expression with RHS {
  def this(name: String, argNames: IList[String]) = this(new MethodNameSymbol(name), argNames.map(n => new VarSymbol(n)))(NoPosition)
  def arg(i: Int): String = i match {
    case n if n >= 0 && n < varSymbols.size => varSymbols(n).id.text
    case _ => throw new IndexOutOfBoundsException("List size " + varSymbols.size + " but index " + i)
  }
  def toCode: String = s"${methodNameSymbol.toCode}(${varSymbols.map(vs => vs.toCode).mkString(", ")})"
}

case class AssignmentStatement(
    lhs: Expression with LHS,
    rhs: Expression with RHS,
    annotations: IList[Annotation])(implicit val pos: Position) extends Assignment {
  def this(lName: String, rName: String, annotations: IList[Annotation]) = this(new VariableNameExpression(lName), new VariableNameExpression(rName), annotations)(NoPosition)
  def this(lName: String, i: Int) = this(new VariableNameExpression(lName), new LiteralExpression(i), ilistEmpty)(NoPosition)
  def this(lName: String, l: Long) = this(new VariableNameExpression(lName), new LiteralExpression(l), ilistEmpty)(NoPosition)
  def this(lName: String, f: Float) = this(new VariableNameExpression(lName), new LiteralExpression(f), ilistEmpty)(NoPosition)
  def this(lName: String, d: Double) = this(new VariableNameExpression(lName), new LiteralExpression(d), ilistEmpty)(NoPosition)
  def this(lName: String, rExpr: Expression with RHS, annotations: IList[Annotation]) = this(new VariableNameExpression(lName), rExpr, annotations)(NoPosition)
  def this(lExpr: Expression with LHS, rName: String, annotations: IList[Annotation]) = this(lExpr, new VariableNameExpression(rName) , annotations)(NoPosition)
  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse({if(rhs.isInstanceOf[Expression with New])"object" else ""})

  override def getLhs: Option[Expression with LHS] = Some(lhs)

  override def getRhs: Expression with RHS = rhs
  def toCode: String = {
    val annoPart = annotations.map(anno => anno.toCode).mkString(" ")
    s"${lhs.toCode}:= ${rhs.toCode} $annoPart".trim + ";"
  }
}

case class ThrowStatement(varSymbol: VarSymbol)(implicit val pos: Position) extends Statement {
  def this(name: String) = this(new VarSymbol(name))(NoPosition)
  def toCode: String = s"throw ${varSymbol.toCode};"
}

case class IfStatement(
    cond: BinaryExpression,
    targetLocation: LocationSymbol)(implicit val pos: Position) extends Jump {
  def this(cond: BinaryExpression, label: String) = this(cond, new LocationSymbol(label))(NoPosition)
  def toCode: String = s"if ${cond.toCode} then goto ${targetLocation.toCode};"
}

case class GotoStatement(targetLocation: LocationSymbol)(implicit val pos: Position) extends Jump {
  def this(target: String) = this(new LocationSymbol(target))(NoPosition)
  def toCode: String = s"goto ${targetLocation.toCode};"
}

case class SwitchStatement(
    condition: VarSymbol,
    cases: IList[SwitchCase],
    defaultCaseOpt: Option[SwitchDefaultCase])(implicit val pos: Position) extends Jump {
  def this(cond: String, cases: IList[SwitchCase], default: SwitchDefaultCase) = this(new VarSymbol(cond), cases, Some(default))(NoPosition)
  def this(cond: String, cases: IList[SwitchCase]) = this(new VarSymbol(cond), cases, None)(NoPosition)
  def toCode: String = s"switch ${condition.toCode}\n              ${cases.map(c => c.toCode).mkString("\n              ")}${defaultCaseOpt match {case Some(d) => "\n              " + d.toCode case None => ""}};"
}

case class SwitchCase(
    constant: Token,
    targetLocation: LocationSymbol)(implicit val pos: Position) extends JawaAstNode {
  def this(i: Int, target: String) = this(Token(Tokens.INTEGER_LITERAL, NoPosition, s"$i"), new LocationSymbol(target))(NoPosition)
  def toCode: String = s"| ${constant.rawText} => goto ${targetLocation.toCode}"
}

case class SwitchDefaultCase(targetLocation: LocationSymbol)(implicit val pos: Position) extends JawaAstNode {
  def this(target: String) = this(new LocationSymbol(target))(NoPosition)
  def toCode: String = s"| else => goto ${targetLocation.toCode}"
}

case class ReturnStatement(
    varOpt: Option[VarSymbol],
    annotations: IList[Annotation])(implicit val pos: Position) extends Jump {
  def this() = this(None, List(new Annotation("kind", new TokenValue("void"))))(NoPosition)
  def this(name: String, annotations: IList[Annotation]) = this(Some(new VarSymbol(name)), annotations)(NoPosition)
  def this(name: String) = this(name, ilistEmpty)

  def kind: String = annotations.find { a => a.key == "kind" }.map(_.value).getOrElse("")
  def toCode: String = {
    val varPart = varOpt match {case Some(v) => " " + v.toCode case None => ""}
    val annoPart = annotations.map(anno => anno.toCode).mkString(" ")
    s"return$varPart $annoPart".trim + ";"
  }
}

case class MonitorStatement(
    monitor: Token,
    varSymbol: VarSymbol)(implicit val pos: Position) extends Statement {
  def this(m: String, varName: String) = this({if(m == "monitorenter") Token(Tokens.MONITOR_ENTER, NoPosition, m) else Token(Tokens.MONITOR_EXIT, NoPosition, m)}, new VarSymbol(varName))(NoPosition)
  def isEnter: Boolean = monitor.tokenType == MONITOR_ENTER
  def isExit: Boolean = monitor.tokenType == MONITOR_EXIT
  def toCode: String = s"@${monitor.rawText} ${varSymbol.toCode}"
}

case class EmptyStatement(annotations: MList[Annotation])(implicit val pos: Position) extends Statement {
  def this() = this(mlistEmpty)(NoPosition)
  def toCode: String = annotations.map(anno => anno.toCode).mkString(" ")
}

sealed trait Expression extends JawaAstNode

/** LHS expressions:
  *   AccessExpression
  *   IndexingExpression
  *   VariableNameExpression
  *   StaticFieldAccessExpression
  */
sealed trait LHS extends RHS

/** RHS expressions:
  *   AccessExpression
  *   BinaryExpression
  *   CallRhs
  *   CastExpression
  *   CmpExpression
  *   ConstClassExpression
  *   ExceptionExpression
  *   IndexingExpression
  *   InstanceOfExpression
  *   LengthExpression
  *   LiteralExpression
  *   VariableNameExpression
  *   StaticFieldAccessExpression
  *   NewExpression
  *   NullExpression
  *   TupleExpression
  *   UnaryExpression
  */
sealed trait RHS

case class VariableNameExpression(varSymbol: VarSymbol)(implicit val pos: Position) extends Expression with LHS {
  def this(name: String, pos: Position) = this(new VarSymbol(name))(pos)
  def this(name: String) = this(name, NoPosition)
  def name: String = varSymbol.varName
  def toCode: String = varSymbol.toCode
}

case class StaticFieldAccessExpression(fieldNameSymbol: FieldNameSymbol, typExp: TypeExpression)(implicit val pos: Position) extends Expression with LHS {
  def this(name: String, typ: JawaType) = this(new FieldNameSymbol(name), new TypeExpression(typ))(NoPosition)
  def name: String = fieldNameSymbol.FQN
  def toCode: String = s"${fieldNameSymbol.toCode} @type ${typExp.toCode}"
  def typ: JawaType = typExp.typ
}

case class ExceptionExpression(typExp: TypeExpression)(implicit val pos: Position) extends Expression with RHS {
  def this(t: JawaType) = this(new TypeExpression(t))(NoPosition)
  def typ: JawaType = typExp.typ
  def toCode: String = s"Exception @type ${typExp.toCode}"
}

case class NullExpression(nul: Token)(implicit val pos: Position) extends Expression with RHS {
  def this() = this(Token(Tokens.NULL, NoPosition, "null"))(NoPosition)
  def toCode: String = nul.rawText
}

case class ConstClassExpression(typExp: TypeExpression)(implicit val pos: Position) extends Expression with RHS {
  def this(t: JawaType) = this(new TypeExpression(t))(NoPosition)
  def toCode: String = s"constclass @type ${typExp.toCode}"
}

case class LengthExpression(varSymbol: VarSymbol)(implicit val pos: Position) extends Expression with RHS {
  def this(name: String) = this(new VarSymbol(name))(NoPosition)
  def toCode: String = s"length @variable ${varSymbol.toCode}"
}

case class IndexingExpression(
    varSymbol: VarSymbol,
    indices: IList[IndexingSuffix])(implicit val pos: Position) extends Expression with LHS {
  def this(base: String, idxs: IList[String]) = this(new VarSymbol(base), idxs.map(i => new IndexingSuffix(i)))(NoPosition)
  def base: String = varSymbol.varName
  def dimensions: Int = indices.size
  def toCode: String = s"${varSymbol.toCode}${indices.map(i => i.toCode).mkString("")}"
}

case class IndexingSuffix(index: Either[VarSymbol, LiteralExpression])(implicit val pos: Position) extends JawaAstNode {
  def this(idx: String) = this(Left(new VarSymbol(idx)))(NoPosition)
  def this(idx: Int) = this(Right(new LiteralExpression(idx)))(NoPosition)
  def toCode: String = s"[${index match {case Left(vs) => vs.toCode case Right(le) => le.toCode}}]"
}

case class AccessExpression(
    varSymbol: VarSymbol,
    fieldSym: FieldNameSymbol,
    typExp: TypeExpression)(implicit val pos: Position) extends Expression with LHS {
  def this(varName: String, fieldName: String, typ: JawaType) = this(new VarSymbol(varName), new FieldNameSymbol(fieldName), new TypeExpression(typ))(NoPosition)
  def base: String = varSymbol.varName
  def fieldName: String = fieldSym.fieldName
  def toCode: String = s"${varSymbol.toCode}.${fieldSym.toCode} @type ${typExp.toCode}"
  def typ: JawaType = typExp.typ
}

case class TupleExpression(constants: IList[LiteralExpression])(implicit val pos: Position) extends Expression with RHS {
  def integers: IList[Int] = constants.map(c => c.getInt)
  def toCode: String = s"(${constants.map(c => c.toCode).mkString(", ")})"
}

case class CastExpression(
    typ: Type,
    varSym: VarSymbol)(implicit val pos: Position) extends Expression with RHS {
  def this(t: JawaType, varName: String) = this(new Type(t), new VarSymbol(varName))(NoPosition)
  def varName: String = varSym.varName
  def toCode: String = s"(${typ.toCode}) ${varSym.toCode}"
}

trait New {
  def typ: JawaType
}

case class NewExpression(base: Type)(implicit val pos: Position) extends Expression with RHS with New {
  def this(t: JawaType) = this(new Type(t))(NoPosition)
  def typ: JawaType = base.typ
  def toCode: String = s"new ${base.toCode}"
}

case class NewArrayExpression(
    base: Type,
    varSymbols: IList[VarSymbol])(implicit val pos: Position) extends Expression with RHS with New {
  def this(t: JawaType, varNames: IList[String]) = this(new Type(t), varNames.map(vn => new VarSymbol(vn)))(NoPosition)
  def dimensions: Int = base.dimensions + 1
  def baseType: JawaType = base.typ
  def typ: JawaType = getType(baseType.baseTyp, dimensions)
  def toCode: String = s"new ${base.toCode}[${varSymbols.map(vs => vs.toCode).mkString("," )}]"
}

case class InstanceOfExpression(
    varSymbol: VarSymbol,
    typExp: TypeExpression)(implicit val pos: Position) extends Expression with RHS {
  def this(varName: String, t: JawaType) = this(new VarSymbol(varName), new TypeExpression(t))(NoPosition)
  def toCode: String = s"instanceof @variable ${varSymbol.toCode} @type ${typExp.toCode}"
}

case class LiteralExpression(constant: Token)(implicit val pos: Position) extends Expression with RHS {
  def this(i: Int, pos: Position) = this(Token(Tokens.INTEGER_LITERAL, pos, s"$i"))(pos)
  def this(i: Int) = this(i, NoPosition)
  def this(l: Long, pos: Position) = this(Token(Tokens.INTEGER_LITERAL, pos, s"${l}L"))(pos)
  def this(l: Long) = this(l, NoPosition)
  def this(f: Float, pos: Position) = this(Token(Tokens.FLOATING_POINT_LITERAL, pos, s"${f}F"))(pos)
  def this(f: Float) = this(f, NoPosition)
  def this(d: Double, pos: Position) = this(Token(Tokens.FLOATING_POINT_LITERAL, pos, s"${d}D"))(pos)
  def this(d: Double) = this(d, NoPosition)
  def this(c: Char, pos: Position) = this(Token(Tokens.CHARACTER_LITERAL, pos, s"$c"))(pos)
  def this(c: Char) = this(c, NoPosition)
  def this(s: String, pos: Position) = this(Token(Tokens.STRING_LITERAL, pos, "\"" +s + "\""))(pos)
  def this(s: String) = this(s, NoPosition)
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
  unary: VarSymbol)(implicit val pos: Position) extends Expression with RHS {
  def this(op: String, name: String) = this(Token(Tokens.OP, NoPosition, op), new VarSymbol(name))(NoPosition)
  def toCode: String = s"${op.rawText}${unary.toCode}"
}

case class BinaryExpression(
  left: VarSymbol,
  op: Token,
  right: Either[VarSymbol, Either[LiteralExpression, NullExpression]])(implicit val pos: Position) extends Expression with RHS {
  def this(l: String, op: String, r: String) = this(new VarSymbol(l), Token(Tokens.OP, NoPosition, op), Left(new VarSymbol(r)))(NoPosition)
  def this(l: String, op: String, le: LiteralExpression) = this(new VarSymbol(l), Token(Tokens.OP, NoPosition, op), Right(Left(le)))(NoPosition)
  def this(l: String, op: String) = this(new VarSymbol(l), Token(Tokens.OP, NoPosition, op), Right(Right(new NullExpression())))(NoPosition)
  def toCode: String = s"${left.toCode} ${op.rawText} ${right match {case Left(vs) => vs.toCode case Right(ln) => ln match {case Left(le) => le.toCode case Right(ne) => ne.toCode}}}"
}

case class CmpExpression(
    cmp: Token,
    var1Symbol: VarSymbol,
    var2Symbol: VarSymbol)(implicit val pos: Position) extends Expression with RHS {
  def this(c: String, v1Name: String, v2Name: String) = this(Token(Tokens.CMP, NoPosition, c), new VarSymbol(v1Name), new VarSymbol(v2Name))(NoPosition)
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
    targetLocation: LocationSymbol)(implicit val pos: Position) extends JawaAstNode {
  def this(t: JawaType, from: String, to: String, target: String) = this(new Type(t), new CatchRange(from, to), new LocationSymbol(target))(NoPosition)
  def from: String = range.fromLocation.location
  def to: String = range.toLocation.location
  def toCode: String = s"catch ${typ.toCode} ${range.toCode} goto ${targetLocation.toCode};"
}

case class CatchRange(
    fromLocation: LocationSymbol,
    toLocation: LocationSymbol)(implicit val pos: Position) extends JawaAstNode {
  def this(from: String, to: String) = this(new LocationSymbol(from), new LocationSymbol(to))(NoPosition)
  def toCode: String = s"@[${fromLocation.toCode}..${toLocation.toCode}]"
}