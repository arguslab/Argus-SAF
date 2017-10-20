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

import java.util
import java.util.Optional

import com.github.javaparser.ast._
import com.github.javaparser.ast.`type`._
import com.github.javaparser.ast.body._
import com.github.javaparser.ast.expr.{AnnotationExpr, NormalAnnotationExpr, SingleMemberAnnotationExpr}
import com.github.javaparser.ast.stmt.{BlockStmt, ExpressionStmt, Statement}
import org.argus.jawa.ast.{AnnotationValue, CatchClause => JawaCatchClause, ExtendAndImplement, ExtendsAndImplementsClauses, FieldDefSymbol, InstanceFieldDeclaration, InstanceFieldDeclarationBlock, LocalVarDeclaration, Location, MethodDefSymbol, Param, ParamClause, ResolvedBody, StatementValue, StaticFieldDeclaration, TokenValue, TypeDefSymbol, TypeFragment, TypeSymbol, VarDefSymbol, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit, MethodDeclaration => JawaMethodDeclaration, Type => JawaTypeAst}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.io.{JavaSourceFile, RangePosition}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JavaKnowledge, JawaType}

class Java2Jawa(global: Global, sourceFile: JavaSourceFile) {

  private var packageName: String = ""

  private val imports: NodeList[ImportDeclaration] = sourceFile.getJavaCU.getImports

  private val typeMap: MMap[String, JawaType] = mmapEmpty

  private def findType(name: String, pos: RangePosition): JawaType = {
    typeMap.get(name) match {
      case Some(t) => t
      case None =>
        var typOpt: Option[JawaType] = None
        // Check whether itself is FQN
        val firstTry = new JawaType(name)
        if(global.containsClass(firstTry)) {
          typOpt = Some(firstTry)
        }
        typOpt match {
          case None =>
            // check current package
            if(packageName.nonEmpty) {
              val checkCurrent = new JawaType(s"$packageName.$name")
              if(global.containsClass(checkCurrent)) {
                typOpt = Some(checkCurrent)
              }
            }
          case _ =>
        }
        typOpt match {
          case None =>
            // Check imports
            imports.forEach { imp =>
              if(!imp.isStatic && !imp.isAsterisk) {
                val typ = new JawaType(imp.getNameAsString)
                if(typ.jawaName.endsWith(name)) {
                  typOpt = Some(typ)
                }
              } else if(!imp.isStatic && imp.isAsterisk) {
                val typ = new JawaType(s"${imp.getNameAsString}.$name")
                if(global.containsClass(typ)) {
                  typOpt = Some(typ)
                }
              }
            }
          case _ =>
        }
        typOpt match {
          case None =>
            // java.lang.* is implicit applied
            val typ = new JawaType(s"java.lang.$name")
            if(global.containsClass(typ)) {
              typOpt = Some(typ)
            }
          case _ =>
        }
        val result = typOpt match {
          case Some(typ) => typ
          case None =>
            global.reporter.error(pos, s"Could not resolve type: $name")
            new JawaType(name)
        }
        typeMap(name) = result
        result
    }
  }

  private def findType(javaType: Type): JawaType = {
    var typStr: String = null
    var dimension: Int = 0
    javaType match {
      case at: ArrayType =>
        typStr = findType(at.getElementType).jawaName
        dimension = at.getArrayLevel
      case cit: ClassOrInterfaceType =>
        typStr = findType(cit.getNameAsString, cit.toRange).jawaName
      case it: IntersectionType =>
        val jawaTypes: MList[JawaType] = mlistEmpty
        it.getElements.forEach{ elem =>
          jawaTypes += findType(elem)
        }
        typStr = jawaTypes.map(t => t.jawaName).mkString("&")
      case pt: PrimitiveType =>
        pt.getType match {
          case PrimitiveType.Primitive.BOOLEAN => typStr = "boolean"
          case PrimitiveType.Primitive.BYTE => typStr = "byte"
          case PrimitiveType.Primitive.CHAR => typStr = "char"
          case PrimitiveType.Primitive.DOUBLE => typStr = "double"
          case PrimitiveType.Primitive.FLOAT => typStr = "float"
          case PrimitiveType.Primitive.INT => typStr = "int"
          case PrimitiveType.Primitive.LONG => typStr = "long"
          case PrimitiveType.Primitive.SHORT => typStr = "short"
          case _ =>
            global.reporter.error(javaType.toRange.pos, s"Unknown primitive type: $pt")
            typStr = "int"
        }
      case _: VoidType =>
        typStr = "void"
      case _ =>
        throw Java2JawaException(s"${javaType.getClass} is not handled by jawa: $javaType")
    }
    new JawaType(typStr, dimension)
  }

  implicit class TransRange(node: Node) {
    def toRange: RangePosition = {
      val nodeRange = node.getRange
      if(nodeRange.isPresent) {
        val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line - 1) + nodeRange.get().begin.column - 1
        val endIn = sourceFile.lineToOffset(nodeRange.get().end.line - 1) + nodeRange.get().end.column - 1
        new RangePosition(sourceFile, startIn, endIn - startIn + 1, nodeRange.get().begin.line - 1, nodeRange.get().begin.column - 1)
      } else {
        new RangePosition(sourceFile, 0, 0, 0, 0)
      }
    }
  }

  private def getKeyWordRange(node: Node): RangePosition = {
    val nodeRange = node.getRange
    if(nodeRange.isPresent) {
      val startIn = sourceFile.lineToOffset(nodeRange.get().begin.line - 1) + nodeRange.get().begin.column - 1
      new RangePosition(sourceFile, startIn, startIn + 1)
    } else {
      new RangePosition(sourceFile, 0, 0, 0, 0)
    }
  }

  implicit class StringProcess(str: String) {
    def apostrophe: String = "`%s`".format(str)
  }

  private def getJawaAccessFlag(modifiers: util.EnumSet[Modifier], isConstructor: Boolean): String = {
    val flags: MList[String] = mlistEmpty
    modifiers.forEach {
      case Modifier.PUBLIC => flags += "PUBLIC"
      case Modifier.PROTECTED => flags += "PROTECTED"
      case Modifier.PRIVATE => flags += "PRIVATE"
      case Modifier.ABSTRACT => flags += "ABSTRACT"
      case Modifier.STATIC => flags += "STATIC"
      case Modifier.FINAL => flags += "FINAL"
      case Modifier.TRANSIENT => flags += "TRANSIENT"
      case Modifier.VOLATILE => flags += "VOLATILE"
      case Modifier.SYNCHRONIZED => flags += "SYNCHRONIZED"
      case Modifier.NATIVE => flags += "NATIVE"
      case Modifier.STRICTFP => flags += "STRICTFP"
      case Modifier.TRANSITIVE => flags += "TRANSITIVE"
      case Modifier.DEFAULT => flags += "DEFAULT"
    }
    if(isConstructor) {
      flags += "CONSTRUCTOR"
    }
    flags.mkString("_")
  }

  private def handleType(javaType: Type): JawaTypeAst = {
    val jawaType = findType(javaType)
    val baseTypeSymbol: Either[TypeSymbol, Token] = {
      jawaType.baseTyp match {
        case x if JavaKnowledge.isJavaPrimitive(x) => Right(Token(Tokens.ID, javaType.getElementType.toRange, x.apostrophe))
        case t => Left(TypeSymbol(Token(Tokens.ID, javaType.getElementType.toRange, t.apostrophe)))
      }
    }
    val typeFragments: IList[TypeFragment] = (0 until jawaType.dimensions).map { _ =>
      TypeFragment(getKeyWordRange(javaType))
    }.toList
    JawaTypeAst(baseTypeSymbol, typeFragments)
  }

  def process: JawaCompilationUnit = {
    process(sourceFile.getJavaCU)
  }

  def process(cu: CompilationUnit): JawaCompilationUnit = {
    cu.getImports
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    val topDecls: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    cu.getTypes.forEach(typ => topDecls ++= processClass(None, typ))
    val result = JawaCompilationUnit(topDecls.toList)
    result.topDecls foreach { cid =>
      val typ = cid.cityp
      cid.getAllChildrenInclude foreach (_.enclosingTopLevelClass = typ)
    }
    result
  }

  def processClass(owner: Option[TypeDefSymbol], typ: TypeDeclaration[_]): IList[JawaClassOrInterfaceDeclaration] = {
    typ match {
      case cid: ClassOrInterfaceDeclaration =>
        val cityp: TypeDefSymbol = owner match {
          case Some(outer) =>
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"${outer.typ.jawaName}$$${cid.getNameAsString}".apostrophe))
          case None =>
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"$packageName.${cid.getNameAsString}".apostrophe))
        }
        val annotations: MList[JawaAnnotation] = mlistEmpty
        // add kind annotation
        val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
        val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), {if(cid.isInterface) "interface" else "class"}))
        annotations += JawaAnnotation(kindKey, Some(kindValue))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(cid), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), getJawaAccessFlag(cid.getModifiers, isConstructor = false)))
        annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))
        // add java annotations
        cid.getAnnotations.forEach{ anno =>
          annotations += processAnnotation(anno)
        }

        // Resolve extends
        var extendAndImplNum = cid.getExtendedTypes.size() + cid.getImplementedTypes.size()
        val extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses] = if(extendAndImplNum > 0) {
          val parentTyps: MList[ExtendAndImplement] = mlistEmpty
          cid.getExtendedTypes.forEach{ et =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "class"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, findType(et).jawaName.apostrophe)), List(annotation))
            parentTyps += ei
          }
          cid.getImplementedTypes.forEach{ et =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "interface"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, findType(et).jawaName.apostrophe)), List(annotation))
            parentTyps += ei
          }
          Some(ExtendsAndImplementsClauses(parentTyps.toList))
        } else {
          None
        }

        val (instanceFieldDeclarationBlock, staticFields, methods, inners) = processMembers(cityp, cid)

        JawaClassOrInterfaceDeclaration(cityp, annotations.toList, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields, methods) :: inners
      case _: EnumDeclaration =>
        ilistEmpty // TODO
      case _: AnnotationDeclaration =>
        ilistEmpty // TODO
    }
  }

  def processAnnotation(ae: AnnotationExpr): JawaAnnotation = {
    val annoKey = Token(Tokens.ID, ae.getName.toRange, findType(ae.getNameAsString, ae.getName.toRange).jawaName.apostrophe)
    val annoValue: Option[AnnotationValue] = ae match {
      case _: NormalAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _: SingleMemberAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _ => None // MarkerAnnotationExpr
    }
    JawaAnnotation(annoKey, annoValue)
  }

  def processMembers(owner: TypeDefSymbol, typ: TypeDeclaration[_]): (InstanceFieldDeclarationBlock, IList[StaticFieldDeclaration], IList[JawaMethodDeclaration], IList[JawaClassOrInterfaceDeclaration]) = {
    val initializers: MList[InitializerDeclaration] = mlistEmpty
    val fields: MList[FieldDeclaration] = mlistEmpty
    val constructors: MList[ConstructorDeclaration] = mlistEmpty
    val methods: MList[MethodDeclaration] = mlistEmpty
    val innerTypes: MList[TypeDeclaration[_]] = mlistEmpty
    val enumConstants: MList[EnumConstantDeclaration] = mlistEmpty // TODO
    typ.getMembers.forEach {
      case id: InitializerDeclaration =>
        initializers += id
      case fd: FieldDeclaration =>
        fields += fd
      case cd: ConstructorDeclaration =>
        constructors += cd
      case md: MethodDeclaration =>
        methods += md
      case td: TypeDeclaration[_] =>
        innerTypes += td
      case ecd: EnumConstantDeclaration =>
        enumConstants += ecd
      case u: BodyDeclaration[_] =>
        global.reporter.warning(u.toRange, "Unhandled member: " + u)
    }
    val (instanceFieldDeclarationBlock, staticFields) = processFields(owner, fields.toList)
    // Resolve methods
    val mds: MList[JawaMethodDeclaration] = mlistEmpty
    mds ++= processConstructors(owner, typ, initializers.toList, fields.toList, constructors.toList)
    methods foreach { m =>
      mds += processMethod(owner, m)
    }
    // Resolve inner classes
    val innerCids: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    innerTypes foreach { inner =>
      innerCids ++= processClass(Some(owner), inner)
    }
    (instanceFieldDeclarationBlock, staticFields, mds.toList, innerCids.toList)
  }

  def processFields(owner: TypeDefSymbol, fields: IList[FieldDeclaration]): (InstanceFieldDeclarationBlock, IList[StaticFieldDeclaration]) = {
    // Resolve fields
    val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
    val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
    fields foreach { f =>
      f.getVariables.forEach{ va =>
        val jawaTypeAst = handleType(va.getType)
        val fieldSymbol = FieldDefSymbol(Token(Tokens.ID, va.getName.toRange, s"${owner.typ.jawaName}.${va.getNameAsString}".apostrophe))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(f), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(f), getJawaAccessFlag(f.getModifiers, isConstructor = false)))
        val accessFlagAnnotation = JawaAnnotation(accessFlagKey, Some(accessFlagValue))
        if(f.isStatic) {
          staticFields += StaticFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))
        } else {
          instanceFields += InstanceFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))
        }
      }
    }
    val instanceFieldDeclarationBlock: InstanceFieldDeclarationBlock = InstanceFieldDeclarationBlock(instanceFields.toList)
    (instanceFieldDeclarationBlock, staticFields.toList)
  }

  def processConstructors(owner: TypeDefSymbol, typ: TypeDeclaration[_], initializers: IList[InitializerDeclaration], fields: IList[FieldDeclaration], constructors: IList[ConstructorDeclaration]): IList[JawaMethodDeclaration] = {
    val staticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
    val nonStaticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
    fields foreach { f =>
      if(f.isStatic) {
        f.getVariables.forEach { v =>
          if(v.getInitializer.isPresent) {
            staticFieldsWithInitializer += v
          }
        }
      } else {
        f.getVariables.forEach { v =>
          if(v.getInitializer.isPresent) {
            nonStaticFieldsWithInitializer += v
          }
        }
      }
    }
    val staticInitializers: MList[InitializerDeclaration] = mlistEmpty
    val nonStaticInitializers: MList[InitializerDeclaration] = mlistEmpty
    initializers foreach { i =>
      if(i.isStatic) {
        staticInitializers += i
      } else {
        nonStaticInitializers += i
      }
    }
    val mds: MList[JawaMethodDeclaration] = mlistEmpty
    // Process static initializer
    if(staticFieldsWithInitializer.nonEmpty || staticInitializers.nonEmpty) {
      mds += processStaticConstructor(owner, typ, staticFieldsWithInitializer.toList, staticInitializers.toList)
    }
    // Process non-static initializers
    val realConstructors: MList[ConstructorDeclaration] = mlistEmpty
    val frontStatements: NodeList[Statement] = new NodeList[Statement]()
    nonStaticFieldsWithInitializer foreach { nsfi =>
      val exp = nsfi.getInitializer.get()
      frontStatements.add(new ExpressionStmt(exp))
    }
    nonStaticInitializers foreach { nsi =>
      frontStatements.addAll(nsi.getBody.getStatements)
    }
    if(constructors.isEmpty) {
      realConstructors += new ConstructorDeclaration(typ.getModifiers, new NodeList[AnnotationExpr], new NodeList[TypeParameter], typ.getName, new NodeList[Parameter], new NodeList[ReferenceType], new BlockStmt(frontStatements))
    } else {
      constructors.foreach { cons =>
        val realStatements = new NodeList[Statement]()
        realStatements.addAll(frontStatements)
        realStatements.addAll(cons.getBody.getStatements)
        val bodyBlock = new BlockStmt(realStatements)
        cons.setBody(bodyBlock)
        realConstructors += cons
      }
    }
    realConstructors foreach { rc =>
      mds += processConstructor(owner, rc)
    }
    mds.toList
  }

  private def processStaticConstructor(owner: TypeDefSymbol, typ: TypeDeclaration[_], staticFieldsWithInitializer: IList[VariableDeclarator], staticInitializers: IList[InitializerDeclaration]): JawaMethodDeclaration = {
    val statements: NodeList[Statement] = new NodeList[Statement]()
    staticFieldsWithInitializer foreach { sfi =>
      val exp = sfi.getInitializer.get()
      statements.add(new ExpressionStmt(exp))
    }
    staticInitializers foreach { si =>
      statements.addAll(si.getBody.getStatements)
    }
    doProcessMethod(
      owner,
      new VoidType(),
      "<clinit>",
      typ.getName.toRange,
      isStatic = true,
      isConstructor = true,
      new NodeList[Parameter](),
      util.EnumSet.of(Modifier.STATIC),
      new NodeList[AnnotationExpr](),
      Optional.ofNullable(new BlockStmt(statements))
    )
  }

  private def processConstructor(owner: TypeDefSymbol, cons: ConstructorDeclaration): JawaMethodDeclaration = {
    doProcessMethod(
      owner,
      new VoidType(),
      "<init>",
      cons.getName.toRange,
      cons.isStatic,
      isConstructor = true,
      cons.getParameters,
      cons.getModifiers,
      cons.getAnnotations,
      Optional.ofNullable(cons.getBody))
  }

  def processMethod(owner: TypeDefSymbol, md: MethodDeclaration): JawaMethodDeclaration = {
    doProcessMethod(
      owner,
      md.getType,
      md.getNameAsString,
      md.getName.toRange,
      md.isStatic,
      isConstructor = false,
      md.getParameters,
      md.getModifiers,
      md.getAnnotations,
      md.getBody)
  }

  private def doProcessMethod(
       owner: TypeDefSymbol,
       typ: Type,
       methodName: String,
       pos: RangePosition,
       isStatic: Boolean,
       isConstructor: Boolean,
       parameters: NodeList[Parameter],
       modifiers: util.EnumSet[Modifier],
       annotationExprs: NodeList[AnnotationExpr],
       bodyBlock: Optional[BlockStmt]): JawaMethodDeclaration = {
    val returnType: JawaTypeAst = handleType(typ)
    val methodSymbol: MethodDefSymbol = MethodDefSymbol(Token(Tokens.ID, pos, methodName.apostrophe))
    val params: MList[Param] = mlistEmpty
    if(isStatic) {
      val jta: JawaTypeAst = JawaTypeAst(Left(TypeSymbol(owner.id)), ilistEmpty)
      getParam(jta, "this", pos, isThis = true)
    }
    val paramTyps: MList[JawaType] = mlistEmpty
    parameters.forEach{ p =>
      val param = processParameter(p)
      paramTyps += param.typ.typ
      params += param
    }
    val paramClause: ParamClause = ParamClause(params.toList)
    val annotations: MList[JawaAnnotation] = mlistEmpty
    // add singature annotation
    val sig = JavaKnowledge.genSignature(owner.typ, methodSymbol.methodName, paramTyps.toList, returnType.typ)
    val signatureKey = Token(Tokens.ID, pos, "signature")
    val signatureValue = TokenValue(Token(Tokens.ID, pos, sig.signature.apostrophe))
    annotations += JawaAnnotation(signatureKey, Some(signatureValue))
    // add access flag annotation
    val accessFlagKey = Token(Tokens.ID, pos, "AccessFlag")
    val accessFlagValue = TokenValue(Token(Tokens.ID, pos, getJawaAccessFlag(modifiers, isConstructor)))
    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))
    // add java annotations
    annotationExprs.forEach{ anno =>
      annotations += processAnnotation(anno)
    }
    val jmd = JawaMethodDeclaration(returnType, methodSymbol, paramClause, annotations.toList, ResolvedBody(ilistEmpty, ilistEmpty, ilistEmpty))
    methodSymbol.signature = jmd.signature
    jmd
  }

  def processParameter(param: Parameter): Param = {
    val typ: JawaTypeAst = handleType(param.getType)
    getParam(typ, param.getNameAsString, param.getName.toRange, isThis = false)
  }

  private def getParam(typ: JawaTypeAst, name: String, pos: RangePosition, isThis: Boolean): Param = {
    val paramSymbol: VarDefSymbol = VarDefSymbol(Token(Tokens.ID, pos, name.apostrophe))
    val annotations: MList[JawaAnnotation] = mlistEmpty
    if(isThis) {
      val kindKey = Token(Tokens.ID, pos, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, pos, "this"))
      annotations += JawaAnnotation(kindKey, Some(kindValue))
    } else if(typ.typ.isObject) {
      val kindKey = Token(Tokens.ID, pos, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, pos, "object"))
      annotations += JawaAnnotation(kindKey, Some(kindValue))
    }
    Param(typ, paramSymbol, annotations.toList)
  }

//  def processBody(bodyBlock: BlockStmt): ResolvedBody = {
//  }
//
//  private def processBlockStmt(blockStmt: BlockStmt): (IList[LocalVarDeclaration], IList[Location], IList[JawaCatchClause]) = {
//
//  }

}

case class Java2JawaException(msg: String) extends RuntimeException