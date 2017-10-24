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
import com.github.javaparser.ast.expr._
import com.github.javaparser.ast.stmt._
import org.argus.jawa.ast.{AnnotationValue, ExtendAndImplement, ExtendsAndImplementsClauses, FieldDefSymbol, InstanceFieldDeclaration, JawaAstNode, MethodDefSymbol, Param, ResolvedBody, StatementValue, StaticFieldDeclaration, TokenValue, TypeDefSymbol, TypeFragment, TypeSymbol, VarDefSymbol, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit, MethodDeclaration => JawaMethodDeclaration, Type => JawaTypeAst}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.io.{JavaSourceFile, Position => JawaPosition, RangePosition}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JavaKnowledge, JawaType, Signature}

class Java2Jawa(global: Global, sourceFile: JavaSourceFile) {

  private var packageName: String = ""

  private val imports: NodeList[ImportDeclaration] = sourceFile.getJavaCU.getImports

  private val typeMap: MMap[String, JawaType] = mmapEmpty

  protected[java] def findType(name: String, pos: RangePosition): JawaType = {
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

  protected[java] def findType(javaType: Type): JawaType = {
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
        throw Java2JawaException(s"${javaType.getClass} is not handled by jawa: $javaType, please contact author: fgwei521@gmail.com")
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

  implicit class ASTPos[T <: JawaAstNode](node: T) {
    def withNode(n: Node): T = {
      node.pos = n.toRange
      node
    }
    def withNodes[N <: Node](ns: NodeList[N]): T = {
      require(ns.isNonEmpty, "Add ast pos with empty node list.")
      val begin = ns.get(0).toRange
      val end = ns.get(ns.size() - 1).toRange
      require(end.end >= begin.start, "Later node should have larger position than prior nodes.")
      node.pos = new RangePosition(begin.source, begin.start, end.end - begin.start + 1, begin.line, begin.column)
      node
    }
    def withPos(pos: JawaPosition): T = {
      node.pos = pos
      node
    }
  }

  protected[java] def getKeyWordRange(node: Node): RangePosition = {
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

  protected[java] def getJawaAccessFlag(modifiers: util.EnumSet[Modifier], isConstructor: Boolean): String = {
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

  protected[java] def handleType(javaType: Type): JawaTypeAst = {
    val jawaType = findType(javaType)
    handleJawaType(jawaType, javaType.getElementType.toRange)
  }

  protected[java] def handleJawaType(jawaType: JawaType, pos: RangePosition): JawaTypeAst = {
    val baseTypeSymbol: Either[TypeSymbol, Token] = {
      jawaType.baseTyp match {
        case x if JavaKnowledge.isJavaPrimitive(x) => Right(Token(Tokens.ID, pos, x.apostrophe))
        case t => Left(TypeSymbol(Token(Tokens.ID, pos, t.apostrophe)).withPos(pos))
      }
    }
    val typeFragments: IList[TypeFragment] = (0 until jawaType.dimensions).map { _ =>
      TypeFragment(pos)
    }.toList
    JawaTypeAst(baseTypeSymbol, typeFragments).withPos(pos)
  }

  def process: JawaCompilationUnit = {
    process(sourceFile.getJavaCU)
  }

  def process(cu: CompilationUnit): JawaCompilationUnit = {
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    val topDecls: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    cu.getTypes.forEach(typ => topDecls ++= processClass(None, typ))
    val result = JawaCompilationUnit(topDecls.toList).withNode(cu)
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
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"${outer.typ.jawaName}$$${cid.getNameAsString}".apostrophe)).withNode(cid.getName)
          case None =>
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"$packageName.${cid.getNameAsString}".apostrophe)).withNode(cid.getName)
        }
        val annotations: MList[JawaAnnotation] = mlistEmpty
        // add kind annotation
        val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
        val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), {if(cid.isInterface) "interface" else "class"}))
        annotations += JawaAnnotation(kindKey, Some(kindValue)).withPos(getKeyWordRange(cid))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(cid), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), getJawaAccessFlag(cid.getModifiers, isConstructor = false)))
        annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue)).withPos(getKeyWordRange(cid))
        // add java annotations
        cid.getAnnotations.forEach{ anno =>
          annotations += processAnnotationExpr(anno)
        }

        // Resolve extends
        var extendAndImplNum = cid.getExtendedTypes.size() + cid.getImplementedTypes.size()
        val extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses] = if(extendAndImplNum > 0) {
          val parentTyps: MList[ExtendAndImplement] = mlistEmpty
          cid.getExtendedTypes.forEach{ et =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "class"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue)).withPos(getKeyWordRange(cid))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, findType(et).jawaName.apostrophe)), List(annotation)).withNode(et)
            parentTyps += ei
          }
          cid.getImplementedTypes.forEach{ it =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "interface"))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, it.toRange, findType(it).jawaName.apostrophe)), List(annotation)).withNode(it)
            parentTyps += ei
          }
          val nodes = new NodeList[ClassOrInterfaceType](cid.getExtendedTypes)
          nodes.addAll(cid.getImplementedTypes)
          Some(ExtendsAndImplementsClauses(parentTyps.toList).withNodes(nodes))
        } else {
          None
        }

        val (instanceFieldDeclarationBlock, staticFields, methods, inners) = processMembers(cityp, cid)

        JawaClassOrInterfaceDeclaration(cityp, annotations.toList, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields, methods).withNode(cid) :: inners
      case _: EnumDeclaration =>
        ilistEmpty // TODO
      case _: AnnotationDeclaration =>
        ilistEmpty // TODO
    }
  }

  def processMembers(owner: TypeDefSymbol, typ: TypeDeclaration[_]): (IList[InstanceFieldDeclaration], IList[StaticFieldDeclaration], IList[JawaMethodDeclaration], IList[JawaClassOrInterfaceDeclaration]) = {
    val initializers = new NodeList[InitializerDeclaration]()
    val fields = new NodeList[FieldDeclaration]()
    val constructors = new NodeList[ConstructorDeclaration]()
    val methods = new NodeList[MethodDeclaration]()
    val innerTypes = new NodeList[TypeDeclaration[_]]()
    val enumConstants = new NodeList[EnumConstantDeclaration]() // TODO
    typ.getMembers.forEach {
      case id: InitializerDeclaration =>
        initializers.add(id)
      case fd: FieldDeclaration =>
        fields.add(fd)
      case cd: ConstructorDeclaration =>
        constructors.add(cd)
      case md: MethodDeclaration =>
        methods.add(md)
      case td: TypeDeclaration[_] =>
        innerTypes.add(td)
      case ecd: EnumConstantDeclaration =>
        enumConstants.add(ecd)
      case u: BodyDeclaration[_] =>
        global.reporter.warning(u.toRange, "Unhandled member: " + u)
    }
    val (instanceFields, staticFields) = processFields(owner, fields)
    // Resolve methods
    val mds: MList[JawaMethodDeclaration] = mlistEmpty
    mds ++= processConstructors(owner, typ, initializers, fields, constructors)
    methods.forEach { m =>
      mds += processMethod(owner, m)
    }
    // Resolve inner classes
    val innerCids: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    innerTypes.forEach { inner =>
      innerCids ++= processClass(Some(owner), inner)
    }
    (instanceFields, staticFields, mds.toList, innerCids.toList)
  }

  def processFields(owner: TypeDefSymbol, fields: NodeList[FieldDeclaration]): (IList[InstanceFieldDeclaration], IList[StaticFieldDeclaration]) = {
    // Resolve fields
    val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
    val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
    fields.forEach { f =>
      f.getVariables.forEach{ va =>
        val jawaTypeAst = handleType(va.getType)
        val fieldSymbol = FieldDefSymbol(Token(Tokens.ID, va.getName.toRange, s"${owner.typ.jawaName}.${va.getNameAsString}".apostrophe))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(f), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(f), getJawaAccessFlag(f.getModifiers, isConstructor = false)))
        val accessFlagAnnotation = JawaAnnotation(accessFlagKey, Some(accessFlagValue)).withPos(getKeyWordRange(f))
        if(f.isStatic) {
          staticFields += StaticFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation)).withNode(f)
        } else {
          instanceFields += InstanceFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation)).withNode(f)
        }
      }
    }
    (instanceFields.toList, staticFields.toList)
  }

  /** Terminology:
    *   No-args constructor: a constructor with no parameters;
    *
    *   Accessible no-args constructor: a no-args constructor in the superclass visible to the subclass. That means it is either public or protected or,
    *                                 if both classes are in the same package, package access;
    *
    *   Default constructor: the public no-args constructor added by the compiler when there is no explicit constructor in the class.
    *
    * So all classes have at least one constructor.
    * Subclasses constructors may specify as the first thing they do which constructor in the superclass to invoke before executing the code in the subclass's constructor.
    * If the subclass constructor does not specify which superclass constructor to invoke then the compiler will automatically call the accessible no-args constructor in the superclass.
    * If the superclass has no no-arg constructor or it isn't accessible then not specifying the superclass constructor to be called (in the subclass constructor)
    * is a compiler error so it must be specified.
    */
  def processConstructors(owner: TypeDefSymbol, typ: TypeDeclaration[_], initializers: NodeList[InitializerDeclaration], fields: NodeList[FieldDeclaration], constructors: NodeList[ConstructorDeclaration]): IList[JawaMethodDeclaration] = {
    val staticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
    val nonStaticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
    fields.forEach { f =>
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
    initializers.forEach { i =>
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
    // Process non-static initializer
    val frontStatements: NodeList[Statement] = new NodeList[Statement]()
    nonStaticFieldsWithInitializer foreach { nsfi =>
      val exp = nsfi.getInitializer.get()
      frontStatements.add(new ExpressionStmt(exp))
    }
    nonStaticInitializers foreach { nsi =>
      frontStatements.addAll(nsi.getBody.getStatements)
    }
    if(constructors.isEmpty) {
      constructors.add(new ConstructorDeclaration(typ.getModifiers, new NodeList[AnnotationExpr], new NodeList[TypeParameter], typ.getName, new NodeList[Parameter], new NodeList[ReferenceType], new BlockStmt(frontStatements)))
    }
    constructors.forEach { cons =>
      val bodyBlock = makeConstructorBody(frontStatements, cons.getBody.getStatements)
      cons.setBody(bodyBlock)
      mds += processConstructor(owner, cons)
    }
    mds.toList
  }

  private def makeConstructorBody(frontStatements: NodeList[Statement], bodyStatements: NodeList[Statement]): BlockStmt = {
    val statements: NodeList[Statement] = new NodeList[Statement]()
    // Check do we need to add super no-arg constructor call.
    if(bodyStatements.isNonEmpty && bodyStatements.get(0).isInstanceOf[ExplicitConstructorInvocationStmt]) {
      statements.addAll(bodyStatements)
      statements.addAll(1, frontStatements)
    } else {
      val ecis = new ExplicitConstructorInvocationStmt(false, null, new NodeList[Expression]())
      statements.add(ecis)
      statements.addAll(frontStatements)
      statements.addAll(bodyStatements)
    }
    new BlockStmt(statements)
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
      typ.toRange,
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
      cons.toRange,
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
      md.toRange,
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
       mdPos: RangePosition,
       returnTyp: Type,
       methodName: String,
       namePos: RangePosition,
       isStatic: Boolean,
       isConstructor: Boolean,
       parameters: NodeList[Parameter],
       modifiers: util.EnumSet[Modifier],
       annotationExprs: NodeList[AnnotationExpr],
       bodyBlock: Optional[BlockStmt]): JawaMethodDeclaration = {
    val returnType: JawaTypeAst = handleType(returnTyp)
    val methodSymbol: MethodDefSymbol = MethodDefSymbol(Token(Tokens.ID, namePos, methodName.apostrophe))
    val params: MList[Param] = mlistEmpty
    if(!isStatic) {
      val jta = JawaTypeAst(Left(TypeSymbol(owner.id)), ilistEmpty).withPos(namePos)
      params += getParam(jta, "this", namePos, isThis = true)
    }
    val paramTyps: MList[JawaType] = mlistEmpty
    parameters.forEach { p =>
      val param = processParameter(p)
      paramTyps += param.typ.typ
      params += param
    }
    val annotations: MList[JawaAnnotation] = mlistEmpty
    // add singature annotation
    val sig = JavaKnowledge.genSignature(owner.typ, methodSymbol.methodName, paramTyps.toList, returnType.typ)
    val signatureKey = Token(Tokens.ID, mdPos, "signature")
    val signatureValue = TokenValue(Token(Tokens.ID, mdPos, sig.signature.apostrophe))
    annotations += JawaAnnotation(signatureKey, Some(signatureValue)).withPos(mdPos)
    // add access flag annotation
    val accessFlagKey = Token(Tokens.ID, mdPos, "AccessFlag")
    val accessFlagValue = TokenValue(Token(Tokens.ID, mdPos, getJawaAccessFlag(modifiers, isConstructor)))
    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue)).withPos(mdPos)
    // add java annotations
    annotationExprs.forEach{ anno =>
      annotations += processAnnotationExpr(anno)
    }
    val body = if(bodyBlock.isPresent) {
      processBody(sig, bodyBlock.get())
    } else {
      ResolvedBody(ilistEmpty, ilistEmpty, ilistEmpty).withPos(mdPos)
    }
    val jmd = JawaMethodDeclaration(returnType, methodSymbol, params.toList, annotations.toList, body).withPos(mdPos)
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
      annotations += JawaAnnotation(kindKey, Some(kindValue)).withPos(pos)
    } else if(typ.typ.isObject) {
      val kindKey = Token(Tokens.ID, pos, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, pos, "object"))
      annotations += JawaAnnotation(kindKey, Some(kindValue)).withPos(pos)
    }
    Param(typ, paramSymbol, annotations.toList).withPos(pos)
  }

  def processBody(sig: Signature, bodyBlock: BlockStmt): ResolvedBody = {
    val visitor = new MethodBodyVisitor(this, sig, bodyBlock.toRange)
    bodyBlock.accept(visitor, null)
    ResolvedBody(visitor.localVarDeclarations.toList, visitor.locations, visitor.catchClauses.toList)
  }

  def processAnnotationExpr(ae: AnnotationExpr): JawaAnnotation = {
    val annoKey = Token(Tokens.ID, ae.getName.toRange, findType(ae.getNameAsString, ae.getName.toRange).jawaName.apostrophe)
    val annoValue: Option[AnnotationValue] = ae match {
      case _: NormalAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _: SingleMemberAnnotationExpr =>
        Some(StatementValue(ilistEmpty)) // TODO
      case _ => None // MarkerAnnotationExpr
    }
    JawaAnnotation(annoKey, annoValue).withNode(ae).withNode(ae)
  }

}

case class Java2JawaException(msg: String) extends RuntimeException