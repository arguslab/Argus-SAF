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
import org.argus.jawa.ast.{AnnotationValue, ExtendAndImplement, ExtendsAndImplementsClauses, FieldDefSymbol, InstanceFieldDeclaration, MethodDefSymbol, Param, ResolvedBody, StatementValue, StaticFieldDeclaration, TokenValue, TypeDefSymbol, TypeFragment, TypeSymbol, UnresolvedBodyJava, VarDefSymbol, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, CompilationUnit => JawaCompilationUnit, MethodDeclaration => JawaMethodDeclaration, Type => JawaTypeAst}
import org.argus.jawa.compiler.lexer.{Token, Tokens}
import org.argus.jawa.core.io.{JavaSourceFile, Position, RangePosition}
import org.argus.jawa.core.util._
import org.argus.jawa.core.{Global, JavaKnowledge, JawaType, Signature}

class Java2Jawa(val global: Global, val sourceFile: JavaSourceFile) {

  private var packageName: String = ""

  private val imports: NodeList[ImportDeclaration] = sourceFile.getJavaCU.getImports

  private val typeMap: MMap[String, JawaType] = mmapEmpty

  private val paramMap: MMap[Signature, IMap[String, JawaType]] = mmapEmpty

  def getParams(sig: Signature): IMap[String, JawaType] = paramMap.getOrElse(sig, imapEmpty)

  protected[java] def findTypeOpt(name: String): Option[JawaType] = {
    typeMap.get(name) match {
      case t @ Some(_) => t
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
              if(!imp.isAsterisk) {
                val typ = new JawaType(imp.getNameAsString)
                if(typ.jawaName.endsWith(name)) {
                  typOpt = Some(typ)
                }
              } else if(imp.isAsterisk) {
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
        typOpt match {
          case Some(t) => typeMap(name) = t
          case None =>
            val dotIndex = name.lastIndexOf('.')
            if(dotIndex >= 0) {
              val innerName = new StringBuilder(name).replace(dotIndex, dotIndex + 1, "$").toString()
              typOpt = findTypeOpt(innerName)
            }
        }
        typOpt
    }
  }

  protected[java] def findType(name: String, pos: RangePosition): JawaType = {
    findTypeOpt(name) match {
      case Some(typ) => typ
      case None =>
        global.reporter.error(pos, s"Could not resolve type: $name")
        val hackType = new JawaType(name)
        typeMap(name) = hackType
        hackType
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
        typStr = findType(cit.getNameAsString, cit.getName.toRange).jawaName
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
        throw Java2JawaException(javaType.toRange, s"${javaType.getClass} is not handled by jawa: $javaType, please contact author: fgwei521@gmail.com")
    }
    new JawaType(typStr, dimension)
  }

  private val superType: MMap[JawaType, JawaType] = mmapEmpty
  protected[java] def getSuperType(typ: JawaType): JawaType = superType.getOrElseUpdate(typ, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)

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
    val baseTypeSymbol: TypeSymbol = TypeSymbol(Token(Tokens.ID, pos, jawaType.baseTyp.apostrophe))(pos)
    val typeFragments: IList[TypeFragment] = (0 until jawaType.dimensions).map { _ =>
      TypeFragment()(pos)
    }.toList
    JawaTypeAst(baseTypeSymbol, typeFragments)(pos)
  }

  def process(resolveBody: Boolean): JawaCompilationUnit = {
    process(sourceFile.getJavaCU, resolveBody)
  }

  def process(cu: CompilationUnit, resolveBody: Boolean): JawaCompilationUnit = {
    val pd = cu.getPackageDeclaration
    if(pd.isPresent) {
      packageName = pd.get().getName.asString()
    }
    val topDecls: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    cu.getTypes.forEach(typ => topDecls ++= processClass(None, typ, resolveBody))
    val result = JawaCompilationUnit(topDecls.toList)(cu.toRange)
    result.topDecls foreach { cid =>
      val typ = cid.cityp
      cid.getAllChildrenInclude foreach (_.enclosingTopLevelClass = typ)
    }
    result
  }

  def processClass(owner: Option[TypeDefSymbol], typ: TypeDeclaration[_], resolveBody: Boolean): IList[JawaClassOrInterfaceDeclaration] = {
    typ match {
      case cid: ClassOrInterfaceDeclaration =>
        val cityp: TypeDefSymbol = owner match {
          case Some(outer) =>
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"${outer.typ.jawaName}$$${cid.getNameAsString}".apostrophe))(cid.getName.toRange)
          case None =>
            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"$packageName.${cid.getNameAsString}".apostrophe))(cid.getName.toRange)
        }
        val annotations: MList[JawaAnnotation] = mlistEmpty
        // add kind annotation
        val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
        val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), {if(cid.isInterface) "interface" else "class"}))(getKeyWordRange(cid))
        annotations += JawaAnnotation(kindKey, Some(kindValue))(getKeyWordRange(cid))
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(cid), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), getJawaAccessFlag(cid.getModifiers, isConstructor = false)))(getKeyWordRange(cid))
        annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(getKeyWordRange(cid))
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
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "class"))(getKeyWordRange(cid))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(getKeyWordRange(cid))
            val sTyp = findType(et)
            superType(cityp.typ) = sTyp
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, sTyp.jawaName.apostrophe))(et.toRange), List(annotation))(et.toRange)
            parentTyps += ei
          }
          cid.getImplementedTypes.forEach{ it =>
            extendAndImplNum -= 1
            val kindKey = Token(Tokens.ID, getKeyWordRange(cid), "kind")
            val kindValue = TokenValue(Token(Tokens.ID, getKeyWordRange(cid), "interface"))(getKeyWordRange(cid))
            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(getKeyWordRange(cid))
            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, it.toRange, findType(it).jawaName.apostrophe))(it.toRange), List(annotation))(it.toRange)
            parentTyps += ei
          }
          val nodes = new NodeList[ClassOrInterfaceType](cid.getExtendedTypes)
          nodes.addAll(cid.getImplementedTypes)
          val firstPos = nodes.get(0).toRange
          val lastPos = nodes.get(nodes.size() - 1).toRange
          Some(ExtendsAndImplementsClauses(parentTyps.toList)(Position.range(firstPos.source, firstPos.start, lastPos.end - firstPos.start + 1)))
        } else {
          None
        }
        val (instanceFieldDeclarationBlock, staticFields, methods, inners) = processMembers(cityp, cid, resolveBody)
        JawaClassOrInterfaceDeclaration(cityp, annotations.toList, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields, methods)(cid.toRange) :: inners
      case _: EnumDeclaration =>
        ilistEmpty // TODO
      case _: AnnotationDeclaration =>
        ilistEmpty // TODO
    }
  }

  def processMembers(owner: TypeDefSymbol, typ: TypeDeclaration[_], resolveBody: Boolean): (IList[InstanceFieldDeclaration], IList[StaticFieldDeclaration], IList[JawaMethodDeclaration], IList[JawaClassOrInterfaceDeclaration]) = {
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
    mds ++= processConstructors(owner, typ, initializers, fields, constructors, resolveBody)
    methods.forEach { m =>
      mds += processMethod(owner, m, resolveBody)
    }
    // Resolve inner classes
    val innerCids: MList[JawaClassOrInterfaceDeclaration] = mlistEmpty
    innerTypes.forEach { inner =>
      innerCids ++= processClass(Some(owner), inner, resolveBody)
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
        val fieldSymbol = FieldDefSymbol(Token(Tokens.ID, va.getName.toRange, s"${owner.typ.jawaName}.${va.getNameAsString}".apostrophe))(va.getName.toRange)
        // add access flag annotation
        val accessFlagKey = Token(Tokens.ID, getKeyWordRange(f), "AccessFlag")
        val accessFlagValue = TokenValue(Token(Tokens.ID, getKeyWordRange(f), getJawaAccessFlag(f.getModifiers, isConstructor = false)))(getKeyWordRange(f))
        val accessFlagAnnotation = JawaAnnotation(accessFlagKey, Some(accessFlagValue))(getKeyWordRange(f))
        if(f.isStatic) {
          staticFields += StaticFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))(f.toRange)
        } else {
          instanceFields += InstanceFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))(f.toRange)
        }
      }
    }
    (instanceFields.toList, staticFields.toList)
  }

  /**
    * Terminology:
    *   No-args constructor: a constructor with no parameters;
    *
    *   Accessible no-args constructor: a no-args constructor in the superclass visible to the subclass. That means it is either public or protected or,
    *                                   if both classes are in the same package, package access;
    *
    *   Default constructor: the public no-args constructor added by the compiler when there is no explicit constructor in the class.
    *
    * So all classes have at least one constructor.
    * Subclasses constructors may specify as the first thing they do which constructor in the superclass to invoke before executing the code in the subclass's constructor.
    * If the subclass constructor does not specify which superclass constructor to invoke then the compiler will automatically call the accessible no-args constructor in the superclass.
    * If the superclass has no no-arg constructor or it isn't accessible then not specifying the superclass constructor to be called (in the subclass constructor)
    * is a compiler error so it must be specified.
    */
  def processConstructors(owner: TypeDefSymbol, typ: TypeDeclaration[_], initializers: NodeList[InitializerDeclaration], fields: NodeList[FieldDeclaration], constructors: NodeList[ConstructorDeclaration], resolveBody: Boolean): IList[JawaMethodDeclaration] = {
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
      mds += processStaticConstructor(owner, typ, staticFieldsWithInitializer.toList, staticInitializers.toList, resolveBody)
    }
    // Process non-static initializer
    val frontStatements: NodeList[Statement] = new NodeList[Statement]()
    nonStaticFieldsWithInitializer foreach { nsfi =>
      val target = new NameExpr(nsfi.getName)
      val value = nsfi.getInitializer.get()
      frontStatements.add(new ExpressionStmt(new AssignExpr(target, value, AssignExpr.Operator.ASSIGN)))
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
      mds += processConstructor(owner, cons, resolveBody)
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

  private def processStaticConstructor(owner: TypeDefSymbol, typ: TypeDeclaration[_], staticFieldsWithInitializer: IList[VariableDeclarator], staticInitializers: IList[InitializerDeclaration], resolveBody: Boolean): JawaMethodDeclaration = {
    val statements: NodeList[Statement] = new NodeList[Statement]()
    staticFieldsWithInitializer foreach { sfi =>
      val target = new NameExpr(sfi.getName)
      val value = sfi.getInitializer.get()
      statements.add(new ExpressionStmt(new AssignExpr(target, value, AssignExpr.Operator.ASSIGN)))
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
      Optional.ofNullable(new BlockStmt(statements)),
      resolveBody
    )
  }

  private def processConstructor(owner: TypeDefSymbol, cons: ConstructorDeclaration, resolveBody: Boolean): JawaMethodDeclaration = {
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
      Optional.ofNullable(cons.getBody),
      resolveBody)
  }

  def processMethod(owner: TypeDefSymbol, md: MethodDeclaration, resolveBody: Boolean): JawaMethodDeclaration = {
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
      md.getBody,
      resolveBody)
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
       bodyBlock: Optional[BlockStmt],
       resolveBody: Boolean): JawaMethodDeclaration = {
    val returnType: JawaTypeAst = handleType(returnTyp)
    val methodSymbol: MethodDefSymbol = MethodDefSymbol(Token(Tokens.ID, namePos, methodName.apostrophe))(namePos)
    val params: MList[Param] = mlistEmpty
    if(!isStatic) {
      val jta = JawaTypeAst(TypeSymbol(owner.id)(namePos), ilistEmpty)(namePos)
      params += getParam(jta, "this", namePos, isThis = true)
    }
    val paramTypes: MList[JawaType] = mlistEmpty
    parameters.forEach { p =>
      val param = processParameter(p)
      paramTypes += param.typ.typ
      params += param
    }
    val annotations: MList[JawaAnnotation] = mlistEmpty
    // add signature annotation
    val sig = JavaKnowledge.genSignature(owner.typ, methodSymbol.methodName, paramTypes.toList, returnType.typ)
    val signatureKey = Token(Tokens.ID, mdPos, "signature")
    val signatureValue = TokenValue(Token(Tokens.ID, mdPos, sig.signature.apostrophe))(mdPos)
    annotations += JawaAnnotation(signatureKey, Some(signatureValue))(mdPos)
    // add access flag annotation
    val accessFlagKey = Token(Tokens.ID, mdPos, "AccessFlag")
    val accessFlagValue = TokenValue(Token(Tokens.ID, mdPos, getJawaAccessFlag(modifiers, isConstructor)))(mdPos)
    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(mdPos)
    // add java annotations
    annotationExprs.forEach{ anno =>
      annotations += processAnnotationExpr(anno)
    }
    paramMap(sig) = params.map { param =>
      param.paramSymbol.varName -> param.typ.typ
    }.toMap
    val body = if(bodyBlock.isPresent) {
      if(resolveBody) {
        processBody(sig, bodyBlock.get)
      } else {
        UnresolvedBodyJava(bodyBlock.get)(bodyBlock.get.toRange, this)
      }
    } else {
      ResolvedBody(ilistEmpty, ilistEmpty, ilistEmpty)(mdPos)
    }
    val jmd = JawaMethodDeclaration(returnType, methodSymbol, params.toList, annotations.toList, body)(mdPos)
    methodSymbol.signature = jmd.signature
    jmd
  }

  def processParameter(param: Parameter): Param = {
    val typ: JawaTypeAst = handleType(param.getType)
    getParam(typ, param.getNameAsString, param.getName.toRange, isThis = false)
  }

  private def getParam(typ: JawaTypeAst, name: String, pos: RangePosition, isThis: Boolean): Param = {
    val paramSymbol: VarDefSymbol = VarDefSymbol(Token(Tokens.ID, pos, name.apostrophe))(pos)
    val annotations: MList[JawaAnnotation] = mlistEmpty
    if(isThis) {
      val kindKey = Token(Tokens.ID, pos, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, pos, "this"))(pos)
      annotations += JawaAnnotation(kindKey, Some(kindValue))(pos)
    } else if(typ.typ.isObject) {
      val kindKey = Token(Tokens.ID, pos, "kind")
      val kindValue = TokenValue(Token(Tokens.ID, pos, "object"))(pos)
      annotations += JawaAnnotation(kindKey, Some(kindValue))(pos)
    }
    Param(typ, paramSymbol, annotations.toList)(pos)
  }

  def processBody(sig: Signature, bodyBlock: BlockStmt): ResolvedBody = {
    val visitor = new MethodBodyVisitor(this, sig, bodyBlock.toRange)
    bodyBlock.accept(visitor, null)
    ResolvedBody(visitor.localVarDeclarations.toList, visitor.locations, visitor.catchClauses.toList)(bodyBlock.toRange)
  }

  def processAnnotationExpr(ae: AnnotationExpr): JawaAnnotation = {
    val annoKey = Token(Tokens.ID, ae.getName.toRange, findType(ae.getNameAsString, ae.getName.toRange).jawaName.apostrophe)
    val annoValue: Option[AnnotationValue] = ae match {
      case _: NormalAnnotationExpr =>
        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
      case _: SingleMemberAnnotationExpr =>
        Some(StatementValue(ilistEmpty)(ae.toRange)) // TODO
      case _ => None // MarkerAnnotationExpr
    }
    JawaAnnotation(annoKey, annoValue)(ae.toRange)
  }

}

case class Java2JawaException(pos: RangePosition, msg: String) extends RuntimeException