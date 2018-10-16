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
//import java.util
//import java.util.Optional
//
//import com.github.javaparser.JavaParser
//import com.github.javaparser.ast._
//import com.github.javaparser.ast.`type`._
//import com.github.javaparser.ast.body._
//import com.github.javaparser.ast.expr._
//import com.github.javaparser.ast.stmt._
//import org.argus.jawa.core.ast.{ExtendAndImplement, ExtendsAndImplementsClauses, FieldDefSymbol, InstanceFieldDeclaration, MethodDefSymbol, Parameter => JawaParameter, ResolvedBody, StaticFieldDeclaration, TokenValue, TypeDefSymbol, TypeFragment, TypeSymbol, UnresolvedBodyJava, VarDefSymbol, Annotation => JawaAnnotation, ClassOrInterfaceDeclaration => JawaClassOrInterfaceDeclaration, MethodDeclaration => JawaMethodDeclaration, Type => JawaTypeAst}
//import org.argus.jawa.core.compiler.lexer.{Token, Tokens}
//import org.argus.jawa.core.io.{Position, RangePosition}
//import org.argus.jawa.core.util._
//import org.argus.jawa.core.{JavaKnowledge, JawaType, Signature}
//
//class ClassResolver(
//    val j2j: Java2Jawa,
//    outer: Option[JawaType],
//    val innerLevel: Int, // used to produce this$0...
//    typ: TypeDeclaration[_],
//    isAnonymous: Boolean,
//    isLocal: Option[Int],
//    staticContext: Boolean) {
//  import j2j._
//
//  protected[javafile] def getJawaAccessFlag(modifiers: util.EnumSet[Modifier], isConstructor: Boolean): String = {
//    val flags: MList[String] = mlistEmpty
//    modifiers.forEach {
//      case Modifier.PUBLIC => flags += "PUBLIC"
//      case Modifier.PROTECTED => flags += "PROTECTED"
//      case Modifier.PRIVATE => flags += "PRIVATE"
//      case Modifier.ABSTRACT => flags += "ABSTRACT"
//      case Modifier.STATIC => flags += "STATIC"
//      case Modifier.FINAL => flags += "FINAL"
//      case Modifier.TRANSIENT => flags += "TRANSIENT"
//      case Modifier.VOLATILE => flags += "VOLATILE"
//      case Modifier.SYNCHRONIZED => flags += "SYNCHRONIZED"
//      case Modifier.NATIVE => flags += "NATIVE"
//      case Modifier.STRICTFP => flags += "STRICTFP"
//      case Modifier.TRANSITIVE => flags += "TRANSITIVE"
//      case Modifier.DEFAULT => flags += "DEFAULT"
//    }
//    if(isConstructor) {
//      flags += "CONSTRUCTOR"
//    }
//    flags.mkString("_")
//  }
//
//  private def handleType(javaType: Type): JawaTypeAst = {
//    val jawaType = imports.findType(javaType)
//    handleJawaType(jawaType, javaType.getElementType.toRange)
//  }
//
//  protected[javafile] def handleJawaType(jawaType: JawaType, pos: Position): JawaTypeAst = {
//    val baseTypeSymbol: TypeSymbol = TypeSymbol(Token(Tokens.ID, pos, jawaType.baseTyp.apostrophe))(pos)
//    val typeFragments: IList[TypeFragment] = (0 until jawaType.dimensions).map { _ =>
//      TypeFragment()(pos)
//    }.toList
//    JawaTypeAst(baseTypeSymbol, typeFragments)(pos)
//  }
//
//  private val paramMap: MMap[Signature, IMap[String, JawaType]] = mmapEmpty
//
//  protected[javafile] def getParams(sig: Signature): IMap[String, JawaType] = paramMap.getOrElse(sig, imapEmpty)
//
//  protected[javafile] var superType: JawaType = JavaKnowledge.OBJECT
//
//  private var anonymousCounter = 0
//  protected[javafile] def getAnonymousClassName: String = {
//    anonymousCounter += 1
//    anonymousCounter.toString
//  }
//
//  private val localClassCounter: MMap[String, Int] = mmapEmpty
//  protected[javafile] def getLocalClassNum(name: String): Int = {
//    val c = localClassCounter.getOrElse(name, 1)
//    localClassCounter(name) = c + 1
//    c
//  }
//
//  private val staticMethods: MSet[Signature] = msetEmpty
//  protected[javafile] def isStaticMethod(sig: Signature): Boolean = staticMethods.contains(sig)
//
//  def process(): JawaClassOrInterfaceDeclaration = {
//    typ match {
//      case cid: ClassOrInterfaceDeclaration =>
//        val cid_range = cid.toRange
//        val cityp: TypeDefSymbol = outer match {
//          case Some(o) =>
//            val name = isLocal match {
//              case Some(i) => s"$i${cid.getNameAsString}"
//              case None => cid.getNameAsString
//            }
//            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"${o.jawaName}$$$name".apostrophe))(cid.getName.toRange)
//          case None =>
//            TypeDefSymbol(Token(Tokens.ID, cid.getName.toRange, s"$packageName.${cid.getNameAsString}".apostrophe))(cid.getName.toRange)
//        }
//        val annotations: MList[JawaAnnotation] = mlistEmpty
//        // add kind annotation
//        val kindKey = Token(Tokens.ID, cid_range, "kind")
//        val kindValue = TokenValue(Token(Tokens.ID, cid_range, {if(cid.isInterface) "interface" else "class"}))(cid_range)
//        annotations += JawaAnnotation(kindKey, Some(kindValue))(cid_range)
//        // add access flag annotation
//        val accessFlagKey = Token(Tokens.ID, cid_range, "AccessFlag")
//        val accessFlagStr = getJawaAccessFlag(cid.getModifiers, isConstructor = false)
//        val accessFlagValue = TokenValue(Token(Tokens.ID, cid_range, accessFlagStr))(cid_range)
//        annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(cid_range)
//        // add java annotations
//        cid.getAnnotations.forEach{ anno =>
//          annotations += processAnnotationExpr(anno)
//        }
//
//        // Resolve extends
//        val extendsAndImplementsClausesOpt: Option[ExtendsAndImplementsClauses] = if(cid.getExtendedTypes.size() + cid.getImplementedTypes.size() > 0) {
//          val parentTyps: MList[ExtendAndImplement] = mlistEmpty
//          cid.getExtendedTypes.forEach{ et =>
//            val kindKey = Token(Tokens.ID, cid_range, "kind")
//            val kindValue = TokenValue(Token(Tokens.ID, cid_range, "class"))(cid_range)
//            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(cid_range)
//            val sTyp = imports.findType(et)
//            superType = sTyp
//            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, et.toRange, sTyp.jawaName.apostrophe))(et.toRange), List(annotation))(et.toRange)
//            parentTyps += ei
//          }
//          cid.getImplementedTypes.forEach{ it =>
//            val kindKey = Token(Tokens.ID, cid_range, "kind")
//            val kindValue = TokenValue(Token(Tokens.ID, cid_range, "interface"))(cid_range)
//            val annotation: JawaAnnotation = JawaAnnotation(kindKey, Some(kindValue))(cid_range)
//            val ei = ExtendAndImplement(TypeSymbol(Token(Tokens.ID, it.toRange, imports.findType(it).jawaName.apostrophe))(it.toRange), List(annotation))(it.toRange)
//            parentTyps += ei
//          }
//          val nodes = new NodeList[ClassOrInterfaceType](cid.getExtendedTypes)
//          nodes.addAll(cid.getImplementedTypes)
//          val firstPos = nodes.get(0).toRange
//          val lastPos = nodes.get(nodes.size() - 1).toRange
//          Some(ExtendsAndImplementsClauses(parentTyps.toList)(Position.range(firstPos.source, firstPos.start, lastPos.end - firstPos.start + 1)))
//        } else {
//          None
//        }
//        val (instanceFieldDeclarationBlock, staticFields, methods) = processMembers(outer, cityp, cid)
//        val jcid = JawaClassOrInterfaceDeclaration(cityp, annotations.toList, extendsAndImplementsClausesOpt, instanceFieldDeclarationBlock, staticFields, methods)(cid.toRange)
//        topDecls += jcid
//        jcid.getAllChildrenInclude foreach (_.enclosingTopLevelClass = cityp)
//        jcid
//      case _: EnumDeclaration =>
//        throw Java2JawaException(typ.toRange, "Have not handle EnumDeclaration") // TODO
//      case _: AnnotationDeclaration =>
//        throw Java2JawaException(typ.toRange, "Have not handle AnnotationDeclaration") // TODO
//    }
//  }
//
//  def processMembers(outer: Option[JawaType], owner: TypeDefSymbol, typ: TypeDeclaration[_]): (IList[InstanceFieldDeclaration], IList[StaticFieldDeclaration], IList[JawaMethodDeclaration]) = {
//    val initializers = new NodeList[InitializerDeclaration]()
//    val fields = new NodeList[FieldDeclaration]()
//    val constructors = new NodeList[ConstructorDeclaration]()
//    val methods = new NodeList[MethodDeclaration]()
//    val innerTypes = new NodeList[TypeDeclaration[_]]()
//    val enumConstants = new NodeList[EnumConstantDeclaration]() // TODO
//    typ.getMembers.forEach {
//      case id: InitializerDeclaration =>
//        initializers.add(id)
//      case fd: FieldDeclaration =>
//        fields.add(fd)
//      case cd: ConstructorDeclaration =>
//        constructors.add(cd)
//      case md: MethodDeclaration =>
//        methods.add(md)
//      case td: TypeDeclaration[_] =>
//        innerTypes.add(td)
//      case ecd: EnumConstantDeclaration =>
//        enumConstants.add(ecd)
//      case u: BodyDeclaration[_] =>
//        global.reporter.warning(u.toRange, "Unhandled member: " + u)
//    }
//
//    // Resolve methods
//    val mds: MList[JawaMethodDeclaration] = mlistEmpty
//    mds ++= processConstructors(owner, typ, initializers, fields, constructors)
//    methods.forEach { m =>
//      mds += processMethod(owner, m)
//    }
//
//    val (instanceFields, staticFields) = processFields(owner, fields)
//
//    // Resolve inner classes
//    val iLevel = if(staticContext) {
//      1
//    } else {
//      innerLevel + 1
//    }
//    innerTypes.forEach { inner =>
//      val static = inner.getModifiers.contains(Modifier.STATIC)
//      new ClassResolver(j2j, Some(owner.typ), iLevel, inner, false, None, static).process()
//    }
//    (instanceFields, staticFields, mds.toList)
//  }
//
//  def processFields(owner: TypeDefSymbol, fields: NodeList[FieldDeclaration]): (IList[InstanceFieldDeclaration], IList[StaticFieldDeclaration]) = {
//    // Resolve fields
//    val instanceFields: MList[InstanceFieldDeclaration] = mlistEmpty
//    val staticFields: MList[StaticFieldDeclaration] = mlistEmpty
//    fields.forEach { f =>
//      f.getVariables.forEach{ va =>
//        val jawaTypeAst = handleType(va.getType)
//        val fieldSymbol = FieldDefSymbol(Token(Tokens.ID, va.getName.toRange, s"${owner.typ.jawaName}.${va.getNameAsString}".apostrophe))(va.getName.toRange)
//        // add access flag annotation
//        val accessFlagKey = Token(Tokens.ID, f.toRange, "AccessFlag")
//        val accessFlagValue = TokenValue(Token(Tokens.ID, f.toRange, getJawaAccessFlag(f.getModifiers, isConstructor = false)))(f.toRange)
//        val accessFlagAnnotation = JawaAnnotation(accessFlagKey, Some(accessFlagValue))(f.toRange)
//        if(f.isStatic) {
//          staticFields += StaticFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))(f.toRange)
//        } else {
//          instanceFields += InstanceFieldDeclaration(jawaTypeAst, fieldSymbol, List(accessFlagAnnotation))(f.toRange)
//        }
//      }
//    }
//    (instanceFields.toList, staticFields.toList)
//  }
//
//  /**
//    * Terminology:
//    *   No-args constructor: a constructor with no parameters;
//    *
//    *   Accessible no-args constructor: a no-args constructor in the superclass visible to the subclass. That means it is either public or protected or,
//    *                                   if both classes are in the same package, package access;
//    *
//    *   Default constructor: the public no-args constructor added by the compiler when there is no explicit constructor in the class.
//    *
//    * So all classes have at least one constructor.
//    * Subclasses constructors may specify as the first thing they do which constructor in the superclass to invoke before executing the code in the subclass's constructor.
//    * If the subclass constructor does not specify which superclass constructor to invoke then the compiler will automatically call the accessible no-args constructor in the superclass.
//    * If the superclass has no no-arg constructor or it isn't accessible then not specifying the superclass constructor to be called (in the subclass constructor)
//    * is a compiler error so it must be specified.
//    */
//  def processConstructors(
//      owner: TypeDefSymbol,
//      typ: TypeDeclaration[_],
//      initializers: NodeList[InitializerDeclaration],
//      fields: NodeList[FieldDeclaration],
//      constructors: NodeList[ConstructorDeclaration]): IList[JawaMethodDeclaration] = {
//    val staticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
//    val nonStaticFieldsWithInitializer: MList[VariableDeclarator] = mlistEmpty
//    fields.forEach { f =>
//      if(f.isStatic) {
//        f.getVariables.forEach { v =>
//          if(v.getInitializer.isPresent) {
//            staticFieldsWithInitializer += v
//          }
//        }
//      } else {
//        f.getVariables.forEach { v =>
//          if(v.getInitializer.isPresent) {
//            nonStaticFieldsWithInitializer += v
//          }
//        }
//      }
//    }
//    val staticInitializers: MList[InitializerDeclaration] = mlistEmpty
//    val nonStaticInitializers: MList[InitializerDeclaration] = mlistEmpty
//    initializers.forEach { i =>
//      if(i.isStatic) {
//        staticInitializers += i
//      } else {
//        nonStaticInitializers += i
//      }
//    }
//    val mds: MList[JawaMethodDeclaration] = mlistEmpty
//    // Process static initializer
//    if(staticFieldsWithInitializer.nonEmpty || staticInitializers.nonEmpty) {
//      mds += processStaticConstructor(owner, typ, staticFieldsWithInitializer.toList, staticInitializers.toList)
//    }
//    // Process non-static initializer
//    val frontStatements: NodeList[Statement] = new NodeList[Statement]()
//    nonStaticFieldsWithInitializer foreach { nsfi =>
//      val target = new NameExpr(nsfi.getName)
//      val value = nsfi.getInitializer.get()
//      frontStatements.add(new ExpressionStmt(new AssignExpr(target, value, AssignExpr.Operator.ASSIGN)))
//    }
//    nonStaticInitializers foreach { nsi =>
//      frontStatements.addAll(nsi.getBody.getStatements)
//    }
//    if(constructors.isEmpty) {
//      val modifiers = util.EnumSet.noneOf(classOf[Modifier])
//      if(typ.getModifiers.contains(Modifier.PUBLIC)) {
//        modifiers.add(Modifier.PUBLIC)
//      }
//      constructors.add(new ConstructorDeclaration(modifiers, new NodeList[AnnotationExpr], new NodeList[TypeParameter], typ.getName, new NodeList[Parameter], new NodeList[ReferenceType], new BlockStmt()))
//    }
//    constructors.forEach { cons =>
//      if(!staticContext && innerLevel > 0) {
//        // add field
//        // final synthetic
//        val modifier = util.EnumSet.of(Modifier.FINAL)
//        val varType = JavaParser.parseClassOrInterfaceType(outer.get.canonicalName)
//        val varName = s"this$$${innerLevel - 1}"
//        val vd = new VariableDeclarator(varType, varName)
//        val fd = new FieldDeclaration(modifier, vd)
//        fields.add(fd)
//
//        // add param to constructor
//        val paramName = s"${outer.get.simpleName}$$outer"
//        val param = new Parameter(varType, paramName)
//        cons.getParameters.add(0, param)
//
//        // add assign
//        val target = new NameExpr(varName)
//        val value = new NameExpr(paramName)
//        frontStatements.add(0, new ExpressionStmt(new AssignExpr(target, value, AssignExpr.Operator.ASSIGN)))
//      }
//      val bodyBlock = makeConstructorBody(frontStatements, cons.getBody.getStatements)
//      cons.setBody(bodyBlock)
//      mds += processConstructor(owner, cons)
//    }
//    mds.toList
//  }
//
//  private def makeConstructorBody(frontStatements: NodeList[Statement], bodyStatements: NodeList[Statement]): BlockStmt = {
//    val statements: NodeList[Statement] = new NodeList[Statement]()
//    // Check do we need to add super no-arg constructor call.
//    if(bodyStatements.isNonEmpty && bodyStatements.get(0).isInstanceOf[ExplicitConstructorInvocationStmt]) {
//      statements.addAll(bodyStatements)
//      statements.addAll(1, frontStatements)
//    } else {
//      val ecis = new ExplicitConstructorInvocationStmt(false, null, new NodeList[Expression]())
//      statements.add(ecis)
//      statements.addAll(frontStatements)
//      statements.addAll(bodyStatements)
//    }
//    new BlockStmt(statements)
//  }
//
//  private def processStaticConstructor(owner: TypeDefSymbol, typ: TypeDeclaration[_], staticFieldsWithInitializer: IList[VariableDeclarator], staticInitializers: IList[InitializerDeclaration]): JawaMethodDeclaration = {
//    val statements: NodeList[Statement] = new NodeList[Statement]()
//    staticFieldsWithInitializer foreach { sfi =>
//      val target = new NameExpr(sfi.getName)
//      val value = sfi.getInitializer.get()
//      statements.add(new ExpressionStmt(new AssignExpr(target, value, AssignExpr.Operator.ASSIGN)))
//    }
//    staticInitializers foreach { si =>
//      statements.addAll(si.getBody.getStatements)
//    }
//    doProcessMethod(
//      owner,
//      typ.toRange,
//      new VoidType(),
//      "<clinit>",
//      typ.getName.toRange,
//      isStatic = true,
//      isConstructor = true,
//      new NodeList[Parameter](),
//      util.EnumSet.of(Modifier.STATIC),
//      new NodeList[AnnotationExpr](),
//      Optional.ofNullable(new BlockStmt(statements)))
//  }
//
//  private def processConstructor(owner: TypeDefSymbol, cons: ConstructorDeclaration): JawaMethodDeclaration = {
//    doProcessMethod(
//      owner,
//      cons.toRange,
//      new VoidType(),
//      "<init>",
//      cons.getName.toRange,
//      cons.isStatic,
//      isConstructor = true,
//      cons.getParameters,
//      cons.getModifiers,
//      cons.getAnnotations,
//      Optional.ofNullable(cons.getBody))
//  }
//
//  def processMethod(owner: TypeDefSymbol, md: MethodDeclaration): JawaMethodDeclaration = {
//    doProcessMethod(
//      owner,
//      md.toRange,
//      md.getType,
//      md.getNameAsString,
//      md.getName.toRange,
//      md.isStatic,
//      isConstructor = false,
//      md.getParameters,
//      md.getModifiers,
//      md.getAnnotations,
//      md.getBody)
//  }
//
//  private def doProcessMethod(
//      owner: TypeDefSymbol,
//      mdPos: RangePosition,
//      returnTyp: Type,
//      methodName: String,
//      namePos: RangePosition,
//      isStatic: Boolean,
//      isConstructor: Boolean,
//      parameters: NodeList[Parameter],
//      modifiers: util.EnumSet[Modifier],
//      annotationExprs: NodeList[AnnotationExpr],
//      bodyBlock: Optional[BlockStmt]): JawaMethodDeclaration = {
//    val returnType: JawaTypeAst = handleType(returnTyp)
//    val methodSymbol: MethodDefSymbol = MethodDefSymbol(Token(Tokens.ID, namePos, methodName.apostrophe))(namePos)
//    val params: MList[JawaParameter] = mlistEmpty
//    if(!isStatic) {
//      val jta = JawaTypeAst(TypeSymbol(owner.id)(namePos), ilistEmpty)(namePos)
//      params += getParam(jta, "this", namePos, isThis = true)
//    }
//    val paramTypes: MList[JawaType] = mlistEmpty
//    parameters.forEach { p =>
//      val param = processParameter(p)
//      paramTypes += param.typ.typ
//      params += param
//    }
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    // add signature annotation
//    val sig = JavaKnowledge.genSignature(owner.typ, methodSymbol.methodName, paramTypes.toList, returnType.typ)
//    val signatureKey = Token(Tokens.ID, mdPos, "signature")
//    val signatureValue = TokenValue(Token(Tokens.ID, mdPos, sig.signature.apostrophe))(mdPos)
//    annotations += JawaAnnotation(signatureKey, Some(signatureValue))(mdPos)
//    // add access flag annotation
//    val accessFlagKey = Token(Tokens.ID, mdPos, "AccessFlag")
//    val accessFlagValue = TokenValue(Token(Tokens.ID, mdPos, getJawaAccessFlag(modifiers, isConstructor)))(mdPos)
//    annotations += JawaAnnotation(accessFlagKey, Some(accessFlagValue))(mdPos)
//    // add java annotations
//    annotationExprs.forEach{ anno =>
//      annotations += processAnnotationExpr(anno)
//    }
//    paramMap(sig) = params.map { param =>
//      param.paramSymbol.varName -> param.typ.typ
//    }.toMap
//    val body = if(bodyBlock.isPresent) {
//      UnresolvedBodyJava(bodyBlock.get)(bodyBlock.get.toRange, this)
//    } else {
//      ResolvedBody(ilistEmpty, ilistEmpty, ilistEmpty)(mdPos)
//    }
//    val jmd = JawaMethodDeclaration(returnType, methodSymbol, params.toList, annotations.toList, body)(mdPos)
//    methodSymbol.signature = jmd.signature
//    if(isStatic) {
//      staticMethods += jmd.signature
//    }
//    jmd
//  }
//
//  def processParameter(param: Parameter): JawaParameter = {
//    val typ: JawaTypeAst = handleType(param.getType)
//    getParam(typ, param.getNameAsString, param.getName.toRange, isThis = false)
//  }
//
//  private def getParam(typ: JawaTypeAst, name: String, pos: RangePosition, isThis: Boolean): JawaParameter = {
//    val paramSymbol: VarDefSymbol = VarDefSymbol(Token(Tokens.ID, pos, name.apostrophe))(pos)
//    val annotations: MList[JawaAnnotation] = mlistEmpty
//    if(isThis) {
//      val kindKey = Token(Tokens.ID, pos, "kind")
//      val kindValue = TokenValue(Token(Tokens.ID, pos, "this"))(pos)
//      annotations += JawaAnnotation(kindKey, Some(kindValue))(pos)
//    } else if(typ.typ.isObject) {
//      val kindKey = Token(Tokens.ID, pos, "kind")
//      val kindValue = TokenValue(Token(Tokens.ID, pos, "object"))(pos)
//      annotations += JawaAnnotation(kindKey, Some(kindValue))(pos)
//    }
//    JawaParameter(typ, paramSymbol, annotations.toList)(pos)
//  }
//
//  def processBody(sig: Signature, bodyBlock: BlockStmt): ResolvedBody = {
//    val visitor = new MethodBodyVisitor(this, sig, bodyBlock.toRange)
//    bodyBlock.accept(visitor, null)
//    ResolvedBody(visitor.localVarDeclarations.toList, visitor.locations, visitor.catchClauses.toList)(bodyBlock.toRange)
//  }
//}
