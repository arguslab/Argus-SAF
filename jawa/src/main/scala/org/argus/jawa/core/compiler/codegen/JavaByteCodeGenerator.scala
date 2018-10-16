/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.codegen

import org.argus.jawa.core.util._
import java.io.PrintWriter
import java.io.File
import java.io.DataOutputStream
import java.io.FileOutputStream
import java.lang.{Double, Float, Long}

import org.argus.jawa.core.ast
import org.argus.jawa.core.ast._
import org.argus.jawa.core.compiler.lexer.Tokens._
import org.argus.jawa.core.compiler.parser.JawaParserException
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{AccessFlag, JavaKnowledge, JawaPackage, JawaType}
import org.argus.jawa.core.io.{Position, RangePosition}
import org.objectweb.asm._
import org.objectweb.asm.util.TraceClassVisitor

object JavaByteCodeGenerator {
  def outputByteCodes(pw: PrintWriter, bytecodes: Array[Byte]): Unit = {
    val cr = new ClassReader(bytecodes)
    val tcv = new TraceClassVisitor(pw)
    cr.accept(tcv, ClassReader.SKIP_FRAMES)
    pw.flush()
  }
  
  def writeClassFile(outputPath: String, pkg: JawaPackage, className: String, bytecode: Array[Byte]): Unit = {
    val classfileDirPath: String = outputPath + File.separator + pkg.toPkgString(File.separator)
    val classfileDir: File = new File(classfileDirPath)
    if(!classfileDir.exists()){
      classfileDir.mkdirs()
    }
    val dout = new DataOutputStream(new FileOutputStream(new File(classfileDir, className + ".class")))
    dout.write(bytecode)
    dout.flush()
    dout.close()
  }
}

class JavaByteCodeGenerator(javaVersion: Int) {
  def this(javaVersionStr: String) = this(javaVersionStr match {
    case "1.1" => Opcodes.V1_1
    case "1.2" => Opcodes.V1_2
    case "1.3" => Opcodes.V1_3
    case "1.4" => Opcodes.V1_4
    case "1.5" => Opcodes.V1_5
    case "1.6" => Opcodes.V1_6
    case "1.7" => Opcodes.V1_7
    case "1.8" => Opcodes.V1_8
    case _ => Opcodes.V1_8 // by default just use the newest version to generate code
  })

  private val classes: MMap[JawaType, Array[Byte]] = mmapEmpty
  
  def getClasses: IMap[JawaType, Array[Byte]] = classes.toMap
  
  def generate(globalOpt: Option[Global], cu: CompilationUnit): IMap[JawaType, Array[Byte]] = {
    if(!cu.localTypResolved) throw new RuntimeException("Cannot generate bytecode for untyped code. Use GenerateTypedJawa() to transform untyped code to typed.")
    cu.topDecls foreach { cid =>
      visitClass(globalOpt, cid, javaVersion)
    }
    getClasses
  }
  
  private def getClassName(name: String): String = {
    name.replaceAll("\\.", "/")
  }
  
  private def visitClass(globalOpt: Option[Global], cid: ClassOrInterfaceDeclaration, javaVersion: Int): Unit = {
    val cw: ClassWriter = globalOpt match {
      case Some(global) => new TraceClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, global)
      case None => new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS)
    }
    val af: Int = AccessFlag.getAccessFlags(cid.accessModifier)
    var mod = AccessFlag.getJavaFlags(af)
    
    val superName: String = cid.superClassOpt match {
      case Some(su) => getClassName(su.name)
      case None => if(cid.typ != JavaKnowledge.OBJECT) getClassName(JavaKnowledge.OBJECT.jawaName) else null
    }
    val interfaceNames: IList[String] = cid.interfaces map(i => getClassName(i.name))
    if(!AccessFlag.isInterface(af) && (superName != null || interfaceNames.nonEmpty)) mod = mod | Opcodes.ACC_SUPER
    if(AccessFlag.isFinal(af)) mod = mod | Opcodes.ACC_SUPER
    cw.visit(javaVersion, mod, getClassName(cid.typ.name), null, superName, interfaceNames.toArray)
    cw.visitSource(null, null)
    cid.fields foreach { fd =>
      visitField(cw, fd)
    }
    cid.methods foreach { md =>
      visitMethod(cw, md)
    }
    cw.visitEnd()
    
    this.classes(cid.typ) = cw.toByteArray
  }
  
  private def visitField(cw: ClassWriter, fd: ast.Field with Declaration): Unit = {
    val af: Int = AccessFlag.getAccessFlags(fd.accessModifier)
    val mod: Int = AccessFlag.getJavaFlags(af)
    val typ: String = JavaKnowledge.formatTypeToSignature(fd.typ.typ)
    cw.visitField(mod, fd.fieldName, typ, null, null).visitEnd()
  }
  
  case class LocalIndex(varname: String, typ: JawaType, index: Int)
  private val locals: MMap[String, LocalIndex] = mmapEmpty
  private val locations: MMap[String, Label] = mmapEmpty
  private var maxLocals: Int = 0
  
  private def visitMethod(cw: ClassWriter, md: MethodDeclaration): Unit = {
    val af: Int = AccessFlag.getAccessFlags(md.accessModifier)
    val mod: Int = AccessFlag.getJavaFlags(af)
    val mv = cw.visitMethod(mod, md.name, md.signature.getDescriptor, null, null)
    val body: ResolvedBody = md.body match {
      case rb: ResolvedBody =>
        rb
      case ub: Body with Unresolved =>
        ub.resolve(md.signature)
    }
    var i = 0
    md.thisParam.foreach{ t =>
      locals(t.name) = LocalIndex("this", t.typ.typ, i)
      i += 1
    }
    md.paramList.foreach{ param =>
      locals(param.name) = LocalIndex(param.name, param.typ.typ, i)
      if(param.typ.typ.name == "long" || param.typ.typ.name == "double") i += 1
      i += 1
    }
    body.locals.foreach{ local =>
      locals(local.varSymbol.varName) = LocalIndex(local.varSymbol.varName, local.typ, i)
      if(local.typ.name == "long" || local.typ.name == "double") i += 1
      i += 1
    }
    this.maxLocals = this.locals.size
    body.locations foreach { location =>
      val locLabel = new Label()
      this.locations(location.locationUri) = locLabel
    }
    body.catchClauses foreach { catchClause =>
      val from: Label = this.locations(catchClause.range.fromLocation.location)
      val to: Label = this.locations(catchClause.range.toLocation.location)
      val target: Label = this.locations(catchClause.targetLocation.location)
      val typ: String = getClassName(catchClause.typ.typ.name)
      mv.visitTryCatchBlock(from, to, target, typ)
    }
    mv.visitCode()

    val initLabel = new Label()
    mv.visitLabel(initLabel)

    val start: Int = body.locations.headOption match {
      case Some(Location(_, EmptyStatement(_))) => 1
      case _ => 0
    }
    val end: Int = body.locations.lastOption match {
      case Some(Location(_, EmptyStatement(_))) => body.locations.size - 1
      case _ => body.locations.size
    }
    (start until end) foreach { i =>
      val location = body.location(i)
      val locLabel = this.locations(location.locationUri)
      mv.visitLabel(locLabel)
      val line = location.pos match {
        case rp: RangePosition => rp.line
        case _ => 0
      }
      mv.visitLineNumber(line, locLabel)
      visitLocation(mv, location)
    }
    val endLabel = new Label()
    mv.visitLabel(endLabel)
    this.locals foreach { case (_, local) =>
      mv.visitLocalVariable(local.varname, JavaKnowledge.formatTypeToSignature(local.typ), null, initLabel, endLabel, local.index)
    }
    try {
      mv.visitMaxs(0, this.maxLocals)
    } catch {
      case ie: Exception =>
        throw ie
    }
    mv.visitEnd()
    this.locals.clear()
    this.locations.clear()
    this.maxLocals = 0
  }
  
  private def visitLocation(mv: MethodVisitor, jl: Location): Unit = {
    jl.statement match {
      case cs: CallStatement =>
        visitCallStatement(mv, cs)
      case as: AssignmentStatement =>
        visitAssignmentStatement(mv, as)
      case ts: ThrowStatement =>
        visitThrowStatement(mv, ts)
      case is: IfStatement =>
        visitIfStatement(mv, is)
      case gs: GotoStatement =>
        visitGotoStatement(mv, gs)
      case ss: SwitchStatement =>
        visitSwitchStatement(mv, ss)
      case rs: ReturnStatement =>
        visitReturnStatement(mv, rs)
      case ms: MonitorStatement =>
        visitMonitorStatement(mv, ms)
      case _: EmptyStatement =>
        
      case _ =>
    }
  }
  
  private def visitMonitorStatement(mv: MethodVisitor, ms: MonitorStatement): Unit = {
    import org.argus.jawa.core.compiler.lexer.Tokens._
    ms.monitor.tokenType match {
      case MONITOR_ENTER => 
        visitVarLoad(mv, ms.varSymbol.varName)
//        mv.visitInsn(Opcodes.DUP)
//        this.maxLocals += 1
//        mv.visitVarInsn(Opcodes.ASTORE, this.maxLocals)
        mv.visitInsn(Opcodes.MONITORENTER)
      case MONITOR_EXIT => 
//        mv.visitVarInsn(Opcodes.ALOAD, this.maxLocals)
//        this.maxLocals -= 1
        visitVarLoad(mv, ms.varSymbol.varName)
        mv.visitInsn(Opcodes.MONITOREXIT)
      case _ => throw new JawaByteCodeGenException(ms.pos, "visitMonitorStatement problem: " + ms)
    }
  }
  
  private def visitThrowStatement(mv: MethodVisitor, ts: ThrowStatement): Unit = {
    visitVarLoad(mv, ts.varSymbol.varName)
    mv.visitInsn(Opcodes.ATHROW)
  }
  
  private def visitSwitchStatement(mv: MethodVisitor, ss: SwitchStatement): Unit = {
    val dflt: Label = ss.defaultCaseOpt match {
      case Some(dc) => locations(dc.targetLocation.location)
      case None => locations(ss.cases.last.targetLocation.location)
    }
    val key = ss.condition.varName
    visitVarLoad(mv, key)
    val size = ss.cases.size
    val keys: MList[Int] = mlistEmpty
    val labels: MList[Label] = mlistEmpty
    
    for(i <- 0 until size){
      val ca = ss.cases(i)
      keys += ca.constant.text.toInt
      labels += locations(ca.targetLocation.location)
    }
    mv.visitLookupSwitchInsn(dflt, keys.toArray, labels.toArray)
  }
  
  private def visitGotoStatement(mv: MethodVisitor, gs: GotoStatement): Unit = {
    val target = this.locations(gs.targetLocation.location)
    mv.visitJumpInsn(Opcodes.GOTO, target)
  }
  
  private def visitIfStatement(mv: MethodVisitor, is: IfStatement): Unit = {
    var isNull: Boolean = false
    var isObject: Boolean = false
    var isBoolean: Boolean = false
    val left = is.cond.left.varName
    locals(left).typ match {
      case pt if pt.jawaName == "boolean" =>
        isBoolean = true
      case _ =>
    }
    is.cond.right match {
      case Left(right) =>
        if(locals(right.varName).typ.isObject) isObject = true
      case Right(right) => 
        right match {
          case Right(_) => isNull = true
          case _ =>
        }
    }
    visitVarLoad(mv, left)
    
    is.cond.right match {
      case Left(right) => 
        visitVarLoad(mv, right.varName)
      case Right(right) => 
        right match {
          case Left(i) => if(!isBoolean)generateIntConst(mv, i.getInt)
          case Right(_) =>
        }
    }
    val target = this.locations(is.targetLocation.location)
    if(isNull){
      is.cond.op.text match {
        case "==" => mv.visitJumpInsn(Opcodes.IFNULL, target)
        case "!=" => mv.visitJumpInsn(Opcodes.IFNONNULL, target)
      }
    } else if(isObject) {
      is.cond.op.text match {
        case "==" => mv.visitJumpInsn(Opcodes.IF_ACMPEQ, target)
        case "!=" => mv.visitJumpInsn(Opcodes.IF_ACMPNE, target)
      }
    } else if (isBoolean) {
      is.cond.op.text match {
        case "==" => mv.visitJumpInsn(Opcodes.IFEQ, target)
        case "!=" => mv.visitJumpInsn(Opcodes.IFNE, target)
        case "<"  => mv.visitJumpInsn(Opcodes.IFLT, target)
        case ">=" => mv.visitJumpInsn(Opcodes.IFGE, target)
        case ">"  => mv.visitJumpInsn(Opcodes.IFGT, target)
        case "<=" => mv.visitJumpInsn(Opcodes.IFLE, target)
      }
    } else {
      is.cond.op.text match {
        case "==" => mv.visitJumpInsn(Opcodes.IF_ICMPEQ, target)
        case "!=" => mv.visitJumpInsn(Opcodes.IF_ICMPNE, target)
        case "<"  => mv.visitJumpInsn(Opcodes.IF_ICMPLT, target)
        case ">=" => mv.visitJumpInsn(Opcodes.IF_ICMPGE, target)
        case ">"  => mv.visitJumpInsn(Opcodes.IF_ICMPGT, target)
        case "<=" => mv.visitJumpInsn(Opcodes.IF_ICMPLE, target)
        case _ =>    throw new JawaByteCodeGenException(is.pos, "visitIfStatement problem: " + is)
      }
    }
  }
  
  private def visitReturnStatement(mv: MethodVisitor, rs: ReturnStatement): Unit = {
    rs.varOpt match {
      case Some(va) => 
        visitVarLoad(mv, va.varName)
        this.locals(va.varName).typ.name match {
          case "byte" | "char" | "short" | "int" | "boolean" => mv.visitInsn(Opcodes.IRETURN)
          case "long" => mv.visitInsn(Opcodes.LRETURN)
          case "float" => mv.visitInsn(Opcodes.FRETURN)
          case "double" => mv.visitInsn(Opcodes.DRETURN)
          case _ => mv.visitInsn(Opcodes.ARETURN)
        }
      case None => 
        mv.visitInsn(Opcodes.RETURN)
    }
  }
  
  private def visitCallStatement(mv: MethodVisitor, cs: CallStatement): Unit = {
    val isStatic: Boolean = cs.isStatic
    cs.recvOpt match {
      case Some(recv) =>
        require(!isStatic, cs.toString)
        mv.visitVarInsn(Opcodes.ALOAD, this.locals(recv).index)
      case None =>
        require(isStatic)
    }
    for(i <- 0 until cs.signature.getParameterNum){
      val arg = cs.arg(i)
      val reqtyp: JawaType = cs.signature.getParameterTypes(i)
      val acttyp: JawaType = this.locals(arg).typ
      visitVarLoad(mv, arg)
      handleTypeImplicitConvert(mv, reqtyp, acttyp)
    }
        
    val opcode = 
      if(cs.isVirtual) Opcodes.INVOKEVIRTUAL
      else if(cs.isStatic) Opcodes.INVOKESTATIC
      else if(cs.isDirect || cs.isSuper) Opcodes.INVOKESPECIAL
      else if(cs.isInterface) Opcodes.INVOKEINTERFACE
      else Opcodes.INVOKEVIRTUAL

    val className: String = getClassName(cs.signature.getClassType.name)
    val methodName: String = cs.signature.methodName
    val descriptor: String = cs.signature.getDescriptor
    val ltf = opcode == Opcodes.INVOKEINTERFACE
    mv.visitMethodInsn(opcode, className, methodName, descriptor, ltf)
    
    val ret = cs.signature.getReturnType
    ret.name match {
      case "void" =>
      case typ =>
        cs.lhsOpt match {
          case Some(lhs) => visitVarStore(mv, lhs.name)
          case _ => 
            if(typ == "long" || typ == "double") mv.visitInsn(Opcodes.POP2)
            else mv.visitInsn(Opcodes.POP)
        }
    }
  }

  private def visitAssignmentStatement(mv: MethodVisitor, as: AssignmentStatement): Unit = {
    val lhs = as.lhs
    val rhs = as.rhs
    
    //This is used to deal with implicit type conversion
    val lhsTyp: JawaType = lhs match {
      case ie: IndexingExpression =>
        visitArrayAccess(mv, ie)
        val typ = this.locals(ie.base).typ
        JawaType.generateType(typ.baseTyp, typ.dimensions - ie.dimensions)
      case ae: AccessExpression =>
        visitFieldAccess(mv, ae)
        ae.typ
      case vne: VariableNameExpression =>
        this.locals(vne.name).typ
      case sfae: StaticFieldAccessExpression =>
        sfae.typ
      case a => // This will never happen
        throw new JawaByteCodeGenException(lhs.pos, "visitAssignmentStatement problem: " + a)
    }
    
    rhs match {
      case _: TupleExpression =>
        lhs match {
          case vne: VariableNameExpression =>
            visitVarLoad(mv, vne.name)
          case sfae: StaticFieldAccessExpression =>
            mv.visitFieldInsn(Opcodes.GETSTATIC, sfae.fieldNameSymbol.baseType.name.replaceAll("\\.", "/"), sfae.fieldNameSymbol.fieldName, JavaKnowledge.formatTypeToSignature(lhsTyp))
          case _ =>
        }
      case _ =>
    }
    
    visitRhsExpression(mv, rhs, lhsTyp)
    visitLhsExpression(mv, lhs)
  }
  
  private def visitLhsExpression(mv: MethodVisitor, lhs: Expression with LHS): Unit = lhs match {
    case vne: VariableNameExpression =>
      visitVarStore(mv, vne.name)
    case sfae: StaticFieldAccessExpression =>
      mv.visitFieldInsn(Opcodes.PUTSTATIC, sfae.fieldNameSymbol.baseType.name.replaceAll("\\.", "/"), sfae.fieldNameSymbol.fieldName, JavaKnowledge.formatTypeToSignature(sfae.typ))
    case ie: IndexingExpression =>
      visitIndexStore(mv, ie)
    case ae: AccessExpression =>
      visitFieldStore(mv, ae, ae.typ)
    case _ => throw new JawaByteCodeGenException(lhs.pos, "visitLhsExpression problem: " + lhs)
  }
  
  private def visitRhsExpression(mv: MethodVisitor, rhs: Expression with RHS, lhsTyp: JawaType): Unit = rhs match {
    case vne: VariableNameExpression =>
      visitVarLoad(mv, vne.name)
      val rhsTyp: JawaType = this.locals(vne.name).typ
      handleTypeImplicitConvert(mv, lhsTyp, rhsTyp)
    case sfae: StaticFieldAccessExpression =>
      mv.visitFieldInsn(Opcodes.GETSTATIC, sfae.fieldNameSymbol.baseType.name.replaceAll("\\.", "/"), sfae.fieldNameSymbol.fieldName, JavaKnowledge.formatTypeToSignature(sfae.typ))
      handleTypeImplicitConvert(mv, lhsTyp, sfae.typ)
    case _: ExceptionExpression =>
    case _: NullExpression =>
      mv.visitInsn(Opcodes.ACONST_NULL)
    case ie: IndexingExpression =>
      visitIndexLoad(mv, ie)
      val rhsTyp = JawaType.generateType(this.locals(ie.base).typ.baseTyp, this.locals(ie.base).typ.dimensions - ie.dimensions)
      handleTypeImplicitConvert(mv, lhsTyp, rhsTyp)
    case ae: AccessExpression =>
      visitFieldLoad(mv, ae, ae.typ)
      handleTypeImplicitConvert(mv, lhsTyp, ae.typ)
    case te: TupleExpression =>
      visitTupleExpression(mv, lhsTyp, te)
    case ce: CastExpression =>
      visitCastExpression(mv, ce)
    case ne: NewExpression =>
      visitNewExpression(mv, ne)
    case nae: NewArrayExpression =>
      visitNewArrayExpression(mv, nae)
    case le: LiteralExpression =>
      visitLiteralExpression(mv, le)
    case ue: UnaryExpression =>
      visitUnaryExpression(mv, ue)
      val rhsTyp: JawaType = this.locals(ue.unary.varName).typ
      handleTypeImplicitConvert(mv, lhsTyp, rhsTyp)
    case be: BinaryExpression =>
      visitBinaryExpression(mv, be, lhsTyp)
    case ce: CmpExpression =>
      visitCmpExpression(mv, ce)
    case ie: InstanceOfExpression =>
      visitInstanceofExpression(mv, ie)
    case ce: ConstClassExpression =>
      visitConstClassExpression(mv, ce)
    case le: LengthExpression =>
      visitLengthExpression(mv, le)
    case _ =>  throw new JawaByteCodeGenException(rhs.pos, "visitRhsExpression problem: " + rhs)
  }
  
  private def handleTypeImplicitConvert(mv: MethodVisitor, lhsTyp: JawaType, rhsTyp: JawaType): Unit = {
    if(lhsTyp.isPrimitive && rhsTyp.isPrimitive){
      val lhs = lhsTyp.name
      val rhs = rhsTyp.name
      (rhs, lhs) match {
        case ("int", "long") => 
          mv.visitInsn(Opcodes.I2L)
        case ("int", "float") => 
          mv.visitInsn(Opcodes.I2F)
        case ("int", "double") =>
          mv.visitInsn(Opcodes.I2D)
        case ("long", "int") =>
          mv.visitInsn(Opcodes.L2I)
        case ("long", "float") =>
          mv.visitInsn(Opcodes.L2F)
        case ("long", "double") =>
          mv.visitInsn(Opcodes.L2D)
        case ("float", "int") =>
          mv.visitInsn(Opcodes.F2I)
        case ("float", "long") =>
          mv.visitInsn(Opcodes.F2L)
        case ("float", "double") =>
          mv.visitInsn(Opcodes.F2D)
        case ("double", "int") =>
          mv.visitInsn(Opcodes.D2I)
        case ("double", "long") =>
          mv.visitInsn(Opcodes.D2L)
        case ("double", "float") =>
          mv.visitInsn(Opcodes.D2F)
        case ("int", "byte") =>
          mv.visitInsn(Opcodes.I2B)
        case ("int", "char") =>
          mv.visitInsn(Opcodes.I2C)
        case ("int", "short") =>
          mv.visitInsn(Opcodes.I2S)
        case _ =>
      }
    }
  }
  
  private def visitConstClassExpression(mv: MethodVisitor, ce: ConstClassExpression): Unit = {
    val c = org.objectweb.asm.Type.getType(JavaKnowledge.formatTypeToSignature(ce.typExp.typ))
    mv.visitLdcInsn(c)
  }
  
  private def visitLengthExpression(mv: MethodVisitor, le: LengthExpression): Unit = {
    visitVarLoad(mv, le.varSymbol.varName)
    mv.visitInsn(Opcodes.ARRAYLENGTH)
  }
  
  private def visitInstanceofExpression(mv: MethodVisitor, ie: InstanceOfExpression): Unit = {
    visitVarLoad(mv, ie.varSymbol.varName)
    val typ: JawaType = ie.typExp.typ
    mv.visitTypeInsn(Opcodes.INSTANCEOF, getClassName(typ.name))
  }
  
  private def visitCmpExpression(mv: MethodVisitor, ce: CmpExpression): Unit = {
    val reqTyp: JawaType = ce.cmp.text match {
      case "fcmpl" =>
        JavaKnowledge.FLOAT
      case "dcmpl" =>
        JavaKnowledge.DOUBLE
      case "fcmpg" =>
        JavaKnowledge.FLOAT
      case "dcmpg" =>
        JavaKnowledge.DOUBLE
      case "lcmp" =>
        JavaKnowledge.LONG
      case _ =>
        JavaKnowledge.OBJECT
    }
    val first = ce.var1Symbol.varName
    visitVarLoad(mv, first)
    val rhs1Typ: JawaType = this.locals(first).typ
    handleTypeImplicitConvert(mv, reqTyp, rhs1Typ)
    val second = ce.var2Symbol.varName
    visitVarLoad(mv, second)
    val rhs2Typ: JawaType = this.locals(second).typ
    handleTypeImplicitConvert(mv, reqTyp, rhs2Typ)
    ce.cmp.text match {
      case "fcmpl" => 
        mv.visitInsn(Opcodes.FCMPL)
      case "dcmpl" =>
        mv.visitInsn(Opcodes.DCMPL)
      case "fcmpg" => 
        mv.visitInsn(Opcodes.FCMPG)
      case "dcmpg" =>
        mv.visitInsn(Opcodes.DCMPG)
      case "lcmp" =>
        mv.visitInsn(Opcodes.LCMP)
      case _ => throw new JawaByteCodeGenException(ce.pos, "visitCmpExpression problem: " + ce)
    }
  }
  
  private def visitTupleExpression(mv: MethodVisitor, lhsTyp: JawaType, te: TupleExpression): Unit = {
    val integers = te.integers
    val size = integers.size
    for(i <- 0 until size){
      val integer = integers(i)
      mv.visitInsn(Opcodes.DUP)
      generateIntConst(mv, i)
      generateIntConst(mv, integer)
      lhsTyp match {
        case typ if typ.baseTyp == "char" => mv.visitInsn(Opcodes.CASTORE)
        case _ => mv.visitInsn(Opcodes.IASTORE)
      }
    }
  }
  
  private def visitBinaryExpression(mv: MethodVisitor, be: BinaryExpression, lhsTyp: JawaType): Unit = {
    visitVarLoad(mv, be.left.varName)
    val rhs1Typ: JawaType = this.locals(be.left.varName).typ
    handleTypeImplicitConvert(mv, lhsTyp, rhs1Typ)
    val rhs2Typ: JawaType = be.right match {
      case Left(va) =>
        visitVarLoad(mv, va.varName)
        this.locals(va.varName).typ
      case Right(lit) =>
        lit match {
          case Left(i) =>
            generateIntConst(mv, i.getInt)
            JavaKnowledge.INT
          case Right(_) => throw new JawaByteCodeGenException(be.pos, "Should not be here!")
        }
    }
    handleTypeImplicitConvert(mv, lhsTyp, rhs2Typ)
    val k = rhs1Typ.jawaName match {
      case "int" | "boolean" | "char" | "byte" | "short" => "int"
      case n => n
    }
    be.op.text match {
      case "+" =>
        k match {
          case "int" =>    mv.visitInsn(Opcodes.IADD)
          case "long" =>   mv.visitInsn(Opcodes.LADD)
          case "float" =>  mv.visitInsn(Opcodes.FADD)
          case "double" => mv.visitInsn(Opcodes.DADD)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "-" =>
        k match {
          case "int" =>    mv.visitInsn(Opcodes.ISUB)
          case "long" =>   mv.visitInsn(Opcodes.LSUB)
          case "float" =>  mv.visitInsn(Opcodes.FSUB)
          case "double" => mv.visitInsn(Opcodes.DSUB)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "*" =>
        k match {
          case "int"  =>   mv.visitInsn(Opcodes.IMUL)
          case "long" =>   mv.visitInsn(Opcodes.LMUL)
          case "float" =>  mv.visitInsn(Opcodes.FMUL)
          case "double" => mv.visitInsn(Opcodes.DMUL)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "/" =>
        k match {
          case "int"  =>   mv.visitInsn(Opcodes.IDIV)
          case "long" =>   mv.visitInsn(Opcodes.LDIV)
          case "float" =>  mv.visitInsn(Opcodes.FDIV)
          case "double" => mv.visitInsn(Opcodes.DDIV)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "%%" =>
        k match {
          case "int"  =>   mv.visitInsn(Opcodes.IREM)
          case "long" =>   mv.visitInsn(Opcodes.LREM)
          case "float" =>  mv.visitInsn(Opcodes.FREM)
          case "double" => mv.visitInsn(Opcodes.DREM)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^&" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.IAND)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LAND)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^|" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.IOR)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LOR)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^~" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.IXOR)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LXOR)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^<" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.ISHL)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LSHL)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^>" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.ISHR)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LSHR)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case "^>>" =>
        k match {
          case "int" | "float"  =>   mv.visitInsn(Opcodes.IUSHR)
          case "long" | "double" =>   mv.visitInsn(Opcodes.LUSHR)
          case _ =>        throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
        }
      case _ =>            throw new JawaByteCodeGenException(be.pos, "visitBinaryExpression problem: " + be.toCode)
    }
  }
  
  private def visitUnaryExpression(mv: MethodVisitor, ue: UnaryExpression): Unit = ue.op.text match {
    case "-" => // Neg int long float double
      visitVarLoad(mv, ue.unary.varName)
      mv.visitInsn(Opcodes.ICONST_M1)
      mv.visitInsn(Opcodes.IMUL)
    case "~" => // Not int long
      visitVarLoad(mv, ue.unary.varName)
      mv.visitInsn(Opcodes.ICONST_M1)
      mv.visitInsn(Opcodes.IXOR)
    case _ =>   throw new JawaByteCodeGenException(ue.pos, "visitUnaryExpression problem: " + ue)
  }
  
  private def visitLiteralExpression(mv: MethodVisitor, le: LiteralExpression): Unit = {
    val lit = le.constant.text
    le.constant.tokenType match {
      case STRING_LITERAL | CHARACTER_LITERAL =>
        visitStringLiteral(mv, le.getString)
      case FLOATING_POINT_LITERAL =>
        lit match {
          case x if x.endsWith("f") | x.endsWith("F") => generateFloatConst(mv, le.getFloat)
          case x if x.endsWith("d") | x.endsWith("D") => generateDoubleConst(mv, le.getDouble)
          case _ => throw new JawaByteCodeGenException(le.pos, "visitLiteralExpression - FLOATING_POINT_LITERAL - problem: " + le.getString + " " + le)
        }
      case INTEGER_LITERAL =>
        lit match {
          case x if x.endsWith("i") | x.endsWith("I") => generateIntConst(mv, le.getInt)
          case x if x.endsWith("l") | x.endsWith("L") => generateLongConst(mv, le.getLong)
          case _ => generateIntConst(mv, le.getInt)
        }
      case _ =>
        throw new JawaByteCodeGenException(le.pos, "visitLiteralExpression problem: " + le.getString + " " + le)
    }
  }
  
  private def visitNewExpression(mv: MethodVisitor, ne: NewExpression): Unit = {
    mv.visitTypeInsn(Opcodes.NEW, getClassName(ne.typ.name))
  }

  private def visitNewArrayExpression(mv: MethodVisitor, nae: NewArrayExpression): Unit = {
    nae.varSymbols foreach { vs =>
      visitVarLoad(mv, vs.varName)
    }
    if(nae.varSymbols.lengthCompare(2) >= 0) {
      mv.visitMultiANewArrayInsn(getClassName(nae.typ.name), nae.dimensions)
    } else {
      nae.baseType match {
        case pt if pt.name == "byte" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
        case pt if pt.name == "short" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_SHORT)
        case pt if pt.name == "int" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT)
        case pt if pt.name == "long" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_LONG)
        case pt if pt.name == "float" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_FLOAT)
        case pt if pt.name == "double" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_DOUBLE)
        case pt if pt.name == "boolean" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BOOLEAN)
        case pt if pt.name == "char" => mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_CHAR)
        case _ => mv.visitTypeInsn(Opcodes.ANEWARRAY, getClassName(nae.baseType.name))
      }
    }
  }
  
  private def visitIndexLoad(mv: MethodVisitor, ie: IndexingExpression): Unit = {
    visitArrayAccess(mv, ie)
    val k = this.locals(ie.base).typ
    val array_type = new JawaType(k.baseType, k.dimensions - 1)
    array_type.jawaName match {
      case "boolean" => mv.visitInsn(Opcodes.BALOAD)
      case "char" => mv.visitInsn(Opcodes.CALOAD)
      case "double" => mv.visitInsn(Opcodes.DALOAD)
      case "float" => mv.visitInsn(Opcodes.FALOAD)
      case "int" | "byte" | "" => mv.visitInsn(Opcodes.IALOAD)
      case "long" => mv.visitInsn(Opcodes.LALOAD)
      case "short" => mv.visitInsn(Opcodes.SALOAD)
      case "object" | _ => mv.visitInsn(Opcodes.AALOAD)
    }
  }
  
  private def visitIndexStore(mv: MethodVisitor, ie: IndexingExpression): Unit = {
    val k = this.locals(ie.base).typ
    val array_type = new JawaType(k.baseType, k.dimensions - 1)
    array_type.jawaName match {
      case "boolean" => mv.visitInsn(Opcodes.BASTORE)
      case "char" => mv.visitInsn(Opcodes.CASTORE)
      case "double" => mv.visitInsn(Opcodes.DASTORE)
      case "float" => mv.visitInsn(Opcodes.FASTORE)
      case "int" | "byte" | "" => mv.visitInsn(Opcodes.IASTORE)
      case "long" => mv.visitInsn(Opcodes.LASTORE)
      case "short" => mv.visitInsn(Opcodes.SASTORE)
      case "object" | _ => mv.visitInsn(Opcodes.AASTORE)
    }
  }
  
  private def visitFieldLoad(mv: MethodVisitor, ae: AccessExpression, typ: JawaType): Unit = {
    visitFieldAccess(mv, ae)
    mv.visitFieldInsn(Opcodes.GETFIELD, ae.fieldSym.baseType.name.replaceAll("\\.", "/"), ae.fieldName, JavaKnowledge.formatTypeToSignature(typ))
  }
  
  private def visitFieldStore(mv: MethodVisitor, ae: AccessExpression, typ: JawaType): Unit = {
    mv.visitFieldInsn(Opcodes.PUTFIELD, ae.fieldSym.baseType.name.replaceAll("\\.", "/"), ae.fieldName, JavaKnowledge.formatTypeToSignature(typ))
  }
  
  private def visitArrayAccess(mv: MethodVisitor, ie: IndexingExpression): Unit = {
    val base: String = ie.base
    val dimensions: Int = ie.dimensions
    val indexs = ie.indices.map(_.index)
    mv.visitVarInsn(Opcodes.ALOAD, this.locals(base).index)
    for(i <- 0 until dimensions){
      val index = indexs(i)
      index match {
        case Left(vs) => 
          visitVarLoad(mv, vs.varName)
        case Right(t) =>
          generateIntConst(mv, t.getInt)
      }
    }
    for(_ <- 0 to dimensions - 2){
        mv.visitInsn(Opcodes.AALOAD)
    }
  }
  
  private def visitFieldAccess(mv: MethodVisitor, ae: AccessExpression): Unit = {
    val base: String = ae.base
    mv.visitVarInsn(Opcodes.ALOAD, this.locals(base).index)
  }
  
  private def visitVarLoad(mv: MethodVisitor, varName: String): Unit = this.locals(varName).typ.name match {
    case "byte" | "char" | "short" | "int" | "boolean" => 
                     mv.visitVarInsn(Opcodes.ILOAD, this.locals(varName).index)
    case "double" => mv.visitVarInsn(Opcodes.DLOAD, this.locals(varName).index)
    case "float" =>  mv.visitVarInsn(Opcodes.FLOAD, this.locals(varName).index)
    case "long" =>   mv.visitVarInsn(Opcodes.LLOAD, this.locals(varName).index)
    case _ =>        mv.visitVarInsn(Opcodes.ALOAD, this.locals(varName).index)
  }
  
  private def visitVarStore(mv: MethodVisitor, varName: String): Unit = this.locals(varName).typ.name match {
    case "byte" | "char" | "short" | "int" | "boolean" => 
                     mv.visitVarInsn(Opcodes.ISTORE, this.locals(varName).index)
    case "double" => mv.visitVarInsn(Opcodes.DSTORE, this.locals(varName).index)
    case "float" =>  
                     mv.visitVarInsn(Opcodes.FSTORE, this.locals(varName).index)
    case "long" =>   mv.visitVarInsn(Opcodes.LSTORE, this.locals(varName).index)
    case _ =>        mv.visitVarInsn(Opcodes.ASTORE, this.locals(varName).index)
  }
  
  private def visitStringLiteral(mv: MethodVisitor, str: String): Unit = {
    mv.visitLdcInsn(str)
  }
  
  private def visitCastExpression(mv: MethodVisitor, ce: CastExpression): Unit = {
    this.locals(ce.varName).typ match {
      case t if t == JavaKnowledge.INT =>
        mv.visitVarInsn(Opcodes.ILOAD, this.locals(ce.varName).index)
        ce.typ.typ match {
          case t2 if t2 == JavaKnowledge.LONG =>
            mv.visitInsn(Opcodes.I2L)
          case t2 if t2 == JavaKnowledge.FLOAT =>
            mv.visitInsn(Opcodes.I2F)
          case t2 if t2 == JavaKnowledge.DOUBLE =>
            mv.visitInsn(Opcodes.I2D)
          case t2 if t2 == JavaKnowledge.BYTE =>
            mv.visitInsn(Opcodes.I2B)
          case t2 if t2 == JavaKnowledge.CHAR =>
            mv.visitInsn(Opcodes.I2C)
          case t2 if t2 == JavaKnowledge.SHORT =>
            mv.visitInsn(Opcodes.I2S)
          case _ =>
            throw new JawaByteCodeGenException(ce.pos, "visitCastExpression problem: " + ce)
        }
      case t if t == JavaKnowledge.LONG =>
        mv.visitVarInsn(Opcodes.LLOAD, this.locals(ce.varName).index)
        ce.typ.typ match {
          case t2 if t2 == JavaKnowledge.INT =>
            mv.visitInsn(Opcodes.L2I)
          case t2 if t2 == JavaKnowledge.FLOAT =>
            mv.visitInsn(Opcodes.L2F)
          case t2 if t2 == JavaKnowledge.DOUBLE =>
            mv.visitInsn(Opcodes.L2D)
          case _ =>
            throw new JawaByteCodeGenException(ce.pos, "visitCastExpression problem: " + ce)
        }
      case t if t == JavaKnowledge.FLOAT =>
        mv.visitVarInsn(Opcodes.FLOAD, this.locals(ce.varName).index)
        ce.typ.typ match {
          case t2 if t2 == JavaKnowledge.INT =>
            mv.visitInsn(Opcodes.F2I)
          case t2 if t2 == JavaKnowledge.LONG =>
            mv.visitInsn(Opcodes.F2L)
          case t2 if t2 == JavaKnowledge.DOUBLE =>
            mv.visitInsn(Opcodes.F2D)
          case _ =>
            throw new JawaByteCodeGenException(ce.pos, "visitCastExpression problem: " + ce)
        }
      case t if t == JavaKnowledge.DOUBLE =>
        mv.visitVarInsn(Opcodes.DLOAD, this.locals(ce.varName).index)
        ce.typ.typ match {
          case t2 if t2 == JavaKnowledge.INT =>
            mv.visitInsn(Opcodes.D2I)
          case t2 if t2 == JavaKnowledge.LONG =>
            mv.visitInsn(Opcodes.D2L)
          case t2 if t2 == JavaKnowledge.FLOAT =>
            mv.visitInsn(Opcodes.D2F)
          case _ =>
            throw new JawaByteCodeGenException(ce.pos, "visitCastExpression problem: " + ce)
        }
      case _ =>
        mv.visitVarInsn(Opcodes.ALOAD, this.locals(ce.varName).index)
        mv.visitTypeInsn(Opcodes.CHECKCAST, getClassName(ce.typ.typ.name))
    }
  }
  
  private def generateIntConst(mv: MethodVisitor, i: Int): Unit = i match {
    case -1 => mv.visitInsn(Opcodes.ICONST_M1)
    case 0  => mv.visitInsn(Opcodes.ICONST_0)
    case 1  => mv.visitInsn(Opcodes.ICONST_1)
    case 2  => mv.visitInsn(Opcodes.ICONST_2)
    case 3  => mv.visitInsn(Opcodes.ICONST_3)
    case 4  => mv.visitInsn(Opcodes.ICONST_4)
    case 5  => mv.visitInsn(Opcodes.ICONST_5)
    case _  =>
      if((i >= Byte.MinValue) && (i <= Byte.MaxValue)) {
        mv.visitIntInsn(Opcodes.BIPUSH, i)
      } else if((i >= Short.MinValue) && (i <= Short.MaxValue)) {
        mv.visitIntInsn(Opcodes.SIPUSH, i)
      } else {
        mv.visitLdcInsn(Integer.valueOf(i))
      }
  }
  
  private def generateLongConst(mv: MethodVisitor, l: scala.Long): Unit = l match {
    case 0  => mv.visitInsn(Opcodes.LCONST_0)
    case 1  => mv.visitInsn(Opcodes.LCONST_1)
    case _  =>
      mv.visitLdcInsn(Long.valueOf(l))
  }
  
  private def generateFloatConst(mv: MethodVisitor, f: scala.Float): Unit = f match {
    case 0  => mv.visitInsn(Opcodes.FCONST_0)
    case 1  => mv.visitInsn(Opcodes.FCONST_1)
    case 2  => mv.visitInsn(Opcodes.FCONST_2)
    case _  =>
      mv.visitLdcInsn(Float.valueOf(f))
  }
  
  private def generateDoubleConst(mv: MethodVisitor, d: scala.Double): Unit = d match {
    case 0  => mv.visitInsn(Opcodes.DCONST_0)
    case 1  => mv.visitInsn(Opcodes.DCONST_1)
    case _  =>
      mv.visitLdcInsn(Double.valueOf(d))
  }
}

class JawaByteCodeGenException(pos: Position, message: String) extends JawaParserException(pos, message)