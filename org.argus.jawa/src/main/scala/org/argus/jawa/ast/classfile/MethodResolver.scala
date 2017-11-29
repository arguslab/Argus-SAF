/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.ast.classfile

import org.argus.jawa.ast._
import org.argus.jawa.core._
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.{Label, MethodVisitor, Opcodes}

class MethodResolver(
    api: Int,
    accessFlag: Int,
    signature: Signature,
    methods: MList[MethodDeclaration]) extends MethodVisitor(api) {
  val returnType: Type = new Type(signature.getReturnType)
  val methodSymbol: MethodDefSymbol = new MethodDefSymbol(signature.methodName)
  methodSymbol.signature = signature

  val annotations: IList[Annotation] = List(
    new Annotation("signature", SymbolValue(new SignatureSymbol(signature))(NoPosition)),
    new Annotation("AccessFlag", new TokenValue(AccessFlag.getAccessFlagString(accessFlag)))
  )

  //******************************************************************************
  //                         Local Variable management
  //******************************************************************************

  val params: MList[Parameter] = mlistEmpty
  private val localVariables: MMap[Int, (JawaType, String)] = mmapEmpty
  private var num = 0

  private def load(i: Int): (JawaType, String) = {
    localVariables.getOrElse(i, throw DeBytecodeException(s"Failed to load idx $i"))
  }

  private def store(i: Int, typ: JawaType): String = {
    val name = checkAndAddVariable(typ, isTemp = false)
    localVariables(i) = ((typ, name))
    name
  }

  private val usedVariables: MMap[String, JawaType] = mmapEmpty

  private def getVarType(name: String): JawaType = usedVariables.getOrElse(name, throw DeBytecodeException(s"Variable $name does not exist."))

  // handle this
  if(!AccessFlag.isStatic(accessFlag) && !AccessFlag.isInterface(accessFlag)) {
    params += new Parameter(signature.getClassType, "this", List(new Annotation("kind", new TokenValue("this"))))
    localVariables(num) = ((signature.getClassType, "this"))
    usedVariables("this") = signature.getClassType
    num += 1
  }

  val locals: MList[LocalVarDeclaration] = mlistEmpty

  // handle params
  private var paramCounter = 0
  override def visitParameter(name: String, access: Int): Unit = {
    val typ: JawaType = signature.getParameterTypes.lift(paramCounter).getOrElse(throw DeBytecodeException(s"Sig: $signature does not have type for param num $paramCounter"))
    val annotations: IList[Annotation] = if(typ.isObject) {
      List(new Annotation("kind", new TokenValue("object")))
    } else {
      ilistEmpty
    }
    params += new Parameter(typ, name, annotations)
    localVariables(num) = ((typ, name))
    usedVariables(name) = typ
    paramCounter += 1
    num += 1
  }

  private def checkAndAddVariable(varType: JawaType, isTemp: Boolean): String = {
    val expectedName = if(isTemp) {
      s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
    } else {
      s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}"
    }
    var varName = expectedName
    var i = 1
    while(stackVars.contains(varName)) {
      varName = expectedName + i
      i += 1
      while({
        usedVariables.get(varName) match {
          case Some(t) => t != varType
          case None => false
        }
      }) {
        varName = expectedName + i
        i += 1
      }
    }
    if(!usedVariables.contains(varName)) {
      val lvd = new LocalVarDeclaration(varType, varName)
      locals += lvd
      usedVariables(varName) = varType
    }
    varName
  }

  private var stackVars: IList[String] = ilistEmpty

  private def push(typ: JawaType): String = {
    val varName = checkAndAddVariable(typ, isTemp = true)
    stackVars = varName :: stackVars
    varName
  }

  private def push(str: String): String = {
    stackVars = str :: stackVars
    str
  }

  private def dup(i: Int): Unit = {
    require(stackVars.size >= i, s"Stack size less than dup $i requirement")
    stackVars = stackVars.take(i) ::: stackVars
  }

  private def pop: String = {
    require(stackVars.nonEmpty, "Stack should not be empty via pop")
    val varName :: tail = stackVars
    stackVars = tail
    varName
  }

  //************************ Local Variable management End ***********************

  private var labelCount: Int = 0
  private var locCount: Int = 0
  private def line: Int = labelCount + locCount

  val locations: MList[Location] = mlistEmpty
  val catchClauses: MList[CatchClause] = mlistEmpty

  private val labels: MMap[Label, Location] = mmapEmpty

  private def createLabel(label: Label): Unit = {
    val l = s"Label$labelCount"
    val loc = new Location(l, EmptyStatement(mlistEmpty)(NoPosition))
    loc.locationSymbol.locationIndex = line
    labels(label) = loc
    locations += loc
    labelCount += 1
  }

  private def createLocation(stmt: Statement): Unit = {
    val l = s"L$locCount"
    val loc = new Location(l, stmt)
    loc.locationSymbol.locationIndex = line
    locations += loc
    locCount += 1
  }

  override def visitLabel(label: Label): Unit = {
    createLabel(label)
  }

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  import Opcodes._

  /**
    * Visits a zero operand instruction.
    *
    * @param opcode
    * the opcode of the instruction to be visited. This opcode is
    * either NOP, ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1,
    * ICONST_2, ICONST_3, ICONST_4, ICONST_5, LCONST_0, LCONST_1,
    * FCONST_0, FCONST_1, FCONST_2, DCONST_0, DCONST_1, IALOAD,
    * LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
    * IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE,
    * SASTORE, POP, POP2, DUP, DUP_X1, DUP_X2, DUP2, DUP2_X1,
    * DUP2_X2, SWAP, IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
    * IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV, IREM, LREM,
    * FREM, DREM, INEG, LNEG, FNEG, DNEG, ISHL, LSHL, ISHR, LSHR,
    * IUSHR, LUSHR, IAND, LAND, IOR, LOR, IXOR, LXOR, I2L, I2F, I2D,
    * L2I, L2F, L2D, F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
    * LCMP, FCMPL, FCMPG, DCMPL, DCMPG, IRETURN, LRETURN, FRETURN,
    * DRETURN, ARETURN, RETURN, ARRAYLENGTH, ATHROW, MONITORENTER,
    * or MONITOREXIT.
    */
  override def visitInsn(opcode: Int): Unit = {
    var stmt: Option[Statement] = None
    opcode match {
      case NOP =>
        stmt = Some(new EmptyStatement())
      case ACONST_NULL =>
        val name = push(JavaKnowledge.OBJECT)
        val ne = new NullExpression()
        stmt = Some(new AssignmentStatement(name, ne, ilistEmpty))
      case ICONST_M1 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, -1))
      case ICONST_0 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 0))
      case ICONST_1 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 1))
      case ICONST_2 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 2))
      case ICONST_3 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 3))
      case ICONST_4 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 4))
      case ICONST_5 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 5))
      case LCONST_0 =>
        val name = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(name, 0L))
      case LCONST_1 =>
        val name = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(name, 1L))
      case FCONST_0 =>
        val name = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(name, 0F))
      case FCONST_1 =>
        val name = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(name, 1F))
      case FCONST_2 =>
        val name = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(name, 2F))
      case DCONST_0 =>
        val name = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(name, 0D))
      case DCONST_1 =>
        val name = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(name, 1D))
//      case IALOAD =>
//      case LALOAD =>
//      case FALOAD =>
//      case DALOAD =>
//      case AALOAD =>
//      case BALOAD =>
//      case CALOAD =>
//      case SALOAD =>
//      case IASTORE =>
//      case LASTORE =>
//      case FASTORE =>
//      case DASTORE =>
//      case AASTORE =>
//      case BASTORE =>
//      case CASTORE =>
//      case SASTORE =>
//      case POP =>
//      case POP2 =>
      case DUP =>
        dup(1)
//      case DUP_X1 =>
//      case DUP_X2 =>
      case DUP2 =>
        dup(2)
//      case DUP2_X1 =>
//      case DUP2_X2 =>
//      case SWAP =>
      case IADD =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LADD =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FADD =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DADD =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "+", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISUB =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSUB =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FSUB =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DSUB =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "-", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IMUL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LMUL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FMUL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DMUL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "*", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IDIV =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LDIV =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FDIV =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DDIV =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "/", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IREM =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LREM =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FREM =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DREM =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "%%", r)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case INEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case LNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case FNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.FLOAT)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case DNEG =>
        val v = pop
        val ue = new UnaryExpression("-", v)
        val temp = push(JavaKnowledge.DOUBLE)
        stmt = Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case ISHL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^<", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHL =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^<", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISHR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^>", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^>", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IUSHR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^>>", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LUSHR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^>>", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IAND =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^&", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LAND =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^&", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IOR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^|", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LOR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^|", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IXOR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^~", r)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LXOR =>
        val l = pop
        val r = pop
        val be = new BinaryExpression(l, "^~", r)
        val temp = push(JavaKnowledge.LONG)
        stmt = Some(new AssignmentStatement(temp, be, ilistEmpty))
//      case I2L =>
//      case I2F =>
//      case I2D =>
//      case L2I =>
//      case L2F =>
//      case L2D =>
//      case F2I =>
//      case F2L =>
//      case F2D =>
//      case D2I =>
//      case D2L =>
//      case D2F =>
//      case I2B =>
//      case I2C =>
//      case I2S =>
//      case LCMP =>
//      case FCMPL =>
//      case FCMPG =>
//      case DCMPL =>
//      case DCMPG =>
      case IRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case LRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case FRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case DRETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name))
      case ARETURN =>
        val name = pop
        stmt = Some(new ReturnStatement(name, List(new Annotation("kind", new TokenValue("object")))))
      case RETURN =>
        stmt = Some(new ReturnStatement())
      case ARRAYLENGTH =>
        val name = pop
        val len = new LengthExpression(name)
        val temp = push(JavaKnowledge.INT)
        stmt = Some(new AssignmentStatement(temp, len, ilistEmpty))
      case ATHROW =>
        val name = pop
        stmt = Some(new ThrowStatement(name))
      case MONITORENTER =>
        val name = pop
        stmt = Some(new MonitorStatement("monitorenter", name))
      case MONITOREXIT =>
        val name = pop
        stmt = Some(new MonitorStatement("monitorexit", name))
      case _ => throw DeBytecodeException(s"Unknown opcode for Insn: $opcode")
    }
    stmt match {
      case Some(s) => createLocation(s)
      case None =>
    }
  }

  /**
    * Visits an instruction with a single int operand.
    *
    * @param opcode
    *            the opcode of the instruction to be visited. This opcode is
    *            either BIPUSH, SIPUSH or NEWARRAY.
    * @param operand
    *            the operand of the instruction to be visited.<br>
    *            When opcode is BIPUSH, operand value should be between
    *            Byte.MIN_VALUE and Byte.MAX_VALUE.<br>
    *            When opcode is SIPUSH, operand value should be between
    *            Short.MIN_VALUE and Short.MAX_VALUE.<br>
    *            When opcode is NEWARRAY, operand value should be one of
    *            { @link Opcodes#T_BOOLEAN}, { @link Opcodes#T_CHAR},
    *                    { @link Opcodes#T_FLOAT}, { @link Opcodes#T_DOUBLE},
    *                    { @link Opcodes#T_BYTE}, { @link Opcodes#T_SHORT},
    *                    { @link Opcodes#T_INT} or { @link Opcodes#T_LONG}.
    */
  override def visitIntInsn(opcode: Int, operand: Int): Unit = {
    opcode match {
//      case BIPUSH =>
//      case SIPUSH =>
//      case NEWARRAY =>
      case _ => throw DeBytecodeException(s"Unknown opcode for IntInsn: $opcode")
    }
  }

  /**
    * Visits a local variable instruction. A local variable instruction is an
    * instruction that loads or stores the value of a local variable.
    *
    * @param opcode
    * the opcode of the local variable instruction to be visited.
    * This opcode is either ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
    * ISTORE, LSTORE, FSTORE, DSTORE, ASTORE or RET.
    * @param v
    * the operand of the instruction to be visited. This operand is
    * the index of a local variable.
    */
  override def visitVarInsn(opcode: Int, v: Int): Unit = {
    var stmt: Option[Statement] = None
    opcode match {
      case ILOAD =>
        val (_, name) = load(v)
        val temp = push(name)
        new AssignmentStatement(temp, name, ilistEmpty)
      case LLOAD =>
        val (_, name) = load(v)
        val temp = push(name)
        new AssignmentStatement(temp, name, ilistEmpty)
      case FLOAD =>
        val (_, name) = load(v)
        push(name)
      case DLOAD =>
        val (_, name) = load(v)
        push(name)
      case ALOAD =>
        val (_, name) = load(v)
        push(name)
      case ISTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case LSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case FSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case DSTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, ilistEmpty))
      case ASTORE =>
        val temp = pop
        val typ = getVarType(temp)
        val name = store(v, typ)
        stmt = Some(new AssignmentStatement(name, temp, List(new Annotation("kind", new TokenValue("object")))))
      //      case RET =>
      case _ => throw DeBytecodeException(s"Unknown opcode for VarInsn: $opcode")
    }
    stmt match {
      case Some(s) =>
        createLocation(s)
      case None =>
    }
  }

  /**
    * Visits a type instruction. A type instruction is an instruction that
    * takes the internal name of a class as parameter.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either NEW, ANEWARRAY, CHECKCAST or INSTANCEOF.
    * @param t
    * the operand of the instruction to be visited. This operand
    * must be the internal name of an object or array class (see
    * { @link Type#getInternalName() getInternalName}).
    */
  override def visitTypeInsn(opcode: Int, t: String): Unit = {
    val typ = JavaKnowledge.getTypeFromName(getClassName(t))
    val stmt: Statement = opcode match {
      case NEW =>
        val temp = push(typ)
        val ne = new NewExpression(typ)
        new AssignmentStatement(temp, ne, ilistEmpty)
      case ANEWARRAY =>
        val idxes = (0 until typ.dimensions).map { _ =>
          pop
        }.toList
        val temp = push(typ)
        val ne = new NewArrayExpression(typ, idxes)
        new AssignmentStatement(temp, ne, ilistEmpty)
      case CHECKCAST =>
        val v = pop
        val temp = push(typ)
        val ce = new CastExpression(typ, v)
        new AssignmentStatement(temp, ce, List(new Annotation("kind", new TokenValue("object"))))
      case INSTANCEOF =>
        val v = pop
        val temp = push(JavaKnowledge.BOOLEAN)
        val ioe = new InstanceOfExpression(v, typ)
        new AssignmentStatement(temp, ioe, ilistEmpty)
      case _ => throw DeBytecodeException(s"Unknown opcode for TypeInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits a field instruction. A field instruction is an instruction that
    * loads or stores the value of a field of an object.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either GETSTATIC, PUTSTATIC, GETFIELD or PUTFIELD.
    * @param owner
    * the internal name of the field's owner class (see
    * { @link Type#getInternalName() getInternalName}).
    * @param name
    * the field's name.
    * @param desc
    * the field's descriptor (see { @link Type Type}).
    */
  override def visitFieldInsn(opcode: Int, owner: String, name: String, desc: String): Unit = {
    val fqn = FieldFQN(JavaKnowledge.getTypeFromName(getClassName(owner)), name, JavaKnowledge.formatSignatureToType(desc))
    val annotations: MList[Annotation] = mlistEmpty
    if(fqn.typ.isObject) {
      annotations += new Annotation("kind", new TokenValue("object"))
    }
    val stmt: Statement = opcode match {
      case GETSTATIC =>
        val temp = push(fqn.typ)
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTSTATIC =>
        val temp = pop
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case GETFIELD =>
        val base = pop
        val temp = push(fqn.typ)
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTFIELD =>
        val temp = pop
        val base = pop
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case _ => throw DeBytecodeException(s"Unknown opcode for FieldInsn: $opcode")
    }
    createLocation(stmt)
  }

  /**
    * Visits a method instruction. A method instruction is an instruction that
    * invokes a method.
    *
    * @param opcode
    * the opcode of the type instruction to be visited. This opcode
    * is either INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC or
    * INVOKEINTERFACE.
    * @param owner
    * the internal name of the method's owner class (see
    * { @link Type#getInternalName() getInternalName}).
    * @param name
    * the method's name.
    * @param desc
    * the method's descriptor (see { @link Type Type}).
    * @param itf
    * if the method's owner class is an interface.
    */
  override def visitMethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean): Unit = {
    val typ = JavaKnowledge.getTypeFromName(getClassName(owner))
    val sig = new Signature(typ, name, desc)
    val stmt: Statement = opcode match {
      case INVOKEVIRTUAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "virtual")
      case INVOKESPECIAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "direct")
      case INVOKESTATIC =>
        val argNum = sig.getParameterNum
        val argNames = (0 until argNum).map(_ => pop).toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "static")
      case INVOKEINTERFACE =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(_ => pop).toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(push(sig.getReturnType))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "interface")
      case _ => throw DeBytecodeException(s"Unknown opcode for MethodInsn: $opcode")
    }
    createLocation(stmt)
  }

  override def visitLineNumber(line: Int, start: Label): Unit = {
    labels.get(start) match {
      case Some(Location(_, EmptyStatement(annos))) =>
        annos += new Annotation("line", new TokenValue(s"$line"))
      case _ =>
    }
  }

  override def visitLocalVariable(
      name: String,
      desc: String,
      signature: String,
      start: Label,
      end: Label,
      index: Int): Unit = {

  }

  override def visitEnd(): Unit = {
    val body: Body = ResolvedBody(locals.toList, locations.toList, catchClauses.toList)(NoPosition)
    val md = MethodDeclaration(returnType, methodSymbol, params.toList, annotations, body)(NoPosition)
    md.getAllChildren foreach {
      case vd: VarDefSymbol => vd.owner = md
      case vs: VarSymbol => vs.owner = md
      case ld: LocationDefSymbol => ld.owner = md
      case ls: LocationSymbol => ls.owner = md
      case _ =>
    }
    methods += md
  }
}
