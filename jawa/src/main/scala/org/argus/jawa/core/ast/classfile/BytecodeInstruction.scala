/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.ast.classfile

import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements.{FieldFQN, JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.io.NoPosition
import org.argus.jawa.core.util._
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes._

trait BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement]
}

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
case class Insn(opcode: Int) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    opcode match {
      case NOP =>
        Some(new EmptyStatement())
      case ACONST_NULL =>
        val name = varProvider(0)
        val ne = new NullExpression()
        Some(new AssignmentStatement(name, ne, ilistEmpty))
      case ICONST_M1 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, -1))
      case ICONST_0 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 0))
      case ICONST_1 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 1))
      case ICONST_2 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 2))
      case ICONST_3 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 3))
      case ICONST_4 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 4))
      case ICONST_5 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 5))
      case LCONST_0 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 0L))
      case LCONST_1 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 1L))
      case FCONST_0 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 0F))
      case FCONST_1 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 1F))
      case FCONST_2 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 2F))
      case DCONST_0 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 0D))
      case DCONST_1 =>
        val name = varProvider(0)
        Some(new AssignmentStatement(name, 1D))
      case IALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case LALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case FALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case DALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case AALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, List(new Annotation("kind", new TokenValue("object")))))
      case BALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case CALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case SALOAD =>
        val idx = varProvider(0)
        val base = varProvider(1)
        val temp = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(temp, ie, ilistEmpty))
      case IASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case LASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case FASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case DASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case AASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, List(new Annotation("kind", new TokenValue("object")))))
      case BASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case CASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case SASTORE =>
        val value = varProvider(0)
        val idx = varProvider(1)
        val base = varProvider(2)
        val ie = new IndexingExpression(base, List(idx))
        Some(new AssignmentStatement(ie, value, ilistEmpty))
      case POP =>
        None
      case POP2 =>
        None
      case DUP =>
        None
      case DUP_X1 =>
        None
      case DUP_X2 =>
        None
      case DUP2 =>
        None
      case DUP2_X1 =>
        None
      case DUP2_X2 =>
        None
      case SWAP =>
        None
      case IADD =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "+", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LADD =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "+", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FADD =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "+", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DADD =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "+", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISUB =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "-", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSUB =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "-", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FSUB =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "-", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DSUB =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "-", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IMUL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "*", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LMUL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "*", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FMUL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "*", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DMUL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "*", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IDIV =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "/", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LDIV =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "/", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FDIV =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "/", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DDIV =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "/", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IREM =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "%%", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LREM =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "%%", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case FREM =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "%%", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case DREM =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "%%", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case INEG =>
        val v = varProvider(0)
        val ue = new UnaryExpression("-", v)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case LNEG =>
        val v = varProvider(0)
        val ue = new UnaryExpression("-", v)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case FNEG =>
        val v = varProvider(0)
        val ue = new UnaryExpression("-", v)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case DNEG =>
        val v = varProvider(0)
        val ue = new UnaryExpression("-", v)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, ue, ilistEmpty))
      case ISHL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^<", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^<", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case ISHR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^>", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LSHR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^>", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IUSHR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^>>", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LUSHR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^>>", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IAND =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^&", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LAND =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^&", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IOR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^|", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LOR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^|", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case IXOR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^~", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case LXOR =>
        val r = varProvider(0)
        val l = varProvider(1)
        val be = new BinaryExpression(l, "^~", r)
        val temp = varProvider(2)
        Some(new AssignmentStatement(temp, be, ilistEmpty))
      case I2L =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2F =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2D =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2I =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2F =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case L2D =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2I =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2L =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case F2D =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.DOUBLE, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2I =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.INT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2L =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.LONG, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case D2F =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.FLOAT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2B =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.BYTE, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2C =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.CHAR, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case I2S =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(JavaKnowledge.SHORT, v)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case LCMP =>
        val r = varProvider(0)
        val l = varProvider(1)
        val temp = varProvider(2)
        val ce = new CmpExpression("lcmp", l, r)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case FCMPL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val temp = varProvider(2)
        val ce = new CmpExpression("fcmpl", l, r)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case FCMPG =>
        val r = varProvider(0)
        val l = varProvider(1)
        val temp = varProvider(2)
        val ce = new CmpExpression("fcmpg", l, r)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case DCMPL =>
        val r = varProvider(0)
        val l = varProvider(1)
        val temp = varProvider(2)
        val ce = new CmpExpression("dcmpl", l, r)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case DCMPG =>
        val r = varProvider(0)
        val l = varProvider(1)
        val temp = varProvider(2)
        val ce = new CmpExpression("dcmpg", l, r)
        Some(new AssignmentStatement(temp, ce, ilistEmpty))
      case IRETURN =>
        val name = varProvider(0)
        Some(new ReturnStatement(name))
      case LRETURN =>
        val name = varProvider(0)
        Some(new ReturnStatement(name))
      case FRETURN =>
        val name = varProvider(0)
        Some(new ReturnStatement(name))
      case DRETURN =>
        val name = varProvider(0)
        Some(new ReturnStatement(name))
      case ARETURN =>
        val name = varProvider(0)
        Some(new ReturnStatement(name, List(new Annotation("kind", new TokenValue("object")))))
      case RETURN =>
        Some(new ReturnStatement())
      case ARRAYLENGTH =>
        val name = varProvider(0)
        val len = new LengthExpression(name)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, len, ilistEmpty))
      case ATHROW =>
        val name = varProvider(0)
        Some(new ThrowStatement(name))
      case MONITORENTER =>
        val name = varProvider(0)
        Some(new MonitorStatement("monitorenter", name))
      case MONITOREXIT =>
        val name = varProvider(0)
        Some(new MonitorStatement("monitorexit", name))
      case _ => throw DeBytecodeException(s"Unknown opcode for Insn: $opcode")
    }
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
case class IntInsn(opcode: Int, operand: Int) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    opcode match {
      case BIPUSH =>
        val temp = varProvider(0)
        Some(new AssignmentStatement(temp, operand))
      case SIPUSH =>
        val temp = varProvider(0)
        Some(new AssignmentStatement(temp, operand))
      case NEWARRAY =>
        val typ = operand match {
          case T_BOOLEAN => JavaKnowledge.BOOLEAN
          case T_CHAR => JavaKnowledge.CHAR
          case T_FLOAT => JavaKnowledge.FLOAT
          case T_DOUBLE => JavaKnowledge.DOUBLE
          case T_BYTE => JavaKnowledge.BYTE
          case T_SHORT => JavaKnowledge.SHORT
          case T_INT => JavaKnowledge.INT
          case T_LONG => JavaKnowledge.LONG
          case _ =>  throw DeBytecodeException(s"Unknown operand for NEWARRAY: $operand")
        }
        val idx = varProvider(0)
        val temp = varProvider(1)
        val nae = new NewArrayExpression(typ, List(idx))
        Some(new AssignmentStatement(temp, nae, ilistEmpty))
      case _ => throw DeBytecodeException(s"Unknown opcode for IntInsn: $opcode")
    }
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
case class VarInsn(opcode: Int, v: Int) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    opcode match {
      case ILOAD =>
        val name = varProvider(0)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, name, ilistEmpty))
      case LLOAD =>
        val name = varProvider(0)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, name, ilistEmpty))
      case FLOAD =>
        val name = varProvider(0)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, name, ilistEmpty))
      case DLOAD =>
        val name = varProvider(0)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, name, ilistEmpty))
      case ALOAD =>
        val name = varProvider(0)
        val temp = varProvider(1)
        Some(new AssignmentStatement(temp, name, List(new Annotation("kind", new TokenValue("object")))))
      case ISTORE =>
        val temp = varProvider(0)
        val name = varProvider(1)
        Some(new AssignmentStatement(name, temp, ilistEmpty))
      case LSTORE =>
        val temp = varProvider(0)
        val name = varProvider(1)
        Some(new AssignmentStatement(name, temp, ilistEmpty))
      case FSTORE =>
        val temp = varProvider(0)
        val name = varProvider(1)
        Some(new AssignmentStatement(name, temp, ilistEmpty))
      case DSTORE =>
        val temp = varProvider(0)
        val name = varProvider(1)
        Some(new AssignmentStatement(name, temp, ilistEmpty))
      case ASTORE =>
        val temp = varProvider(0)
        val name = varProvider(1)
        Some(new AssignmentStatement(name, temp, List(new Annotation("kind", new TokenValue("object")))))
      //      case RET =>
      case _ => throw DeBytecodeException(s"Unknown opcode for VarInsn: $opcode")
    }
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
case class TypeInsn(opcode: Int, t: String) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val typ = JavaKnowledge.getTypeFromName(t.replaceAll("/", "."))
    opcode match {
      case NEW =>
        val temp = varProvider(0)
        val ne = new NewExpression(typ)
        Some(new AssignmentStatement(temp, ne, ilistEmpty))
      case ANEWARRAY =>
        val idx = varProvider(0)
        val temp = varProvider(1)
        val ne = new NewArrayExpression(typ, List(idx))
        Some(new AssignmentStatement(temp, ne, ilistEmpty))
      case CHECKCAST =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ce = new CastExpression(typ, v)
        Some(new AssignmentStatement(temp, ce, List(new Annotation("kind", new TokenValue("object")))))
      case INSTANCEOF =>
        val v = varProvider(0)
        val temp = varProvider(1)
        val ioe = new InstanceOfExpression(v, typ)
        Some(new AssignmentStatement(temp, ioe, ilistEmpty))
      case _ => throw DeBytecodeException(s"Unknown opcode for TypeInsn: $opcode")
    }
  }
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
case class FieldInsn(opcode: Int, owner: String, name: String, desc: String) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val fqn = new FieldFQN(JavaKnowledge.getTypeFromName(owner.replaceAll("/", ".")),
                           name, JavaKnowledge.formatSignatureToType(desc))
    val annotations: MList[Annotation] = mlistEmpty
    if(fqn.typ.isObject) {
      annotations += new Annotation("kind", new TokenValue("object"))
    }
    val stmt: Statement = opcode match {
      case GETSTATIC =>
        val temp = varProvider(0)
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTSTATIC =>
        val temp = varProvider(0)
        val f = new StaticFieldAccessExpression(s"@@${fqn.fqn}", fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case GETFIELD =>
        val base = varProvider(0)
        val temp = varProvider(1)
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(temp, f, annotations.toList)
      case PUTFIELD =>
        val temp = varProvider(0)
        val base = varProvider(1)
        val f = new AccessExpression(base, fqn.fqn, fqn.typ)
        new AssignmentStatement(f, temp, annotations.toList)
      case _ => throw DeBytecodeException(s"Unknown opcode for FieldInsn: $opcode")
    }
    Some(stmt)
  }
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
case class MethodInsn(opcode: Int, owner: String, name: String, desc: String, itf: Boolean) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val typ = JavaKnowledge.getTypeFromName(owner.replaceAll("/", "."))
    val sig = new Signature(typ, name, desc)
    val stmt: Statement = opcode match {
      case INVOKEVIRTUAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(i => varProvider(i)).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(varProvider(argNum))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "virtual")
      case INVOKESPECIAL =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(i => varProvider(i)).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(varProvider(argNum))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "direct")
      case INVOKESTATIC =>
        val argNum = sig.getParameterNum
        val argNames = (0 until argNum).map(i => varProvider(i)).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(varProvider(argNum))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "static")
      case INVOKEINTERFACE =>
        val argNum = sig.getParameterNum + 1
        val argNames = (0 until argNum).map(i => varProvider(i)).reverse.toList
        val retVar = if(sig.getReturnType != JavaKnowledge.VOID) {
          Some(varProvider(argNum))
        } else {
          None
        }
        new CallStatement(retVar, name, argNames, sig, "interface")
      case _ => throw DeBytecodeException(s"Unknown opcode for MethodInsn: $opcode")
    }
    Some(stmt)
  }
}

/**
  * Visits an invokedynamic instruction.
  *
  * @param name
  * the method's name.
  * @param desc
  * the method's descriptor (see { @link Type Type}).
  * @param bsm
  * the bootstrap method.
  * @param bsmArgs
  * the bootstrap method constant arguments. Each argument must be
  * an { @link Integer}, { @link Float}, { @link Long},
  *            { @link Double}, { @link String}, { @link Type} or { @link Handle}
  *            value. This method is allowed to modify the content of the
  *            array so a caller should expect that this array may change.
  */
case class InvokeDynamicInsn(name: FileResourceUri, desc: FileResourceUri, bsm: Handle, bsmArgs: AnyRef*) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    //TODO
    throw DeBytecodeException(s"Unhandled InvokeDynamicInsn")
  }
}

/**
  * Visits a jump instruction. A jump instruction is an instruction that may
  * jump to another instruction.
  *
  * @param opcode
  * the opcode of the type instruction to be visited. This opcode
  * is either IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IF_ICMPEQ,
  * IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
  * IF_ACMPEQ, IF_ACMPNE, GOTO, JSR, IFNULL or IFNONNULL.
  * @param label
  * the operand of the instruction to be visited. This operand is
  * a label that designates the instruction to which the jump
  * instruction may jump.
  */
case class JumpInsn(opcode: Int, label: String) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val stmt: Statement = opcode match {
      case IFEQ =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "==", new LiteralExpression(0))
        new IfStatement(be, label)
      case IFNE =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "!=", new LiteralExpression(0))
        new IfStatement(be, label)
      case IFLT =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "<", new LiteralExpression(0))
        new IfStatement(be, label)
      case IFGE =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, ">=", new LiteralExpression(0))
        new IfStatement(be, label)
      case IFGT =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, ">", new LiteralExpression(0))
        new IfStatement(be, label)
      case IFLE =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "<=", new LiteralExpression(0))
        new IfStatement(be, label)
      case IF_ICMPEQ =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "==", right)
        new IfStatement(be, label)
      case IF_ICMPNE =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "!=", right)
        new IfStatement(be, label)
      case IF_ICMPLT =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "<", right)
        new IfStatement(be, label)
      case IF_ICMPGE =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, ">=", right)
        new IfStatement(be, label)
      case IF_ICMPGT =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, ">", right)
        new IfStatement(be, label)
      case IF_ICMPLE =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "<=", right)
        new IfStatement(be, label)
      case IF_ACMPEQ =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "==", right)
        new IfStatement(be, label)
      case IF_ACMPNE =>
        val right = varProvider(0)
        val left = varProvider(1)
        val be = new BinaryExpression(left, "!=", right)
        new IfStatement(be, label)
      case GOTO =>
        new GotoStatement(label)
      //      case JSR =>
      case IFNULL =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "==")
        new IfStatement(be, label)
      case IFNONNULL =>
        val cond = varProvider(0)
        val be = new BinaryExpression(cond, "!=")
        new IfStatement(be, label)
      case _ => throw DeBytecodeException(s"Unknown opcode for JumpInsn: $opcode")
    }
    Some(stmt)
  }
}

/**
  * Visits a LDC instruction. Note that new constant types may be added in
  * future versions of the Java Virtual Machine. To easily detect new
  * constant types, implementations of this method should check for
  * unexpected constant types, like this:
  *
  * <pre>
  * if (cst instanceof Integer) {
  * // ...
  * } else if (cst instanceof Float) {
  * // ...
  * } else if (cst instanceof Long) {
  * // ...
  * } else if (cst instanceof Double) {
  * // ...
  * } else if (cst instanceof String) {
  * // ...
  * } else if (cst instanceof Type) {
  * int sort = ((Type) cst).getSort();
  * if (sort == Type.OBJECT) {
  * // ...
  * } else if (sort == Type.ARRAY) {
  * // ...
  * } else if (sort == Type.METHOD) {
  * // ...
  * } else {
  * // throw an exception
  * }
  * } else if (cst instanceof Handle) {
  * // ...
  * } else {
  * // throw an exception
  * }
  * </pre>
  *
  * @param cst
  * the constant to be loaded on the stack. This parameter must be
  * a non null { @link Integer}, a { @link Float}, a { @link Long}, a
  *                    { @link Double}, a { @link String}, a { @link Type} of OBJECT or
  *                    ARRAY sort for <tt>.class</tt> constants, for classes whose
  *                    version is 49.0, a { @link Type} of METHOD sort or a
  *                    { @link Handle} for MethodType and MethodHandle constants, for
  *                    classes whose version is 51.0.
  */
case class LdcInsn(cst: Any) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val expr = cst.getClass.getName match {
      case "java.lang.Integer" =>
        new LiteralExpression(cst.asInstanceOf[java.lang.Integer].intValue())
      case "java.lang.Float" =>
        new LiteralExpression(cst.asInstanceOf[java.lang.Float].floatValue())
      case "java.lang.Long" =>
        new LiteralExpression(cst.asInstanceOf[java.lang.Long].longValue())
      case "java.lang.Double" =>
        new LiteralExpression(cst.asInstanceOf[java.lang.Double].doubleValue())
      case "java.lang.String" =>
        new LiteralExpression(cst.asInstanceOf[java.lang.String])
      case "org.objectweb.asm.Type" =>
        val asmType = cst.asInstanceOf[org.objectweb.asm.Type]
        val t = Option(asmType.getClassName) match {
          case Some(cn) => // class type
            JavaKnowledge.getTypeFromJawaName(cn)
          case None => // method type
            throw DeBytecodeException(s"Method type is not handled: $cst")
        }
        new ConstClassExpression(t)
      case "org.objectweb.asm.Handle" =>
        throw DeBytecodeException(s"Handle is not handled: $cst")
      case _ => throw DeBytecodeException(s"Unknown opcode for LdcInsn: $cst")
    }
    val temp = varProvider(0)
    Some(new AssignmentStatement(temp, expr, ilistEmpty))
  }
}

/**
  * Visits an IINC instruction.
  *
  * @param v
  * index of the local variable to be incremented.
  * @param increment
  * amount to increment the local variable by.
  */
case class IincInsn(v: Int, increment: Int) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val name = varProvider(0)
    val negative = Math.signum(increment) == -1
    val num = Math.abs(increment)
    val op = if(negative) "-" else "+"
    val be = new BinaryExpression(name, op, new LiteralExpression(num))
    Some(new AssignmentStatement(name, be, ilistEmpty))
  }
}

/**
  * Visits a TABLESWITCH instruction.
  *
  * @param min
  * the minimum key value.
  * @param max
  * the maximum key value.
  * @param dflt
  * beginning of the default handler block.
  * @param labels
  * beginnings of the handler blocks. <tt>labels[i]</tt> is the
  * beginning of the handler block for the <tt>min + i</tt> key.
  */
case class TableSwitchInsn(min: Int, max: Int, dflt: String, labels: Seq[String]) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val cond = varProvider(0)
    val cases: IList[SwitchCase] = (min to max).map { i =>
      val idx = i - min
      val label = labels(idx)
      new SwitchCase(i, label)
    }.toList
    val defaultCase = new SwitchDefaultCase(dflt)
    Some(new SwitchStatement(cond, cases, defaultCase))
  }
}

/**
  * Visits a LOOKUPSWITCH instruction.
  *
  * @param dflt
  * beginning of the default handler block.
  * @param keys
  * the values of the keys.
  * @param labels
  * beginnings of the handler blocks. <tt>labels[i]</tt> is the
  * beginning of the handler block for the <tt>keys[i]</tt> key.
  */
case class LookupSwitchInsn(dflt: String, keys: Array[Int], labels: Array[String]) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val cond = varProvider(0)
    val cases: IList[SwitchCase] = keys.indices.map { i =>
      val key = keys(i)
      val label = labels(i)
      new SwitchCase(key, label)
    }.toList
    val defaultCase = new SwitchDefaultCase(dflt)
    Some(new SwitchStatement(cond, cases, defaultCase))
  }
}

/**
  * Visits a MULTIANEWARRAY instruction.
  *
  * @param desc
  * an array type descriptor (see { @link Type Type}).
  * @param dims
  * number of dimensions of the array to allocate.
  */
case class MultiANewArrayInsn(desc: String, dims: Int) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    val typ = JavaKnowledge.formatSignatureToType(desc)
    val idxs = (0 until dims).map(i => varProvider(i)).reverse.toList
    val temp = varProvider(dims)
    val arrayType = JawaType.addDimensions(typ, -1)
    val ne = new NewArrayExpression(arrayType, idxs)
    Some(new AssignmentStatement(temp, ne, ilistEmpty))
  }
}

/**
  * Visits a label. A label designates the instruction that will be visited
  * just after it.
  *
  * @param label
  * a { @link Label Label} object.
  */
case class LabelInsn(label: String, annotations: MList[Annotation], var typ: Option[JawaType]) extends BytecodeInstruction {
  def exec(varProvider: Int => String): Option[Statement] = {
    Some(EmptyStatement(annotations)(NoPosition))
  }
}