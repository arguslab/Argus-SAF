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

import org.argus.jawa.core.util._
import org.argus.jawa.core.elements._
import org.objectweb.asm.Label

import scala.collection.mutable

class LocalVarResolver(sig: Signature) {

  val localVariables: MMap[Int, MList[VarScope]] = mmapEmpty
  private val usedVariables: MMap[String, JawaType] = mmapEmpty

  private def checkAndAddVariable(varType: JawaType, name: Option[String]): String = {
    val expectedName = name match {
      case Some(n) =>
        n
      case None =>
        s"${varType.baseType.name}${if(varType.isArray) s"_arr${varType.dimensions}" else ""}_temp"
    }
    var varName = expectedName
    var i = 1
    while(stackVars.exists(sv => sv.name == varName)) {
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
      usedVariables(varName) = varType
    }
    varName
  }

  private def load(loc: Int, idx: Int): LocalVariable = {
    val vs = localVariables.getOrElse(idx, throw DeBytecodeException(s"Failed to load idx $idx")).find{ v =>
      v.inScope(loc)
    }.getOrElse(throw DeBytecodeException(s"Failed to load idx $idx at loc $loc"))
    val lv = vs.lv
    variables.getOrElseUpdate(loc, mlistEmpty) += lv
    lv
  }

  private def store(loc: Int, idx: Int, typ: TypeRepresentation): Unit = {
    val expectedName = s"${typ.typ.baseType.name}${if(typ.typ.isArray) s"_arr${typ.typ.dimensions}" else ""}_$idx"
    val vs = localVariables.getOrElseUpdate(idx, mutable.ListBuffer(VarScope(0, Integer.MAX_VALUE, new LocalVariable(typ, expectedName)))).find{ v =>
      v.inScope(loc) || v.inScope(loc + 1)
    } match {
      case Some(v) => v
      case None =>
        val v = VarScope(0, Integer.MAX_VALUE, new LocalVariable(typ, expectedName))
        localVariables.getOrElseUpdate(idx, mutable.ListBuffer()) += v
        v
    }
    val lv = vs.lv
    variables.getOrElseUpdate(loc, mlistEmpty) += lv
  }

  val labelIdxs: MMap[Label, Int] = mmapEmpty

  case class VarScope(min: Int, max: Int, lv: LocalVariable) {
    def this(min: Int, max: Int, typ: JawaType, name: String) = this(min, max, new LocalVariable(new TypeRepresentation(typ), name))
    def this(start: Label, end: Label, typ: JawaType, name: String) = this(labelIdxs.getOrElse(start, 0), labelIdxs.getOrElse(end, Integer.MAX_VALUE), typ, name)
    def inScope(l: Label): Boolean = {
      val idx = labelIdxs.getOrElse(l, 0)
      min <= idx && idx < max
    }
    def inScope(loc: Int): Boolean = {
      min <= loc && loc < max
    }
  }

  class BaseType(var bt: JawaBaseType)
  class TypeRepresentation(val bt: BaseType, val dim: Int) {
    def this(typ: JawaType) = this(new BaseType(typ.baseType), typ.dimensions)
    def typ: JawaType = new JawaType(bt.bt, dim)
    def add(i: Int): TypeRepresentation = new TypeRepresentation(bt, dim + i)
  }

  class LocalVariable(val typ: TypeRepresentation, val name: String)

  val variables: MMap[Int, MList[LocalVariable]] = mmapEmpty
  def getVariableAt(loc: Int, idx: Int): LocalVariable = {
    variables.getOrElse(loc, mlistEmpty).lift(idx).getOrElse(throw DeBytecodeException(s"Could not get variable at loc $loc idx $idx"))
  }

  private var stackVars: IList[LocalVariable] = ilistEmpty

  private def push(loc: Int, typ: TypeRepresentation): Unit = {
    val name = checkAndAddVariable(typ.typ, None)
    val lv = new LocalVariable(typ, name)
    stackVars = lv :: stackVars
    variables.getOrElseUpdate(loc, mlistEmpty) += lv
  }

  private def dup(pos: Int): Unit = {
    require(stackVars.lengthCompare(pos) >= 0, s"Stack size less than dup $pos requirement")
    val (front, back) = stackVars.splitAt(pos)
    stackVars = front ::: stackVars.head :: back
  }

  private def swap(): Unit = {
    require(stackVars.lengthCompare(2) >= 0, s"Stack size less than 2 for swap")
    stackVars = stackVars.take(2).reverse ::: stackVars.drop(2)
  }

  private def pop(loc: Int, expected: Option[JawaType]): LocalVariable = {
    require(stackVars.nonEmpty, "Stack should not be empty via pop")
    val variable :: tail = stackVars
    stackVars = tail
    if(variable.typ.typ.baseType.unknown) {
      expected match {
        case Some(typ) =>
          variable.typ.bt.bt = typ.baseType
        case None =>
      }
    }
    variables.getOrElseUpdate(loc, mlistEmpty) += variable
    variable
  }

  private def getClassName(name: String): String = {
    name.replaceAll("/", ".")
  }

  private val labelStack: MMap[String, IList[LocalVariable]] = mmapEmpty

  import org.objectweb.asm.Opcodes._
  def resolveType(instructions: IList[BytecodeInstruction]): Unit = {
    instructions.zipWithIndex.foreach { case (ins, loc) =>
      ins match {
        case Insn(opcode) =>
          opcode match {
            case NOP =>
            case ACONST_NULL =>
              push(loc, new TypeRepresentation(JavaKnowledge.OBJECT.toUnknown))
            case ICONST_M1 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_0 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_1 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_2 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_3 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_4 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ICONST_5 =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LCONST_0 =>
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case LCONST_1 =>
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FCONST_0 =>
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case FCONST_1 =>
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case FCONST_2 =>
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DCONST_0 =>
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case DCONST_1 =>
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case IALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.INT, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.LONG, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.FLOAT, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.DOUBLE, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case AALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              val lv = pop(loc, None)
              push(loc, lv.typ.add(-1))
            case BALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.BYTE, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.BYTE))
            case CALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.CHAR, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.CHAR))
            case SALOAD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.SHORT, 1)))
              push(loc, new TypeRepresentation(JavaKnowledge.SHORT))
            case IASTORE =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.INT, 1)))
            case LASTORE =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.LONG, 1)))
            case FASTORE =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.FLOAT, 1)))
            case DASTORE =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.DOUBLE, 1)))
            case AASTORE =>
              val value = pop(loc, None)
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(value.typ.add(1).typ))
            case BASTORE =>
              pop(loc, Some(JavaKnowledge.BYTE))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.BYTE, 1)))
            case CASTORE =>
              pop(loc, Some(JavaKnowledge.CHAR))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.CHAR, 1)))
            case SASTORE =>
              pop(loc, Some(JavaKnowledge.SHORT))
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JawaType.addDimensions(JavaKnowledge.SHORT, 1)))
            case POP =>
              pop(loc, None)
            case POP2 =>
              pop(loc, None)
              pop(loc, None)
            case DUP =>
              dup(0)
            case DUP_X1 =>
              dup(1)
            case DUP_X2 =>
              dup(1)
            case DUP2 =>
              dup(0)
            case DUP2_X1 =>
              dup(1)
            case DUP2_X2 =>
              dup(1)
            case SWAP =>
              swap()
            case IADD =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LADD =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FADD =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DADD =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case ISUB =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LSUB =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FSUB =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DSUB =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case IMUL =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LMUL =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FMUL =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DMUL =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case IDIV =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LDIV =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FDIV =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DDIV =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case IREM =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LREM =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FREM =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DREM =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case INEG =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LNEG =>
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FNEG =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DNEG =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case ISHL =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LSHL =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case ISHR =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LSHR =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case IUSHR =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LUSHR =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case IAND =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LAND =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case IOR =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LOR =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case IXOR =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LXOR =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case I2L =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case I2F =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case I2D =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case L2I =>
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case L2F =>
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case L2D =>
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case F2I =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case F2L =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case F2D =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case D2I =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case D2L =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case D2F =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case I2B =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.BYTE))
            case I2C =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.CHAR))
            case I2S =>
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(JavaKnowledge.SHORT))
            case LCMP =>
              pop(loc, Some(JavaKnowledge.LONG))
              pop(loc, Some(JavaKnowledge.LONG))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case FCMPL =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case FCMPG =>
              pop(loc, Some(JavaKnowledge.FLOAT))
              pop(loc, Some(JavaKnowledge.FLOAT))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case DCMPL =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case DCMPG =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
              pop(loc, Some(JavaKnowledge.DOUBLE))
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case IRETURN =>
              pop(loc, Some(JavaKnowledge.INT))
            case LRETURN =>
              pop(loc, Some(JavaKnowledge.LONG))
            case FRETURN =>
              pop(loc, Some(JavaKnowledge.FLOAT))
            case DRETURN =>
              pop(loc, Some(JavaKnowledge.DOUBLE))
            case ARETURN =>
              pop(loc, Some(sig.getReturnType))
            case RETURN =>
            case ARRAYLENGTH =>
              pop(loc, None)
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case ATHROW =>
              pop(loc, None)
            case MONITORENTER =>
              pop(loc, None)
            case MONITOREXIT =>
              pop(loc, None)
            case _ => throw DeBytecodeException(s"Unknown opcode for Insn: $opcode")
          }
        case IntInsn(opcode, operand) =>
          opcode match {
            case BIPUSH =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case SIPUSH =>
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
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
              val arrType = JawaType.addDimensions(typ, 1)
              pop(loc, Some(JavaKnowledge.INT))
              push(loc, new TypeRepresentation(arrType))
            case _ => throw DeBytecodeException(s"Unknown opcode for IntInsn: $opcode")
          }
        case VarInsn(opcode, v) =>
          opcode match {
            case ILOAD =>
              load(loc, v)
              push(loc, new TypeRepresentation(JavaKnowledge.INT))
            case LLOAD =>
              load(loc, v)
              push(loc, new TypeRepresentation(JavaKnowledge.LONG))
            case FLOAD =>
              load(loc, v)
              push(loc, new TypeRepresentation(JavaKnowledge.FLOAT))
            case DLOAD =>
              load(loc, v)
              push(loc, new TypeRepresentation(JavaKnowledge.DOUBLE))
            case ALOAD =>
              val lv = load(loc, v)
              push(loc, lv.typ)
            case ISTORE =>
              val lv = pop(loc, Some(JavaKnowledge.INT))
              store(loc, v, lv.typ)
            case LSTORE =>
              val lv = pop(loc, Some(JavaKnowledge.LONG))
              store(loc, v, lv.typ)
            case FSTORE =>
              val lv = pop(loc, Some(JavaKnowledge.FLOAT))
              store(loc, v, lv.typ)
            case DSTORE =>
              val lv = pop(loc, Some(JavaKnowledge.DOUBLE))
              store(loc, v, lv.typ)
            case ASTORE =>
              val typ = localVariables.getOrElse(v, mlistEmpty).find{ v =>
                v.inScope(loc)
              }.map(vs => vs.lv.typ.typ)
              val lv = pop(loc, typ)
              store(loc, v, lv.typ)
            //      case RET =>
            case _ => throw DeBytecodeException(s"Unknown opcode for VarInsn: $opcode")
          }
        case TypeInsn(opcode, t) =>
          val typ = JavaKnowledge.getTypeFromName(getClassName(t))
          opcode match {
            case NEW =>
              push(loc, new TypeRepresentation(typ))
            case ANEWARRAY =>
              pop(loc, Some(JavaKnowledge.INT))
              val arrType = JawaType.addDimensions(typ, 1)
              push(loc, new TypeRepresentation(arrType))
            case CHECKCAST =>
              pop(loc, Some(typ))
              push(loc, new TypeRepresentation(typ))
            case INSTANCEOF =>
              pop(loc, Some(typ))
              push(loc, new TypeRepresentation(JavaKnowledge.BOOLEAN))
            case _ => throw DeBytecodeException(s"Unknown opcode for TypeInsn: $opcode")
          }
        case FieldInsn(opcode, owner, name, desc) =>
          val fqn = new FieldFQN(JavaKnowledge.getTypeFromName(getClassName(owner)),
                                 name, JavaKnowledge.formatSignatureToType(desc))
          opcode match {
            case GETSTATIC =>
              push(loc, new TypeRepresentation(fqn.typ))
            case PUTSTATIC =>
              pop(loc, Some(fqn.typ))
            case GETFIELD =>
              pop(loc, Some(fqn.owner))
              push(loc, new TypeRepresentation(fqn.typ))
            case PUTFIELD =>
              pop(loc, Some(fqn.typ))
              pop(loc, Some(fqn.owner))
            case _ => throw DeBytecodeException(s"Unknown opcode for FieldInsn: $opcode")
          }
        case MethodInsn(opcode, owner, name, desc, _) =>
          val typ = JavaKnowledge.getTypeFromName(getClassName(owner))
          val sig = new Signature(typ, name, desc)
          sig.getParameterTypes.reverse.map{ pt =>
            pop(loc, Some(pt))
          }
          if(opcode != INVOKESTATIC) {
            pop(loc, Some(sig.getClassType))
          }
          if(sig.getReturnType != JavaKnowledge.VOID) {
            push(loc, new TypeRepresentation(sig.getReturnType))
          }
        case InvokeDynamicInsn(_, _, _, _) =>
          throw DeBytecodeException(s"Unhandled InvokeDynamicInsn")
        case JumpInsn(opcode, target) =>
          opcode match {
            case IFEQ =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IFNE =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IFLT =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IFGE =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IFGT =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IFLE =>
              pop(loc, Some(JavaKnowledge.BOOLEAN))
            case IF_ICMPEQ =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ICMPNE =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ICMPLT =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ICMPGE =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ICMPGT =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ICMPLE =>
              pop(loc, Some(JavaKnowledge.INT))
              pop(loc, Some(JavaKnowledge.INT))
            case IF_ACMPEQ =>
              pop(loc, None)
              pop(loc, None)
            case IF_ACMPNE =>
              pop(loc, None)
              pop(loc, None)
            case GOTO =>
            //      case JSR =>
            case IFNULL =>
              pop(loc, None)
            case IFNONNULL =>
              pop(loc, None)
            case _ => throw DeBytecodeException(s"Unknown opcode for JumpInsn: $opcode")
          }
          labelStack(target) = stackVars
        case LdcInsn(cst) =>
          val typ = cst.getClass.getName match {
            case "java.lang.Integer" =>
              JavaKnowledge.INT
            case "java.lang.Float" =>
              JavaKnowledge.FLOAT
            case "java.lang.Long" =>
              JavaKnowledge.LONG
            case "java.lang.Double" =>
              JavaKnowledge.DOUBLE
            case "java.lang.String" =>
              JavaKnowledge.STRING
            case "org.objectweb.asm.Type" =>
              JavaKnowledge.CLASS
            case "org.objectweb.asm.Handle" =>
              throw DeBytecodeException(s"Handle is not handled: $cst")
            case _ => throw DeBytecodeException(s"Unknown opcode for LdcInsn: $cst")
          }
          push(loc, new TypeRepresentation(typ))
        case IincInsn(v, _) =>
          load(loc, v)
        case TableSwitchInsn(_, _, dflt, ls) =>
          pop(loc, Some(JavaKnowledge.INT))
          ls.foreach {l => labelStack(l) = stackVars}
          labelStack(dflt) = stackVars
        case LookupSwitchInsn(dflt, _, ls) =>
          pop(loc, Some(JavaKnowledge.INT))
          ls.foreach {l => labelStack(l) = stackVars}
          labelStack(dflt) = stackVars
        case MultiANewArrayInsn(desc, dims) =>
          val typ = JavaKnowledge.formatSignatureToType(desc)
          (0 until dims).foreach(_ => pop(loc, Some(JavaKnowledge.INT)))
          push(loc, new TypeRepresentation(typ))
        case LabelInsn(l, _, typ) =>
          stackVars = labelStack.getOrElse(l, stackVars)
          typ match {
            case Some(t) =>
              push(loc, new TypeRepresentation(t))
            case None =>
          }
      }
    }
  }
}