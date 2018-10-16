/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import java.io.{IOException, StringWriter, Writer}

import org.argus.jawa.core.codegen.JawaModelProvider
import org.argus.jawa.core.elements.{FieldFQN, JavaKnowledge, JawaType, Signature}
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.base.reference.BaseFieldReference
import org.jf.dexlib2.dexbacked.DexBackedMethod
import org.jf.dexlib2.dexbacked.instruction._
import org.jf.dexlib2.dexbacked.reference.{DexBackedFieldReference, DexBackedMethodReference}
import org.jf.dexlib2.iface.instruction.{FiveRegisterInstruction, NarrowLiteralInstruction, RegisterRangeInstruction, WideLiteralInstruction}
import org.jf.util.{NibbleUtils, NumberUtils}
import org.argus.jawa.core.util._
import org.stringtemplate.v4.STGroupString

import collection.JavaConverters._
import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class DexInstructionToJawaParser(
    dexMethod: DexBackedMethod,
    generator: JawaStyleCodeGenerator,
    exceptionTypeMap: IMap[Long, JawaType],
    template: STGroupString) extends DexConstants {

  final val TITLE = "DexInstructionToJawaParser"
  final val DEBUG = false

  import generator._

  // For special task param type resolve
  private val fillArrayMapping: MMap[Long, (Long, String)] = mmapEmpty
  private val switchMapping: MMap[Long, (Long, Long, String)] = mmapEmpty

  /**
   * The input like: methodName: java/io/File/<init>, proto: <init>(Ljava/lang/String;)V
   * The output like: Ljava/io/File;.<init>:(Ljava/lang/String;)V
   */
  private def getSignature(ref: DexBackedMethodReference): Signature = {
    val classPart: String = ref.getDefiningClass
    val methodNamePart: String = ref.getName
    val paramSigPart: String = "(" + ref.getParameterTypes.asScala.mkString("") + ")" + ref.getReturnType
    val sig = new Signature(classPart + "." + methodNamePart + ":" + paramSigPart)
    sig.signature.resolveProcedure
  }
  
  def calculateTarget(instrBase: Long, offset: Int): Long = {
    instrBase + (offset * 2L)
  }

  /**
    * modified from org.apache.commons.lang.StringEscapeUtils
    * @param str rawstring to escape
    */
  private def escapeJavaStyleString(str: String): String = {
    if (str == null) return null
    try {
      val writer: StringWriter = new StringWriter(str.length * 2)
      escapeJavaStyleString(writer, str)
      writer.toString
    } catch {
      case ioe: IOException =>
        // this should never ever happen while writing to a StringWriter
        ioe.printStackTrace()
        null
    }
  }

  private def escapeJavaStyleString(out: Writer, str: String): Unit = {
    if (out == null) throw new IllegalArgumentException("The Writer must not be null")
    if (str == null) return
    var sz: Int = 0
    sz = str.length
    var i: Int = 0
    while (i < sz) {
      {
        val ch: Char = str.charAt(i)
        if (ch < 32) ch match {
          case '\b' =>
            out.write('\\')
            out.write('b')
          case '\n' =>
            out.write('\\')
            out.write('n')
          case '\t' =>
            out.write('\\')
            out.write('t')
          case '\f' =>
            out.write('\\')
            out.write('f')
          case '\r' =>
            out.write('\\')
            out.write('r')
          case _ =>
            if (ch > 0xf) out.write("\\u00" + hex(ch))
            else out.write("\\u000" + hex(ch))
        } else ch match {
          case '"' =>
            out.write('\\')
            out.write('"')
          case '\\' =>
            out.write('\\')
            out.write('\\')
          case _ =>
            out.write(ch)
        }
      }
      {
        i += 1; i - 1
      }
    }
  }

  private def hex(ch: Char): String = Integer.toHexString(ch).toUpperCase

  implicit class VarName(i: Int) {
    def toVar: String = "v" + i
  }

  private def getFQNFieldReference(ref: BaseFieldReference): FieldFQN = {
    var defClass = JavaKnowledge.formatSignatureToType(ref.getDefiningClass)
    defClass = defClass.jawaName.resolveRecord
    val name = defClass.jawaName + "." + ref.getName
    val typ = JavaKnowledge.formatSignatureToType(ref.getType)
    name.resolveAttribute(typ)
  }

  private def getInvokeMethodInfo(ref: DexBackedMethodReference): (Option[String], String, Signature, String) = {
    val signature = getSignature(ref)
    val retName = signature.getReturnType.jawaName match {
      case "void" => None
      case _ => Some("temp")
    }
    val methodName = signature.methodName
    val classTyp = JawaModelProvider.generateType(signature.getClassType, template).render()
    (retName, methodName, signature, classTyp)
  }

  private def getInvokeElements(i35c: DexBackedInstruction35c, isStatic: Boolean): (Option[String], String, IList[String], Signature, String) = {
    val (retName, methodName, signature, classTyp) = getInvokeMethodInfo(i35c.getReference.asInstanceOf[DexBackedMethodReference])
    val args = filterRegsForDoubleWords(getRegsFrom5(i35c), signature, isStatic)
    (retName, methodName, args.map(_.toVar), signature, classTyp)
  }

  private def getInvokeElements(i3rc: DexBackedInstruction3rc, isStatic: Boolean): (Option[String], String, IList[String], Signature, String) = {
    val (retName, methodName, signature, classTyp) = getInvokeMethodInfo(i3rc.getReference.asInstanceOf[DexBackedMethodReference])
    val args = filterRegsForDoubleWords(getRegsFromr(i3rc), signature, isStatic)
    (retName, methodName, args.map(_.toVar), signature, classTyp)
  }

  private def getRegsFrom5(i35c: DexBackedInstruction with FiveRegisterInstruction): IList[Int] = {
    val regs: MList[Int] = mlistEmpty
    var byteCounter = 3
    var regno = i35c.getRegisterCount
    var lastreg = -1
    if((regno > 4) && (regno % 4) == 1) {
      regno -= 1
      lastreg = i35c.getRegisterG
    }
    for (i <- 0 until regno) {
      var reg = 0
      if ((i % 2) == 0) {
        byteCounter += 1
        reg = NibbleUtils.extractLowUnsignedNibble(i35c.dexFile.readUbyte(i35c.instructionStart + byteCounter))
      } else
        reg = NibbleUtils.extractHighUnsignedNibble(i35c.dexFile.readUbyte(i35c.instructionStart + byteCounter))
      regs += reg
    }
    if(lastreg != -1) regs += lastreg
    regs.toList
  }

  private def getRegsFromr(i3rc: DexBackedInstruction with RegisterRangeInstruction): IList[Int] = {
    val regno = i3rc.getRegisterCount
    val regbase = i3rc.getStartRegister
    (0 until regno).map(regbase + _).toList
  }

  private def filterRegsForDoubleWords(args: IList[Int], signature: Signature, isStatic: Boolean): IList[Int] = {
    val newArgs: MList[Int] = mlistEmpty
    val ptyps = signature.getParameterTypes
    var j = 0
    var nextpass = false
    for(i <- args.indices) {
      val arg = args(i)
      if (!isStatic && i == 0) {
        newArgs += arg
      } else {
        val ptyp =
          if (ptyps.isDefinedAt(j)) ptyps(j)
          else JavaKnowledge.OBJECT
        ptyp match {
          case pt if pt.jawaName == "long" || pt.jawaName == "double" =>
            if (!nextpass) {
              newArgs += arg
              nextpass = true
            } else {
              nextpass = false
              j += 1
            }
          case _ =>
            newArgs += arg
            j += 1
        }
      }
    }
    newArgs.toList
  }

  private def resolveConst(inst: DexBackedInstruction): (String, JawaType) = {
    if (inst.getOpcode.setsWideRegister()) {
      val lit: Long = inst.asInstanceOf[WideLiteralInstruction].getWideLiteral
      if (NumberUtils.isLikelyDouble(lit)) {
        (java.lang.Double.toString(java.lang.Double.longBitsToDouble(lit)), new JawaType("double"))
      } else {
        (java.lang.Long.toString(lit), new JawaType("long"))
      }
    } else {
      val lit: Int = inst.asInstanceOf[NarrowLiteralInstruction].getNarrowLiteral
      if (NumberUtils.isLikelyFloat(lit)) {
        (java.lang.Float.toString(java.lang.Float.intBitsToFloat(lit)), new JawaType("float"))
      } else {
        (Integer.toString(lit), new JawaType("int"))
      }
    }
  }

  def parse(inst: DexBackedInstruction, startPos: Long, endPos: Long): String = {
    val instrBase: Long = inst.instructionStart
    def inRange: (Long => Boolean) = pos => startPos <= pos && pos <= endPos
    val insttAddress: String = "#L%06x.  ".format(instrBase)
    insttAddress + {
      inst.getOpcode match {
        case Opcode.NOP => // 0
          nop
        case Opcode.MOVE => // 1
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          move(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MOVE_FROM16 => // 2
          val i22x = inst.asInstanceOf[DexBackedInstruction22x]
          move(i22x.getRegisterA.toVar, i22x.getRegisterB.toVar)
        case Opcode.MOVE_16 => // 3
          val i32x = inst.asInstanceOf[DexBackedInstruction32x]
          move(i32x.getRegisterA.toVar, i32x.getRegisterB.toVar)
        case Opcode.MOVE_WIDE => // 4
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          moveWide(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MOVE_WIDE_FROM16 => // 5
          val i22x = inst.asInstanceOf[DexBackedInstruction22x]
          moveWide(i22x.getRegisterA.toVar, i22x.getRegisterB.toVar)
        case Opcode.MOVE_WIDE_16 => // 6
          val i32x = inst.asInstanceOf[DexBackedInstruction32x]
          moveWide(i32x.getRegisterA.toVar, i32x.getRegisterB.toVar)
        case Opcode.MOVE_OBJECT => // 7
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          moveObject(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MOVE_OBJECT_FROM16 => // 8
          val i22x = inst.asInstanceOf[DexBackedInstruction22x]
          moveObject(i22x.getRegisterA.toVar, i22x.getRegisterB.toVar)
        case Opcode.MOVE_OBJECT_16 => // 9
          val i32x = inst.asInstanceOf[DexBackedInstruction32x]
          moveObject(i32x.getRegisterA.toVar, i32x.getRegisterB.toVar)
        case Opcode.MOVE_RESULT => // 10
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          moveResult(i11x.getRegisterA.toVar, "temp")
        case Opcode.MOVE_RESULT_WIDE => // 11
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          moveResultWide(i11x.getRegisterA.toVar, "temp")
        case Opcode.MOVE_RESULT_OBJECT => // 12
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          moveResultObject(i11x.getRegisterA.toVar, "temp")
        case Opcode.MOVE_EXCEPTION => // 13
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          moveExc(i11x.getRegisterA.toVar, JawaModelProvider.generateType(exceptionTypeMap.getOrElse(instrBase, new JawaType("java.lang.Exception")), template).render())
        case Opcode.RETURN_VOID => // 14
          returnVoid
        case Opcode.RETURN => // 15
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          `return`(i11x.getRegisterA.toVar)
        case Opcode.RETURN_WIDE => // 16
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          returnWide(i11x.getRegisterA.toVar)
        case Opcode.RETURN_OBJECT => // 17
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          returnObj(i11x.getRegisterA.toVar)
        case Opcode.CONST_4 => // 18
          val i11n = inst.asInstanceOf[DexBackedInstruction11n]
          const(i11n.getRegisterA.toVar, Integer.toString(i11n.getNarrowLiteral), new JawaType("int"), null)
        case Opcode.CONST_16 => // 19
          val i21s = inst.asInstanceOf[DexBackedInstruction21s]
          const(i21s.getRegisterA.toVar, Integer.toString(i21s.getNarrowLiteral), new JawaType("int"), null)
        case Opcode.CONST => // 20
          val i31i = inst.asInstanceOf[DexBackedInstruction31i]
          const(i31i.getRegisterA.toVar, Integer.toString(i31i.getNarrowLiteral), new JawaType("int"), null)
        case Opcode.CONST_HIGH16 => // 21
          val i21ih = inst.asInstanceOf[DexBackedInstruction21ih]
          val (lit, typ) = resolveConst(i21ih)
          const(i21ih.getRegisterA.toVar, lit, typ, null)
        case Opcode.CONST_WIDE_16 => // 22
          val i21s = inst.asInstanceOf[DexBackedInstruction21s]
          val (lit, typ) = resolveConst(i21s)
          constWide(i21s.getRegisterA.toVar, lit, typ)
        case Opcode.CONST_WIDE_32 => // 23
          val i31i = inst.asInstanceOf[DexBackedInstruction31i]
          val (lit, typ) = resolveConst(i31i)
          constWide(i31i.getRegisterA.toVar, lit, typ)
        case Opcode.CONST_WIDE => // 24
          val i51l = inst.asInstanceOf[DexBackedInstruction51l]
          val (lit, typ) = resolveConst(i51l)
          constWide(i51l.getRegisterA.toVar, lit, typ)
        case Opcode.CONST_WIDE_HIGH16 => // 25
          val i21lh = inst.asInstanceOf[DexBackedInstruction21lh]
          val (lit, typ) = resolveConst(i21lh)
          constWide(i21lh.getRegisterA.toVar, lit, typ)
        case Opcode.CONST_STRING => // 26
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val string = escapeJavaStyleString(i21c.getReference.toString)
          if(string.lines.size > 1) constMString(i21c.getRegisterA.toVar, string)
          else constString(i21c.getRegisterA.toVar, string)
        case Opcode.CONST_STRING_JUMBO => // 27
          val i31c = inst.asInstanceOf[DexBackedInstruction31c]
          val string = escapeJavaStyleString(i31c.getReference.toString)
          if(string.lines.size > 1) constMString(i31c.getRegisterA.toVar, string)
          else constString(i31c.getRegisterA.toVar, string)
        case Opcode.CONST_CLASS => // 28
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          var typ = JavaKnowledge.formatSignatureToType(i21c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          constClass(i21c.getRegisterA.toVar, JawaModelProvider.generateType(typ, template).render)
        case Opcode.MONITOR_ENTER => // 29
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          monitorEnter(i11x.getRegisterA.toVar)
        case Opcode.MONITOR_EXIT => // 30
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          monitorExit(i11x.getRegisterA.toVar)
        case Opcode.CHECK_CAST => // 31
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          var typ = JavaKnowledge.formatSignatureToType(i21c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          checkCast(i21c.getRegisterA.toVar, JawaModelProvider.generateType(typ, template).render(), i21c.getRegisterA.toVar)
        case Opcode.INSTANCE_OF => // 32
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          var typ = JavaKnowledge.formatSignatureToType(i22c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          instanceOf(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, JawaModelProvider.generateType(typ, template).render())
        case Opcode.ARRAY_LENGTH => // 33
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          arrayLen(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NEW_INSTANCE => // 34
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          var typ = JavaKnowledge.formatSignatureToType(i21c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          newIns(i21c.getRegisterA.toVar, JawaModelProvider.generateType(typ, template).render())
        case Opcode.NEW_ARRAY => // 35
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          var typ = JavaKnowledge.formatSignatureToType(i22c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          newArray(i22c.getRegisterA.toVar, JawaModelProvider.generateType(JawaType.generateType(typ.baseTyp, typ.dimensions - 1), template).render(), i22c.getRegisterB.toVar)
        case Opcode.FILLED_NEW_ARRAY => // 36
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val regs = getRegsFrom5(i35c)
          var typ = JavaKnowledge.formatSignatureToType(i35c.getReference.toString)
          typ = typ.jawaName.resolveRecord
          filledNewArray("temp", JawaModelProvider.generateType(JawaType.generateType(typ.baseTyp, typ.dimensions - 1), template).render(), regs.map(_.toVar))
        case Opcode.FILLED_NEW_ARRAY_RANGE => // 37
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val regs: IList[Int] = getRegsFromr(i3rc)
          var typ = JavaKnowledge.formatSignatureToType(i3rc.getReference.toString)
          typ = typ.jawaName.resolveRecord
          filledNewArray("temp", JawaModelProvider.generateType(JawaType.generateType(typ.baseTyp, typ.dimensions - 1), template).render(), regs.map(_.toVar))
        case Opcode.FILL_ARRAY_DATA => // 38
          val i31t = inst.asInstanceOf[DexBackedInstruction31t]
          val target: Long = calculateTarget(instrBase, i31t.getCodeOffset)
          fillArrayMapping(target) = (calculateTarget(instrBase, i31t.getCodeUnits), i31t.getRegisterA.toVar)
          fillArrData(target)
        case Opcode.THROW => // 39
          val i11x = inst.asInstanceOf[DexBackedInstruction11x]
          `throw`(i11x.getRegisterA.toVar)
        case Opcode.GOTO => // 40
          val i10t = inst.asInstanceOf[DexBackedInstruction10t]
          val target = calculateTarget(instrBase, i10t.getCodeOffset)
          if(inRange(target))
            goto(target)
          else "@INVALID_GOTO"
        case Opcode.GOTO_16 => // 41
          val i20t = inst.asInstanceOf[DexBackedInstruction20t]
          val target = calculateTarget(instrBase, i20t.getCodeOffset)
          if(inRange(target))
            goto(target)
          else "@INVALID_GOTO_16"
        case Opcode.GOTO_32 => // 42
          val i30t = inst.asInstanceOf[DexBackedInstruction30t]
          val target = calculateTarget(instrBase, i30t.getCodeOffset)
          if(inRange(target))
            goto(target)
          else "@INVALID_GOTO_32"
        case Opcode.PACKED_SWITCH => // 43
          val i31t = inst.asInstanceOf[DexBackedInstruction31t]
          val target = calculateTarget(instrBase, i31t.getCodeOffset)
          switchMapping(target) = (instrBase, calculateTarget(instrBase, i31t.getCodeUnits), i31t.getRegisterA.toVar)
          switch(target)
        case Opcode.SPARSE_SWITCH => // 44
          val i31t = inst.asInstanceOf[DexBackedInstruction31t]
          val target = calculateTarget(instrBase, i31t.getCodeOffset)
          switchMapping(target) = (instrBase, calculateTarget(instrBase, i31t.getCodeUnits), i31t.getRegisterA.toVar)
          switch(target)
        case Opcode.CMPL_FLOAT => // 45
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          fcmpl(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.CMPG_FLOAT => // 46
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          fcmpg(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.CMPL_DOUBLE => // 47
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          dcmpl(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.CMPG_DOUBLE => // 48
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          dcmpg(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.CMP_LONG => // 49
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          lcmp(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.IF_EQ => // 50
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifEq(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_EQ"
        case Opcode.IF_NE => // 51
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifNe(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_NE"
        case Opcode.IF_LT => // 52
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifLt(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_LT"
        case Opcode.IF_GE => // 53
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifGe(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_GE"
        case Opcode.IF_GT => // 54
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifGt(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_GT"
        case Opcode.IF_LE => // 55
          val i22t = inst.asInstanceOf[DexBackedInstruction22t]
          val target = calculateTarget(instrBase, i22t.getCodeOffset)
          if(inRange(target))
            ifLe(i22t.getRegisterA.toVar, i22t.getRegisterB.toVar, target)
          else "@INVALID_IF_LE"
        case Opcode.IF_EQZ => // 56
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifEqz(i21t.getRegisterA.toVar, target, isObject = false)
          else "@INVALID_IF_EQZ"
        case Opcode.IF_NEZ => // 57
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifNez(i21t.getRegisterA.toVar, target, isObject = false)
          else "@INVALID_IF_NEZ"
        case Opcode.IF_LTZ => // 58
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifLtz(i21t.getRegisterA.toVar, target)
          else "@INVALID_IF_LTZ"
        case Opcode.IF_GEZ => // 59
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifGez(i21t.getRegisterA.toVar, target)
          else "@INVALID_IF_GEZ"
        case Opcode.IF_GTZ => // 60
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifGtz(i21t.getRegisterA.toVar, target)
          else "@INVALID_IF_GTZ"
        case Opcode.IF_LEZ => // 61
          val i21t = inst.asInstanceOf[DexBackedInstruction21t]
          val target = calculateTarget(instrBase, i21t.getCodeOffset)
          if(inRange(target))
            ifLez(i21t.getRegisterA.toVar, target)
          else "@INVALID_IF_LEZ"
        case Opcode.AGET => // 68
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aget(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_WIDE => // 69
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetWide(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_OBJECT => // 70
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetObject(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_BOOLEAN => // 71
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetBool(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_BYTE => // 72
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetByte(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_CHAR => // 73
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetChar(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AGET_SHORT => // 74
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          agetShort(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.APUT => // 75
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aput(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_WIDE => // 76
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputWide(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_OBJECT => // 77
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputObject(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_BOOLEAN => // 78
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputBool(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_BYTE => // 79
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputByte(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_CHAR => // 80
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputChar(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.APUT_SHORT => // 81
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          aputShort(i23x.getRegisterB.toVar, i23x.getRegisterC.toVar, i23x.getRegisterA.toVar)
        case Opcode.IGET => // 82
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iget(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_WIDE => // 83
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetWide(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_OBJECT => // 84
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetObject(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_BOOLEAN => // 85
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetBool(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_BYTE => // 86
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetByte(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_CHAR => // 87
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetChar(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_SHORT => // 88
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetShort(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT => // 89
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iput(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_WIDE => // 90
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputWide(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_OBJECT => // 91
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputObject(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_BOOLEAN => // 92
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputBool(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_BYTE => // 93
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputByte(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_CHAR => // 94
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputChar(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_SHORT => // 95
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputChar(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET => // 96
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sget(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_WIDE => // 97
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetWide(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_OBJECT => // 98
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetObject(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_BOOLEAN => // 99
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetBool(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_BYTE => // 100
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetByte(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_CHAR => // 101
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetChar(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_SHORT => // 102
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetShort(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT => // 103
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sput(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_WIDE => // 104
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputWide(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_OBJECT => // 105
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputObject(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_BOOLEAN => // 106
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputBool(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_BYTE => // 107
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputByte(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_CHAR => // 108
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputChar(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_SHORT => // 109
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputShort(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.INVOKE_VIRTUAL => // 110
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = false)
          invokeVirtual(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_SUPER => // 111
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = false)
          invokeSuper(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_DIRECT => // 112
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = false)
          invokeDirect(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_STATIC => // 113
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = true)
          invokeStatic(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_INTERFACE => // 114
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = false)
          invokeInterface(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_VIRTUAL_RANGE => // 116
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = false)
          invokeVirtual(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_SUPER_RANGE => // 117
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = false)
          invokeSuper(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_DIRECT_RANGE => // 118
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = false)
          invokeDirect(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_STATIC_RANGE => // 119
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = true)
          invokeStatic(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_INTERFACE_RANGE => // 120
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = false)
          invokeInterface(retName, methodName, argNames, signature, classTyp)
        case Opcode.NEG_INT => // 123
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          negInt(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NOT_INT => // 124
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          notInt(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NEG_LONG => // 125
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          negLong(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NOT_LONG => // 126
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          notLong(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NEG_FLOAT => // 127
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          negFloat(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.NEG_DOUBLE => // 128
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          negDouble(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_LONG => // 129
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Long(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_FLOAT => // 130
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Float(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_DOUBLE => // 131
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Double(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.LONG_TO_INT => // 132
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          long2Int(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.LONG_TO_FLOAT => // 133
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          long2Float(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.LONG_TO_DOUBLE => // 134
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          long2Double(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.FLOAT_TO_INT => // 135
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          float2Int(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.FLOAT_TO_LONG => // 136
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          float2Long(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.FLOAT_TO_DOUBLE => // 137
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          float2Double(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DOUBLE_TO_INT => // 138
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          double2Int(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DOUBLE_TO_LONG => // 139
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          double2Long(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DOUBLE_TO_FLOAT => // 140
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          double2Float(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_BYTE => // 141
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Byte(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_CHAR => // 142
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Char(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.INT_TO_SHORT => // 143
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          int2Short(i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.ADD_INT => // 144
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          addInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SUB_INT => // 145
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          subInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.MUL_INT => // 146
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          mulInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.DIV_INT => // 147
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          divInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.REM_INT => // 148
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          remInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AND_INT => // 149
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          andInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.OR_INT => // 150
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          orInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.XOR_INT => // 151
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          xorInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SHL_INT => // 152
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          shlInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SHR_INT => // 153
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          shrInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.USHR_INT => // 154
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          ushrInt(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.ADD_LONG => // 155
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          addLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SUB_LONG => // 156
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          subLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.MUL_LONG => // 157
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          mulLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.DIV_LONG => // 158
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          divLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.REM_LONG => // 159
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          remLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.AND_LONG => // 160
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          andLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.OR_LONG => // 161
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          orLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.XOR_LONG => // 162
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          xorLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SHL_LONG => // 163
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          shlLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SHR_LONG => // 164,
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          shrLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.USHR_LONG => // 165
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          ushrLong(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.ADD_FLOAT => // 166
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          addFloat(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SUB_FLOAT => // 167
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          subFloat(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.MUL_FLOAT => // 168
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          mulFloat(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.DIV_FLOAT => // 169
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          divFloat(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.REM_FLOAT => // 170
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          remFloat(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.ADD_DOUBLE => // 171
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          addDouble(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.SUB_DOUBLE => // 172
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          subDouble(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.MUL_DOUBLE => // 173
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          mulDouble(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.DIV_DOUBLE => // 174
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          divDouble(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.REM_DOUBLE => // 175
          val i23x = inst.asInstanceOf[DexBackedInstruction23x]
          remDouble(i23x.getRegisterA.toVar, i23x.getRegisterB.toVar, i23x.getRegisterC.toVar)
        case Opcode.ADD_INT_2ADDR => // 176
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          addInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SUB_INT_2ADDR => // 177
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          subInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MUL_INT_2ADDR => // 178
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          mulInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DIV_INT_2ADDR => // 179
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          divInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.REM_INT_2ADDR => // 180
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          remInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.AND_INT_2ADDR => // 181
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          andInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.OR_INT_2ADDR => // 182
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          orInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.XOR_INT_2ADDR => // 183
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          xorInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SHL_INT_2ADDR => // 184
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          shlInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SHR_INT_2ADDR => // 185
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          shrInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.USHR_INT_2ADDR => // 186
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          ushrInt(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.ADD_LONG_2ADDR => // 187
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          addLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SUB_LONG_2ADDR => // 188
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          subLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MUL_LONG_2ADDR => // 189
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          mulLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DIV_LONG_2ADDR => // 190
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          divLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.REM_LONG_2ADDR => // 191
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          remLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.AND_LONG_2ADDR => // 192
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          andLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.OR_LONG_2ADDR => // 193
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          orLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.XOR_LONG_2ADDR => // 194
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          xorLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SHL_LONG_2ADDR => // 195
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          shlLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SHR_LONG_2ADDR => // 196
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          shrLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.USHR_LONG_2ADDR => // 197
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          ushrLong(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.ADD_FLOAT_2ADDR => // 198
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          addFloat(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SUB_FLOAT_2ADDR => // 199
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          subFloat(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MUL_FLOAT_2ADDR => // 200
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          mulFloat(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DIV_FLOAT_2ADDR => // 201
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          divFloat(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.REM_FLOAT_2ADDR => // 202
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          remFloat(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.ADD_DOUBLE_2ADDR => // 203
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          addDouble(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.SUB_DOUBLE_2ADDR => // 204
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          subDouble(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.MUL_DOUBLE_2ADDR => // 205
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          mulDouble(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.DIV_DOUBLE_2ADDR => // 206=
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          divDouble(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.REM_DOUBLE_2ADDR => // 207
          val i12x = inst.asInstanceOf[DexBackedInstruction12x]
          remDouble(i12x.getRegisterA.toVar, i12x.getRegisterA.toVar, i12x.getRegisterB.toVar)
        case Opcode.ADD_INT_LIT16 => // 208
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          addLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.RSUB_INT => // 209
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          subLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.MUL_INT_LIT16 => // 210
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          mulLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.DIV_INT_LIT16 => // 211
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          divLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.REM_INT_LIT16 => // 212
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          remLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.AND_INT_LIT16 => // 213
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          andLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.OR_INT_LIT16 => // 214
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          orLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.XOR_INT_LIT16 => // 215
          val i22s = inst.asInstanceOf[DexBackedInstruction22s]
          xorLit16(i22s.getRegisterA.toVar, i22s.getRegisterB.toVar, i22s.getNarrowLiteral)
        case Opcode.ADD_INT_LIT8 => // 216
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          addLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.RSUB_INT_LIT8 => // 217
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          subLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.MUL_INT_LIT8 => // 218
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          mulLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.DIV_INT_LIT8 => // 219
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          divLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.REM_INT_LIT8 => // 220
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          remLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.AND_INT_LIT8 => // 221
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          andLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.OR_INT_LIT8 => // 222
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          orLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.XOR_INT_LIT8 => // 223
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          xorLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.SHL_INT_LIT8 => // 224
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          shlLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.SHR_INT_LIT8 => // 225
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          shrLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.USHR_INT_LIT8 => // 226
          val i22b = inst.asInstanceOf[DexBackedInstruction22b]
          ushrLit8(i22b.getRegisterA.toVar, i22b.getRegisterB.toVar, i22b.getNarrowLiteral)
        case Opcode.IGET_VOLATILE => // 227
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetVolatile(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_VOLATILE => // 228
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputVolatile(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_VOLATILE => // 229
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetVolatile(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_VOLATILE => // 230
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputVolatile(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_OBJECT_VOLATILE => // 231
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetObjectVolatile(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IGET_WIDE_VOLATILE => // 232
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          igetWideVolatile(i22c.getRegisterA.toVar, i22c.getRegisterB.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.IPUT_WIDE_VOLATILE => // 233
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputWideVolatile(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_WIDE_VOLATILE => // 234
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetWideVolatile(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_WIDE_VOLATILE => // 235
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputWideVolatile(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.THROW_VERIFICATION_ERROR => // 237
          ""
        case Opcode.EXECUTE_INLINE => // 238
          val i35mi = inst.asInstanceOf[DexBackedInstruction35mi]
          executeInline(getRegsFrom5(i35mi), i35mi.getInlineIndex)
        case Opcode.EXECUTE_INLINE_RANGE => // 239
          val i3rmi = inst.asInstanceOf[DexBackedInstruction3rmi]
          executeInlineRange(i3rmi.getStartRegister, i3rmi.getRegisterCount, i3rmi.getInlineIndex)
        case Opcode.INVOKE_DIRECT_EMPTY => // 240
          val i35c = inst.asInstanceOf[DexBackedInstruction35c]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i35c, isStatic = false)
          invokeObjectInit(retName, methodName, argNames, signature, classTyp)
        case Opcode.INVOKE_OBJECT_INIT_RANGE => // 240
          val i3rc = inst.asInstanceOf[DexBackedInstruction3rc]
          val (retName, methodName, argNames, signature, classTyp) = getInvokeElements(i3rc, isStatic = false)
          invokeObjectInit(retName, methodName, argNames, signature, classTyp)
        case Opcode.RETURN_VOID_BARRIER => // 241
          returnVoidBarrier
        case Opcode.RETURN_VOID_NO_BARRIER => // 115
          returnVoidNoBarrier
        case Opcode.IGET_QUICK => // 242
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IGET_WIDE_QUICK => // 243
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetWideQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IGET_OBJECT_QUICK => // 244
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetObjectQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IPUT_QUICK => // 245
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_WIDE_QUICK => // 246
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputWideQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_OBJECT_QUICK => // 247
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputObjectQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_BOOLEAN_QUICK => // 235
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputBoolQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_BYTE_QUICK => // 236
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputByteQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_CHAR_QUICK => // 237
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputCharQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IPUT_SHORT_QUICK => // 238
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          iputShortQuick(i22cs.getRegisterB, i22cs.getRegisterA, i22cs.getFieldOffset)
        case Opcode.IGET_BOOLEAN_QUICK => // 239
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetBoolQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IGET_BYTE_QUICK => // 240
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetByteQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IGET_CHAR_QUICK => // 241
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetCharQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.IGET_SHORT_QUICK => // 242
          val i22cs = inst.asInstanceOf[DexBackedInstruction22cs]
          igetShortQuick(i22cs.getRegisterA, i22cs.getRegisterB, i22cs.getFieldOffset)
        case Opcode.INVOKE_VIRTUAL_QUICK => // 248
          val i35ms = inst.asInstanceOf[DexBackedInstruction35ms]
          invokeVirtualQuick(getRegsFrom5(i35ms), i35ms.getVtableIndex)
        case Opcode.INVOKE_VIRTUAL_QUICK_RANGE => // 249
          val i3rms = inst.asInstanceOf[DexBackedInstruction3rms]
          invokeVirtualQuickRange(i3rms.getStartRegister, i3rms.getRegisterCount, i3rms.getVtableIndex)
        case Opcode.INVOKE_SUPER_QUICK => // 250
          val i35ms = inst.asInstanceOf[DexBackedInstruction35ms]
          invokeSuperQuick(getRegsFrom5(i35ms), i35ms.getVtableIndex)
        case Opcode.INVOKE_SUPER_QUICK_RANGE => // 251
          val i3rms = inst.asInstanceOf[DexBackedInstruction3rms]
          invokeSuperQuickRange(i3rms.getStartRegister, i3rms.getRegisterCount, i3rms.getVtableIndex)
        case Opcode.IPUT_OBJECT_VOLATILE => // 252
          val i22c = inst.asInstanceOf[DexBackedInstruction22c]
          val ref = i22c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          iputObjectVolatile(i22c.getRegisterB.toVar, fqn.fqn, i22c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SGET_OBJECT_VOLATILE => // 253
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sgetObjectVolatile(i21c.getRegisterA.toVar, fqn.fqn, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.SPUT_OBJECT_VOLATILE => // 254
          val i21c = inst.asInstanceOf[DexBackedInstruction21c]
          val ref = i21c.getReference.asInstanceOf[DexBackedFieldReference]
          val fqn = getFQNFieldReference(ref)
          sputObjectVolatile(fqn.fqn, i21c.getRegisterA.toVar, JawaModelProvider.generateType(fqn.typ, template).render())
        case Opcode.PACKED_SWITCH_PAYLOAD => // 256
          val payload = inst.asInstanceOf[DexBackedPackedSwitchPayload]
          switchMapping.get(instrBase) match {
            case Some((base, default, v)) =>
              val code: StringBuilder = new StringBuilder
              code.append("switch %s\n".format(v))
              payload.getSwitchElements.asScala.foreach { elem =>
                code.append("                | %d => goto L%06x\n".format(elem.getKey, calculateTarget(base, elem.getOffset)))
              }
              code.append("                | else => goto L%06x;".format(default))
              code.toString()
            case None => "@INVALID_PACKED_SWITCH_PAYLOAD"
          }
        case Opcode.SPARSE_SWITCH_PAYLOAD => // 512
          val payload = inst.asInstanceOf[DexBackedSparseSwitchPayload]
          switchMapping.get(instrBase) match {
            case Some((base, default, v)) =>
              val code: StringBuilder = new StringBuilder
              code.append("switch %s\n".format(v))
              payload.getSwitchElements.asScala.foreach { elem =>
                code.append("                | %d => goto L%06x\n".format(elem.getKey, calculateTarget(base, elem.getOffset)))
              }
              code.append("                | else => goto L%06x;".format(default))
              code.toString()
            case None => "@INVALID_SPARSE_SWITCH_PAYLOAD"
          }
        case Opcode.ARRAY_PAYLOAD => // 768
          val payload = inst.asInstanceOf[DexBackedArrayPayload]
          val elementWidth = payload.getElementWidth
          fillArrayMapping.get(instrBase) match {
            case Some((target, v)) =>
              val elems = if(elementWidth == 8) payload.getArrayElements.asScala.map(_.longValue() + "L") else payload.getArrayElements.asScala.map(_.intValue() + "I")
              val code: StringBuilder = new StringBuilder
              code.append("%s:= (%s) @kind object;\n".format(v, elems.mkString(", ")))
              code.append("#L%06x.  goto L%06x;".format(calculateTarget(instrBase, payload.getCodeUnits) - 1, target))
              code.toString()
            case None => "@INVALID_ARRAY_PAYLOAD"
          }
        case Opcode.INVOKE_LAMBDA => // 243
          "@UNSUPPORTED_INVOKE_LAMBDA"
        case Opcode.CAPTURE_VARIABLE => // 245
          "@UNSUPPORTED_CAPTURE_VARIABLE"
        case Opcode.CREATE_LAMBDA => // 246
          "@UNSUPPORTED_CREATE_LAMBDA"
        case Opcode.LIBERATE_VARIABLE => // 247
          "@UNSUPPORTED_LIBERATE_VARIABLE"
        case Opcode.BOX_LAMBDA => // 248
          "@UNSUPPORTED_BOX_LAMBDA"
        case Opcode.UNBOX_LAMBDA => // 249
          "@UNSUPPORTED_UNBOX_LAMBDA"
        case _ => throw JawaDedexException("Error parsing instruction: " + inst)
      }
    }
  }
}