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

import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait DexConstants {
  def nop = "" // 0x00
  def move(x: String, y: String): String = "%s:= %s;".format(x, y) // 0x1, 0x2, 0x3
  def moveWide(x: String, y: String): String = "%s:= %s @kind wide;".format(x, y) // 0x4, 0x5, 0x6
  def moveObject(x: String, y: String): String = "%s:= %s @kind object;".format(x, y) // 0x7, 0x8, 0x9
  def moveResult(x: String, y: String): String = "%s:= %s;".format(x, y) // 0xa
  def moveResultWide(x: String, y: String): String = "%s:= %s @kind wide;".format(x, y) // 0xb
  def moveResultObject(x: String, y: String): String = "%s:= %s @kind object;".format(x, y) // 0xc
  def moveExc(x: String, y: String): String = "%s:= Exception @type ^%s @kind object;".format(x, y) // 0xd
  def returnVoid = "return @kind void;" // 0xe
  def `return`(x: String): String = "return %s;".format(x)  // 0xf
  def returnWide(x: String): String = "return %s @kind wide;".format(x) // 0x10
  def returnObj(x: String): String = "return %s @kind object;".format(x) // 0x11
  def const(x: String, y: String, typ: JawaType, typstr: String): String = {
    typ match {
      case pt if pt.isPrimitive =>
        pt.jawaName match {
          case "int" => "%s:= %sI;".format(x, y)
          case "long" => "%s:= %sL;".format(x, y)
          case "float" => "%s:= %sF;".format(x, y)
          case "double" => "%s:= %sD;".format(x, y)
          case _ => "%s:= %sI;".format(x, y)
        }
      case ot if ot.isObject =>
        "%s:= null @type ^%s @kind object;".format(x, typstr)
      case _ => "%s:= %sI;".format(x, y)
    }
    
  } // 0x12, 0x13, 0x14, 0x15
  def constWide(x: String, y: String, typ: JawaType): String = {
    typ match {
      case pt if pt.isPrimitive =>
        pt.jawaName match {
          case "int" => "%s:= %sI;".format(x, y)
          case "long" => "%s:= %sL;".format(x, y)
          case "float" => "%s:= %sF;".format(x, y)
          case "double" => "%s:= %sD;".format(x, y)
          case _ => "%s:= %sL;".format(x, y)
        }
      case ot if ot.isObject =>
        "%s:= null @kind object;".format(x)
      case _ => "%s:= %sL;".format(x, y)
    }
  } // 0x16, 0x17, 0x18, 0x19
  def constString(x: String, str: String): String = "%s:= \"%s\" @kind object;".format(x, str)  // 0x1a, 0x1b
  def constMString(x: String, str: String): String = "%s:= \n\"\"\"\n%s\n\"\"\" @kind object;".format(x, str)  // 0x1a, 0x1b
  def constClass(x: String, typ: String): String = "%s:= constclass @type ^%s @kind object;".format(x, typ) // 0x1c
  def monitorEnter(x: String): String = "@monitorenter %s".format(x) // 0x1d
  def monitorExit(x: String): String = "@monitorexit %s".format(x) // 0x1e
  def checkCast(x: String, typ: String, z: String): String = "%s:= (%s) %s @kind object;".format(x, typ, z) // 0x1f
  def instanceOf(x: String, y: String, typ: String): String = "%s:= instanceof @variable %s @type ^%s @kind boolean;".format(x, y, typ) // 0x20
  def arrayLen(x: String, y: String): String = "%s:= length @variable %s;".format(x, y) // 0x21
  def newIns(x: String, typ: String): String = "%s:= new %s;".format(x, typ) // 0x22
  def newArray(x: String, basetyp: String, y: String): String = "%s:= new %s[%s];".format(x, basetyp, y) // 0x23
  def filledNewArray(retName: String, baseTyp: String, regs: IList[String]) = s"$retName:= new $baseTyp[${regs.mkString(", ")}];" // 0x24
//  def filledNewArrayRange(baseTyp: String, regbase: Int, regsize: Int) = s"temp:= new $baseTyp[${(0 to regsize - 1).map(i => "v" + (regbase + i)).mkString(", ")}];" // 0x25
  def fillArrData(target: Long): String = "goto L%06x;".format(target) // 0x26
  def `throw`(x: String): String = "throw %s;".format(x) // 0x27
  def goto(target: Long): String = "goto L%06x;".format(target) // 0x28, 0x29, 0x2a
  def switch(target: Long): String = "goto L%06x;".format(target) // 0x2b, 0x2c
  def fcmpl(x: String, y: String, z: String): String = "%s:= fcmpl(%s, %s);".format(x, y, z) // 0x2d
  def fcmpg(x: String, y: String, z: String): String = "%s:= fcmpg(%s, %s);".format(x, y, z) // 0x2e
  def dcmpl(x: String, y: String, z: String): String = "%s:= dcmpl(%s, %s);".format(x, y, z) // 0x2f
  def dcmpg(x: String, y: String, z: String): String = "%s:= dcmpg(%s, %s);".format(x, y, z) // 0x30
  def lcmp(x: String, y: String, z: String): String = "%s:= lcmp(%s, %s);".format(x, y, z) // 0x31
  def ifEq(x: String, y: String, target: Long): String = "if %s == %s then goto L%06x;".format(x, y, target) // 0x32
  def ifNe(x: String, y: String, target: Long): String = "if %s != %s then goto L%06x;".format(x, y, target) // 0x33
  def ifLt(x: String, y: String, target: Long): String = "if %s < %s then goto L%06x;".format(x, y, target) // 0x34
  def ifGe(x: String, y: String, target: Long): String = "if %s >= %s then goto L%06x;".format(x, y, target) // 0x35
  def ifGt(x: String, y: String, target: Long): String = "if %s > %s then goto L%06x;".format(x, y, target) // 0x36
  def ifLe(x: String, y: String, target: Long): String = "if %s <= %s then goto L%06x;".format(x, y, target) // 0x37
  def ifEqz(x: String, target: Long, isObject: Boolean): String = {
    if(isObject) "if %s == null then goto L%06x;".format(x, target)
    else "if %s == 0 then goto L%06x;".format(x, target)
  } // 0x38
  def ifNez(x: String, target: Long, isObject: Boolean): String = {
    if(isObject) "if %s != null then goto L%06x;".format(x, target)
    else "if %s != 0 then goto L%06x;".format(x, target)
  } // 0x39
  def ifLtz(x: String, target: Long): String = "if %s < 0 then goto L%06x;".format(x, target) // 0x3a
  def ifGez(x: String, target: Long): String = "if %s >= 0 then goto L%06x;".format(x, target) // 0x3b
  def ifGtz(x: String, target: Long): String = "if %s > 0 then goto L%06x;".format(x, target) // 0x3c
  def ifLez(x: String, target: Long): String = "if %s <= 0 then goto L%06x;".format(x, target) // 0x3d
  // unused 0x3e to 0x43
  def aget(x: String, y: String, z: String): String = "%s:= %s[%s];".format(x, y, z) // 0x44
  def agetWide(x: String, y: String, z: String): String = "%s:= %s[%s] @kind wide;".format(x, y, z) // 0x45
  def agetObject(x: String, y: String, z: String): String = "%s:= %s[%s] @kind object;".format(x, y, z) // 0x46
  def agetBool(x: String, y: String, z: String): String = "%s:= %s[%s] @kind boolean;".format(x, y, z) // 0x47
  def agetByte(x: String, y: String, z: String): String = "%s:= %s[%s] @kind byte;".format(x, y, z) // 0x48
  def agetChar(x: String, y: String, z: String): String = "%s:= %s[%s] @kind char;".format(x, y, z) // 0x49
  def agetShort(x: String, y: String, z: String): String = "%s:= %s[%s] @kind short;".format(x, y, z) // 0x4a
  def aput(x: String, y: String, z: String): String = "%s[%s]:= %s;".format(x, y, z) // 0x4b
  def aputWide(x: String, y: String, z: String): String = "%s[%s]:= %s @kind wide;".format(x, y, z) // 0x4c
  def aputObject(x: String, y: String, z: String): String = "%s[%s]:= %s @kind object;".format(x, y, z) // 0x4d
  def aputBool(x: String, y: String, z: String): String = "%s[%s]:= %s @kind boolean;".format(x, y, z) // 0x4e
  def aputByte(x: String, y: String, z: String): String = "%s[%s]:= %s @kind byte;".format(x, y, z) // 0x4f
  def aputChar(x: String, y: String, z: String): String = "%s[%s]:= %s @kind char;".format(x, y, z) // 0x50
  def aputShort(x: String, y: String, z: String): String = "%s[%s]:= %s @kind short;".format(x, y, z) // 0x51
  def iget(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s;".format(x, y, field, typ) // 0x52
  def igetWide(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind wide;".format(x, y, field, typ) // 0x53
  def igetObject(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind object;".format(x, y, field, typ) // 0x54
  def igetBool(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind boolean;".format(x, y, field, typ) // 0x55
  def igetByte(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind byte;".format(x, y, field, typ) // 0x56
  def igetChar(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind char;".format(x, y, field, typ) // 0x57
  def igetShort(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind short;".format(x, y, field, typ) // 0x58
  def iput(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s;".format(x, field, typ, y) // 0x59
  def iputWide(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind wide;".format(x, field, typ, y) // 0x5a
  def iputObject(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind object;".format(x, field, typ, y) // 0x5b
  def iputBool(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind boolean;".format(x, field, typ, y) // 0x5c
  def iputByte(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind byte;".format(x, field, typ, y) // 0x5d
  def iputChar(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind char;".format(x, field, typ, y) // 0x5e
  def iputShort(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind short;".format(x, field, typ, y) // 0x5f
  def sget(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s;".format(x, field, typ) // 0x60
  def sgetWide(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind wide;".format(x, field, typ) // 0x61
  def sgetObject(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind object;".format(x, field, typ) // 0x62
  def sgetBool(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind boolean;".format(x, field, typ) // 0x63
  def sgetByte(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind byte;".format(x, field, typ) // 0x64
  def sgetChar(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind char;".format(x, field, typ) // 0x65
  def sgetShort(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind short;".format(x, field, typ) // 0x66
  def sput(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s;".format(field, typ, x) // 0x67
  def sputWide(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind wide;".format(field, typ, x) // 0x68
  def sputObject(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind object;".format(field, typ, x) // 0x69
  def sputBool(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind boolean;".format(field, typ, x) // 0x6a
  def sputByte(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind byte;".format(field, typ, x) // 0x6b
  def sputChar(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind char;".format(field, typ, x) // 0x6c
  def sputShort(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind short;".format(field, typ, x) // 0x6d
  def invokeVirtual(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind virtual;" // 0x6e
  def invokeSuper(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind super;" // 0x6f
  def invokeDirect(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind direct;" // 0x70
  def invokeStatic(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind static;" // 0x71
  def invokeInterface(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind interface;" // 0x72
  def returnVoidNoBarrier = "return @kind void;" // 0x73
//  def invokeVirtualRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind virtual;" // 0x74
//  def invokeSuperRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind super;" // 0x75
//  def invokeDirectRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind direct;" // 0x76
//  def invokeStaticRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind static;" // 0x77
//  def invokeInterfaceRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind interface;" // 0x78
  // unused 0x79 0x7a
  def negInt(x: String, y: String): String = "%s:= -%s @kind int;".format(x, y) // 0x7b
  def notInt(x: String, y: String): String = "%s:= ~%s @kind int;".format(x, y) // 0x7c
  def negLong(x: String, y: String): String = "%s:= -%s @kind long;".format(x, y) // 0x7d
  def notLong(x: String, y: String): String = "%s:= ~%s @kind long;".format(x, y) // 0x7e
  def negFloat(x: String, y: String): String = "%s:= -%s @kind float;".format(x, y) // 0x7f
  def negDouble(x: String, y: String): String = "%s:= -%s @kind double;".format(x, y) // 0x80
  def int2Long(x: String, y: String): String = "%s:= (`long`) %s @kind i2l;".format(x, y) // 0x81
  def int2Float(x: String, y: String): String = "%s:= (`float`) %s @kind i2f;".format(x, y) // 0x82
  def int2Double(x: String, y: String): String = "%s:= (`double`) %s @kind i2d;".format(x, y) // 0x83
  def long2Int(x: String, y: String): String = "%s:= (`int`) %s @kind l2i;".format(x, y) // 0x84
  def long2Float(x: String, y: String): String = "%s:= (`float`) %s @kind l2f;".format(x, y) // 0x85
  def long2Double(x: String, y: String): String = "%s:= (`double`) %s @kind l2d;".format(x, y) // 0x86
  def float2Int(x: String, y: String): String = "%s:= (`int`) %s @kind f2i;".format(x, y) // 0x87
  def float2Long(x: String, y: String): String = "%s:= (`long`) %s @kind f2l;".format(x, y) // 0x88
  def float2Double(x: String, y: String): String = "%s:= (`double`) %s @kind f2d;".format(x, y) // 0x89
  def double2Int(x: String, y: String): String = "%s:= (`int`) %s @kind d2i;".format(x, y) // 0x8a
  def double2Long(x: String, y: String): String = "%s:= (`long`) %s @kind d2l;".format(x, y) // 0x8b
  def double2Float(x: String, y: String): String = "%s:= (`float`) %s @kind d2f;".format(x, y) // 0x8c
  def int2Byte(x: String, y: String): String = "%s:= (`byte`) %s @kind i2b;".format(x, y) // 0x8d
  def int2Char(x: String, y: String): String = "%s:= (`char`) %s @kind i2c;".format(x, y) // 0x8e
  def int2Short(x: String, y: String): String = "%s:= (`short`) %s @kind i2s;".format(x, y) // 0x8f
  def addInt(x: String, y: String, z: String): String = "%s:= %s + %s @kind int;".format(x, y, z) // 0x90
  def subInt(x: String, y: String, z: String): String = "%s:= %s - %s @kind int;".format(x, y, z) // 0x91
  def mulInt(x: String, y: String, z: String): String = "%s:= %s * %s @kind int;".format(x, y, z) // 0x92
  def divInt(x: String, y: String, z: String): String = "%s:= %s / %s @kind int;".format(x, y, z) // 0x93
  def remInt(x: String, y: String, z: String): String = "%s:= %s %%%% %s @kind int;".format(x, y, z) // 0x94
  def andInt(x: String, y: String, z: String): String = "%s:= %s ^& %s @kind int;".format(x, y, z) // 0x95
  def orInt(x: String, y: String, z: String): String = "%s:= %s ^| %s @kind int;".format(x, y, z) // 0x96
  def xorInt(x: String, y: String, z: String): String = "%s:= %s ^~ %s @kind int;".format(x, y, z) // 0x97
  def shlInt(x: String, y: String, z: String): String = "%s:= %s ^< %s @kind int;".format(x, y, z) // 0x98
  def shrInt(x: String, y: String, z: String): String = "%s:= %s ^> %s @kind int;".format(x, y, z) // 0x99
  def ushrInt(x: String, y: String, z: String): String = "%s:= %s ^>> %s @kind int;".format(x, y, z) // 0x9a
  def addLong(x: String, y: String, z: String): String = "%s:= %s + %s @kind long;".format(x, y, z) // 0x9b
  def subLong(x: String, y: String, z: String): String = "%s:= %s - %s @kind long;".format(x, y, z) // 0x9c
  def mulLong(x: String, y: String, z: String): String = "%s:= %s * %s @kind long;".format(x, y, z) // 0x9d
  def divLong(x: String, y: String, z: String): String = "%s:= %s / %s @kind long;".format(x, y, z) // 0x9e
  def remLong(x: String, y: String, z: String): String = "%s:= %s %%%% %s @kind long;".format(x, y, z) // 0x9f
  def andLong(x: String, y: String, z: String): String = "%s:= %s ^& %s @kind long;".format(x, y, z) // 0xa0
  def orLong(x: String, y: String, z: String): String = "%s:= %s ^| %s @kind long;".format(x, y, z) // 0xa1
  def xorLong(x: String, y: String, z: String): String = "%s:= %s ^~ %s @kind long;".format(x, y, z) // 0xa2
  def shlLong(x: String, y: String, z: String): String = "%s:= %s ^< %s @kind long;".format(x, y, z) // 0xa3
  def shrLong(x: String, y: String, z: String): String = "%s:= %s ^> %s @kind long;".format(x, y, z) // 0xa4
  def ushrLong(x: String, y: String, z: String): String = "%s:= %s ^>> %s @kind long;".format(x, y, z) // 0xa5
  def addFloat(x: String, y: String, z: String): String = "%s:= %s + %s @kind float;".format(x, y, z) // 0xa6
  def subFloat(x: String, y: String, z: String): String = "%s:= %s - %s @kind float;".format(x, y, z) // 0xa7
  def mulFloat(x: String, y: String, z: String): String = "%s:= %s * %s @kind float;".format(x, y, z) // 0xa8
  def divFloat(x: String, y: String, z: String): String = "%s:= %s / %s @kind float;".format(x, y, z) // 0xa9
  def remFloat(x: String, y: String, z: String): String = "%s:= %s %%%% %s @kind float;".format(x, y, z) // 0xaa
  def addDouble(x: String, y: String, z: String): String = "%s:= %s + %s @kind double;".format(x, y, z) // 0xab
  def subDouble(x: String, y: String, z: String): String = "%s:= %s - %s @kind double;".format(x, y, z) // 0xac
  def mulDouble(x: String, y: String, z: String): String = "%s:= %s * %s @kind double;".format(x, y, z) // 0xad
  def divDouble(x: String, y: String, z: String): String = "%s:= %s / %s @kind double;".format(x, y, z) // 0xae
  def remDouble(x: String, y: String, z: String): String = "%s:= %s %%%% %s @kind double;".format(x, y, z) // 0xaf
//  def addInt2addr(x: String, y: String) = "%s:= %s + %s @kind int;".format(x, x, y) // 0xb0
//  def subInt2addr(x: String, y: String) = "%s:= %s - %s @kind int;".format(x, x, y) // 0xb1
//  def mulInt2addr(x: String, y: String) = "%s:= %s * %s @kind int;".format(x, x, y) // 0xb2
//  def divInt2addr(x: String, y: String) = "%s:= %s / %s @kind int;".format(x, x, y) // 0xb3
//  def remInt2addr(x: String, y: String) = "%s:= %s %%%% %s @kind int;".format(x, x, y) // 0xb4
//  def andInt2addr(x: String, y: String) = "%s:= %s ^& %s @kind int;".format(x, x, y) // 0xb5
//  def orInt2addr(x: String, y: String)  = "%s:= %s ^| %s @kind int;".format(x, x, y) // 0xb6
//  def xorInt2addr(x: String, y: String) = "%s:= %s ^~ %s @kind int;".format(x, x, y) // 0xb7
//  def shlInt2addr(x: String, y: String) = "%s:= %s ^< %s @kind int;".format(x, x, y) // 0xb8
//  def shrInt2addr(x: String, y: String) = "%s:= %s ^> %s @kind int;".format(x, x, y) // 0xb9
//  def ushrInt2addr(x: String, y: String) = "%s:= %s ^>> %s @kind int;".format(x, x, y) // 0xba
//  def addLong2addr(x: String, y: String) = "%s:= %s + %s @kind long;".format(x, x, y) // 0xbb
//  def subLong2addr(x: String, y: String) = "%s:= %s - %s @kind long;".format(x, x, y) // 0xbc
//  def mulLong2addr(x: String, y: String) = "%s:= %s * %s @kind long;".format(x, x, y) // 0xbd
//  def divLong2addr(x: String, y: String) = "%s:= %s / %s @kind long;".format(x, x, y) // 0xbe
//  def remLong2addr(x: String, y: String) = "%s:= %s %%%% %s @kind long;".format(x, x, y) // 0xbf
//  def andLong2addr(x: String, y: String) = "%s:= %s ^& %s @kind long;".format(x, x, y) // 0xc0
//  def orLong2addr(x: String, y: String) = "%s:= %s ^| %s @kind long;".format(x, x, y) // 0xc1
//  def xorLong2addr(x: String, y: String) = "%s:= %s ^~ %s @kind long;".format(x, x, y) // 0xc2
//  def shlLong2addr(x: String, y: String) = "%s:= %s ^< %s @kind long;".format(x, x, y) // 0xc3
//  def shrLong2addr(x: String, y: String) = "%s:= %s ^> %s @kind long;".format(x, x, y) // 0xc4
//  def ushrLong2addr(x: String, y: String) = "%s:= %s ^>> %s @kind long;".format(x, x, y) // 0xc5
//  def addFloat2addr(x: String, y: String) = "%s:= %s + %s @kind float;".format(x, x, y) // 0xc6
//  def subFloat2addr(x: String, y: String) = "%s:= %s - %s @kind float;".format(x, x, y) // 0xc7
//  def mulFloat2addr(x: String, y: String) = "%s:= %s * %s @kind float;".format(x, x, y) // 0xc8
//  def divFloat2addr(x: String, y: String) = "%s:= %s / %s @kind float;".format(x, x, y) // 0xc9
//  def remFloat2addr(x: String, y: String) = "%s:= %s %%%% %s @kind float;".format(x, x, y) // 0xca
//  def addDouble2addr(x: String, y: String) = "%s:= %s + %s @kind double;".format(x, x, y) // 0xcb
//  def subDouble2addr(x: String, y: String) = "%s:= %s - %s @kind double;".format(x, x, y) // 0xcc
//  def mulDouble2addr(x: String, y: String) = "%s:= %s * %s @kind double;".format(x, x, y) // 0xcd
//  def divDouble2addr(x: String, y: String) = "%s:= %s / %s @kind double;".format(x, x, y) // 0xce
//  def remDouble2addr(x: String, y: String) = "%s:= %s %%%% %s @kind double;".format(x, x, y) // 0xcf
  def addLit16(x: String, y: String, z: Int): String = "%s:= %s + %d;".format(x, y, z) // 0xd0
  def subLit16(x: String, y: String, z: Int): String = "%s:= %s - %d;".format(x, y, z) // 0xd1
  def mulLit16(x: String, y: String, z: Int): String = "%s:= %s * %d;".format(x, y, z) // 0xd2
  def divLit16(x: String, y: String, z: Int): String = "%s:= %s / %d;".format(x, y, z) // 0xd3
  def remLit16(x: String, y: String, z: Int): String = "%s:= %s %%%% %d;".format(x, y, z) // 0xd4
  def andLit16(x: String, y: String, z: Int): String = "%s:= %s ^& %d;".format(x, y, z) // 0xd5
  def orLit16(x: String, y: String, z: Int): String = "%s:= %s ^| %d;".format(x, y, z) // 0xd6
  def xorLit16(x: String, y: String, z: Int): String = "%s:= %s ^~ %d;".format(x, y, z) // 0xd7
  def addLit8(x: String, y: String, z: Int): String = "%s:= %s + %d;".format(x, y, z) // 0xd8
  def subLit8(x: String, y: String, z: Int): String = "%s:= %s - %d;".format(x, y, z) // 0xd9
  def mulLit8(x: String, y: String, z: Int): String = "%s:= %s * %d;".format(x, y, z) // 0xda
  def divLit8(x: String, y: String, z: Int): String = "%s:= %s / %d;".format(x, y, z) // 0xdb
  def remLit8(x: String, y: String, z: Int): String = "%s:= %s %%%% %d;".format(x, y, z) // 0xdc
  def andLit8(x: String, y: String, z: Int): String = "%s:= %s ^& %d;".format(x, y, z) // 0xdd
  def orLit8(x: String, y: String, z: Int): String = "%s:= %s ^| %d;".format(x, y, z) // 0xde
  def xorLit8(x: String, y: String, z: Int): String = "%s:= %s ^~ %d;".format(x, y, z) // 0xdf
  def shlLit8(x: String, y: String, z: Int): String = "%s:= %s ^< %d;".format(x, y, z) // 0xe0
  def shrLit8(x: String, y: String, z: Int): String = "%s:= %s ^> %d;".format(x, y, z) // 0xe1
  def ushrLit8(x: String, y: String, z: Int): String = "%s:= %s ^>> %d;".format(x, y, z) // 0xe2
  def igetVolatile(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s;".format(x, y, field, typ) // 0xe3
  def iputVolatile(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s;".format(x, field, typ, y) // 0xe4
  def sgetVolatile(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s;".format(x, field, typ) // 0xe5
  def sputVolatile(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s;".format(field, typ, x) // 0xe6
  def igetObjectVolatile(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind object;".format(x, y, field, typ) // 0xe7
  def igetWideVolatile(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind wide;".format(x, y, field, typ) // 0xe8
  def iputWideVolatile(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind wide ;".format(x, field, typ, y) // 0xe9
  def sgetWideVolatile(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind wide;".format(x, field, typ) // 0xea
  def sputWideVolatile(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind wide;".format(field, typ, x) // 0xeb
  // unused 0xec 0xed
  def executeInline(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xee
    s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind static;"
  def executeInline(args: IList[Int], inlineOffset: Int) = s"@invoke execute_inline ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @inline_offset ${"0x%x".format(inlineOffset)}" // 0xee
//  def executeInlineRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xef
//    s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind direct;"
  def executeInlineRange(argbase: Int, argsize: Int, inlineOffset: Int) = s"@invoke execute_inline_range @args ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @inline_offset ${"0x%x".format(inlineOffset)}" // 0xef
  def invokeObjectInit(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind direct;" // 0xf0
  def returnVoidBarrier = "return @kind void;" // 0xf1
  def igetQuick(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s;".format(x, y, field, typ) // 0xf2
  def igetQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf2
  def igetWideQuick(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind wide;".format(x, y, field, typ) // 0xf3
  def igetWideQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_wide_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf3
  def igetObjectQuick(x: String, y: String, field: String, typ: String): String = "%s:= %s.`%s` @type ^%s @kind object;".format(x, y, field, typ) // 0xf4
  def igetObjectQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_object_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf4
  def igetBoolQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_boolean_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def igetByteQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_byte_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def igetCharQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_char_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def igetShortQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldAccess iget_short_quick @lhsreg v%d @basereg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def iputQuick(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s;".format(x, field, typ, y) // 0xf5
  def iputQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf5
  def iputWideQuick(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind wide;".format(x, field, typ, y) // 0xf6
  def iputWideQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_wide_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf6
  def iputObjectQuick(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind object;".format(x, field, typ, y) // 0xf7
  def iputObjectQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_object_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset) // 0xf7
  def iputBoolQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_boolean_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def iputByteQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_byte_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def iputCharQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_char_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def iputShortQuick(x: Int, y: Int, vtableOffset: Int): String = "@fieldStore iput_short_quick @basereg v%d @rhsreg v%d @vtable_offset 0x%x".format(x, y, vtableOffset)
  def invokeVirtualQuick(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xf8
    s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind virtual;"
  def invokeVirtualQuick(args: IList[Int], vtableOffset: Int) = s"@invoke virtual_quick ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xf8
//  def invokeVirtualQuickRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xf9
//    s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind virtual;"
  def invokeVirtualQuickRange(argbase: Int, argsize: Int, vtableOffset: Int) = s"@invoke virtual_quick_range ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xf9
  def invokeSuperQuick(retName: Option[String], methodName: String, args: IList[String], sig: Signature, classTyp: String) = // 0xfa
    s"call ${if(retName.isDefined) retName.get + ":= " else ""}`$methodName`(${args.mkString(", ")}) @signature `$sig` @kind super;"
  def invokeSuperQuick(args: IList[Int], vtableOffset: Int) = s"@invoke super_quick ${args.map(arg => s"@arg${args.indexOf(arg)} v$arg").mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xfa
//  def invokeSuperQuickRange(className: String, methodName: String, argbase: Int, argsize: Int, sig: Signature, classTyp: String) = // 0xfb
//    s"call temp:= `$methodName`(${(0 to argsize - 1).map(i => "v" + (argbase + i)).mkString(", ")}) @signature `$sig` @kind super;"
  def invokeSuperQuickRange(argbase: Int, argsize: Int, vtableOffset: Int) = s"@invoke super_quick_range ${(0 until argsize).map(i => "@arg" + i + " v" + (argbase + i)).mkString(" ")} @vtable_offset ${"0x%x".format(vtableOffset)}" // 0xfb
  def iputObjectVolatile(x: String, field: String, y: String, typ: String): String = "%s.`%s` @type ^%s := %s @kind object;".format(x, field, typ, y) // 0xfc
  def sgetObjectVolatile(x: String, field: String, typ: String): String = "%s:= `@@%s` @type ^%s @kind object;".format(x, field, typ) // 0xfd
  def sputObjectVolatile(field: String, x: String, typ: String): String = "`@@%s` @type ^%s := %s @kind object;".format(field, typ, x) // 0xfe
  //unused 0xff
}
