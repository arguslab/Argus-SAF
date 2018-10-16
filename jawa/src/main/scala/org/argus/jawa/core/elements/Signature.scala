/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.elements

import org.argus.jawa.core.java_signatures.MethodProto.ReturnType.{ReturnJavaType, ReturnVoidType}
import org.argus.jawa.core.java_signatures.{JavaType, MethodProto, MethodSignature, VoidType}
import org.argus.jawa.core.util._

object Signature extends JavaKnowledge {
  def isValidSignature(sig: String): Boolean = {
    val dot = sig.indexOf('.')
    val colon = sig.indexOf(':')
    dot > 0 && colon > dot
  }
  def getClassTyp(sig: String): JawaType = {
    formatSignatureToType(sig.substring(0, sig.indexOf(".")))
  }
  def getMethodName(sig: String): String = {
    sig.substring(sig.indexOf(".") + 1, sig.indexOf(":"))
  }
  private class ParameterSignatureIterator(proto: String) extends Iterator[String] {
    private var index = 1

    def hasNext(): Boolean = {
      index < proto.length() && proto.charAt(index) != ')'
    }

    def next(): String = {
      if (!hasNext())
        throw new NoSuchElementException()
      val result = new StringBuilder()
      var done: Boolean = false
      do {
        done = true
        val ch = proto.charAt(index)
        ch match {
          case 'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' =>
            result.append(proto.charAt(index))
            index += 1
          case 'L' =>
            val semi = proto.indexOf(';', index + 1)
            if (semi < 0)
              throw new IllegalStateException("Invalid method paramSig: " + proto)
            result.append(proto.substring(index, semi + 1))
            index = semi + 1
          case '[' =>
            result.append('[')
            index += 1
            done = false
          case _ =>
            throw new IllegalStateException("Invalid method paramSig: " + proto)
        }
      } while (!done)

      result.toString()
    }

    def remove(): Nothing = {
      throw new UnsupportedOperationException()
    }
  }

  def getProtoFromProto(proto: String): MethodProto = {
    val params: MList[JavaType] = mlistEmpty
    val iterator = new ParameterSignatureIterator(proto)
    while(iterator.hasNext()){
      val p = formatSignatureToType(iterator.next())
      params += p.javaType
    }
    val endOfParams = proto.lastIndexOf(')')
    if (endOfParams < 0)
      throw new IllegalArgumentException("Bad method signature: " + proto)
    val returnSig = proto.substring(endOfParams + 1)
    val typ = formatSignatureToType(returnSig)
    val returnType = if(typ.name == "void") {
      ReturnVoidType(value = VoidType())
    } else {
      ReturnJavaType(value = typ.javaType)
    }
    MethodProto(paramTypes = params, returnType = returnType)
  }

  def getProtoFromSig(sig: String): MethodProto = {
    val proto = sig.substring(sig.indexOf(":") + 1)
    getProtoFromProto(proto)
  }

  def methodProtoToString(proto: MethodProto): String = {
    val paramstr = proto.paramTypes.map(typ => JavaKnowledge.formatTypeToSignature(JawaType(typ))).mkString("")
    val returnstr = proto.returnType match {
      case ReturnJavaType(jt) =>
        JavaKnowledge.formatTypeToSignature(JawaType(jt))
      case _ => "V"
    }
    s"($paramstr)$returnstr"
  }
}

/**
 * This class providing all helper methods for signature e.g., Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class Signature(method_signature: MethodSignature) extends JavaKnowledge {
  def this(classTyp: JawaType, methodName: String, methodProto: MethodProto) =
    this(MethodSignature(owner = Some(classTyp.javaType), name = methodName, proto = Some(methodProto)))
  def this(classTyp: JawaType, methodName: String, proto: String) =
    this(classTyp, methodName, Signature.getProtoFromProto(proto))
  def this(sig: String) = this(Signature.getClassTyp(sig), Signature.getMethodName(sig), Signature.getProtoFromSig(sig))
  lazy val signature: String = s"${formatTypeToSignature(classTyp)}.$methodName:${Signature.methodProtoToString(proto)}"

  val classTyp: JawaType = JawaType(method_signature.getOwner)
  val methodName: String = method_signature.name
  val proto: MethodProto = method_signature.getProto

  override def hashCode: Int = signature.hashCode

  override def equals(obj: scala.Any): Boolean = hashCode == obj.hashCode()
  
  /**
   * Get the method return type signature.
   * 
   * @return the method return type signature
   */
  def getReturnTypeSignature: String = {
    val endOfParams = signature.lastIndexOf(')')
    if (endOfParams < 0)
      throw new IllegalArgumentException("Bad method signature: " + signature)
    signature.substring(endOfParams + 1)
  }
  
  /**
   * Get the method return type. 
   * 
   * @return the method return type signature
   */
  def getReturnType: JawaType = formatSignatureToType(getReturnTypeSignature)
  
  /**
   * Get the method return type. 
   * 
   * @return the method return type signature
   */
  def getReturnObjectType: Option[JawaType] = {
    if(isReturnObject) {
      val retPart = getReturnTypeSignature
      Some(formatSignatureToType(retPart))
    } else None
  }
  
  def isReturnObject: Boolean = {
    val ret = getReturnTypeSignature
    ret.startsWith("L") || isReturnArray
  }
  
  def isReturnArray: Boolean = {
    val ret = getReturnTypeSignature
    ret.startsWith("[")
  }
  
  def getReturnArrayDimension: Int = {
    val ret = getReturnTypeSignature
    if(ret.startsWith("["))
    ret.lastIndexOf('[') - ret.indexOf('[') + 1
    else 0
  }
  
  def getParameterTypes: IList[JawaType] = {
    proto.paramTypes.map(JawaType(_)).toList
  }
  
  def getParameterNum: Int = {
    proto.paramTypes.size
  }
  
  def getObjectParameters: MMap[Int, JawaType] = {
    var count = 0
    val params: MMap[Int, JawaType] = mmapEmpty
    getParameterTypes.foreach { typ =>
      if(typ.isObject) {
        params(count) = typ
      }
      count+=1
    }
    params
  }
  
  /**
   * get class name from method signature. e.g. Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z -> java.lang.Object
   */
  def getClassName: String = getClassType.name
  
  /**
   * get class type from method signature. e.g. Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z -> (java.lang.Object, 0)
   */
  def getClassType: JawaType = {
    classTyp
  }
  
  def getDescriptor: String = {
    this.signature.substring(this.signature.indexOf(":") + 1)
  }
  
  def getSubSignature: String = {
    this.signature.substring(this.signature.indexOf(".") + 1)
  }
  
  override def toString: String = this.signature
}
