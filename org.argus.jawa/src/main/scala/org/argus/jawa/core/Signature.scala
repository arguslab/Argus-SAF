/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.util._

object Signature extends JavaKnowledge {
  def getClassTyp(sig: String): JawaType = {
    formatSignatureToType(sig.substring(0, sig.indexOf(".")))
  }
  def getMethodName(sig: String): String = {
    sig.substring(sig.indexOf(".") + 1, sig.indexOf(":"))
  }
  def getProto(sig: String): String = {
    sig.substring(sig.indexOf(":") + 1)
  }
}

/**
 * This class providing all helper methods for signature e.g., Ljava/lang/Object;.equals:(Ljava/lang/Object;)Z
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
case class Signature(classTyp: JawaType, methodName: String, proto: String) extends JavaKnowledge {

  override def hashCode: Int = signature.hashCode

  override def equals(obj: scala.Any): Boolean = hashCode == obj.hashCode()
  
  def this(sig: String) = this(Signature.getClassTyp(sig), Signature.getMethodName(sig), Signature.getProto(sig))
  lazy val signature: String = formatTypeToSignature(classTyp) + "." + methodName + ":" + proto
  
  def FQMN: String = {
    val sb = new StringBuilder
    sb.append(getClassType.canonicalName)
    sb.append(".")
    sb.append(methodName)
    sb.append("(")
    var i = 0
    val params = getParameterTypes
    val size = params.size
    params foreach { typ =>
      sb.append(typ.canonicalName)
      if(i < size - 1)
        sb.append(",")
      i += 1
    }
    sb.append(")")
    sb.append(getReturnType.canonicalName)
    sb.toString().intern()
  }
  
  private class ParameterSignatureIterator extends Iterator[String] {
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

  def getParameters: IList[String] = {
    var count = 0
    val params: MList[String] = mlistEmpty
    val iterator = new ParameterSignatureIterator
    while(iterator.hasNext()){
      val p = iterator.next()
      params.insert(count, p)
      count+=1
    }
    params.toList
  }
  
  def getParameterTypes: IList[JawaType] = {
    val params: MList[JawaType] = mlistEmpty
    val iterator = new ParameterSignatureIterator
    while(iterator.hasNext()){
      val p = formatSignatureToType(iterator.next())
      params += p
    }
    params.toList
  }
  
  def getParameterNum: Int = {
    var count = 0
    val iterator = new ParameterSignatureIterator
    while(iterator.hasNext()){
      iterator.next()
      count+=1
    }
    count
  }
  
  def getObjectParameters: MMap[Int, JawaType] = {
    var count = 0
    val params: MMap[Int, JawaType] = mmapEmpty
    val iterator = new ParameterSignatureIterator
    while(iterator.hasNext()){
      val p = iterator.next()
      if(p.startsWith("L") || p.startsWith("[")){
        params(count) = formatSignatureToType(p)
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
