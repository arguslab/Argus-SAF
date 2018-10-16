/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.util

import org.argus.jawa.core.util._
import java.util.regex.Pattern

import org.argus.jawa.core.elements.{JavaKnowledge, Signature}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object PScoutTranslator {
  def main(args: Array[String]): Unit = {
    val filepath = args(0)
    val fileuri = FileUtil.toUri(filepath)
    translate(fileuri)
  }
  
  def translate(uri: FileResourceUri): IMap[String, ISet[Signature]] = {
    val permissionMap: MMap[String, MSet[Signature]] = mmapEmpty
    var currentPermission: String = null
    scala.io.Source.fromFile(FileUtil.toFile(uri)).getLines().foreach {
      case permission if permission.startsWith("Permission:") =>
        currentPermission = permission.replace("Permission:", "")
      case sigstr if sigstr.startsWith("<") =>
        val sig = formatSignature(sigstr)
        permissionMap.getOrElseUpdate(currentPermission, msetEmpty) ++= sig
      case _ =>
    }
    permissionMap.map{case (k, v) => (k, v.toSet)}.toMap
  }
  //                                    1            2                     3                     4
  private val regex = "<([[^\\s]&&[^:]]+):\\s([^\\s]+)\\s([[^\\s]&&[^\\(]]+)\\(([[^\\s]&&[^\\)]]*)\\)>\\s+\\(.*\\)"
  private def formatSignature(sigstr: String): Option[Signature] = {
    val p: Pattern = Pattern.compile(regex)
    val m = p.matcher(sigstr)
    if(m.find()){
      val classTypStr = m.group(1)
      val retTypStr = m.group(2)
      val methodName = m.group(3)
      val paramTypStrList = m.group(4).split(",")
      val classTyp = JavaKnowledge.getTypeFromJawaName(classTypStr)
      val protosb = new StringBuilder
      protosb.append("(")
      paramTypStrList.foreach{
        paramTypStr =>
          if(!paramTypStr.isEmpty)
            protosb.append(JavaKnowledge.formatTypeToSignature(JavaKnowledge.getTypeFromJawaName(paramTypStr)))
      }
      protosb.append(")")
      protosb.append(JavaKnowledge.formatTypeToSignature(JavaKnowledge.getTypeFromJawaName(retTypStr)))
      Some(new Signature(classTyp, methodName, protosb.toString()))
    } else {
      System.err.println("PScoutTranslator, does not match: " + sigstr)
      None
    }
  }
}
