/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jnsaf.analysis

import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.parser.ComponentInfo
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType, Signature}
import org.argus.jawa.core.util._
import org.argus.jnsaf.client.NativeDroidClient

object NativeMethodHandler {
  def getJNIFunctionName(global: Global, sig: Signature): String = {
    val clazz = global.getClassOrResolve(sig.classTyp)
    val overload = clazz.getMethodsByName(sig.methodName).size > 1
    getJNIFunctionName(sig, overload)
  }

  def getJNIFunctionName(sig: Signature, overload: Boolean): String = {
    val classNamePart = sig.classTyp.jawaName.replaceAll("_", "_1").replace('.', '_')
    val methodNamePart = sig.methodName.replaceAll("_", "_1")
    if (overload) {
      val paramPart = sig.getParameterTypes.map { typ =>
        val param = JavaKnowledge.formatTypeToSignature(typ).replaceAll("_", "_1").replaceAll("/", "_").replaceAll(";", "_2").replaceAll("\\[", "_3")
        val sb = new StringBuilder
        param.foreach { ch =>
          if (ch >= 128) { // unicode
            sb.append(s"_0${Integer.toHexString(ch)}")
          } else {
            sb.append(ch)
          }
        }
        sb.toString
      }.mkString("")
      s"Java_${classNamePart}_${methodNamePart}__$paramPart"
    } else {
      s"Java_${classNamePart}_$methodNamePart"
    }
  }
}

/**
  * Created by fgwei on 4/27/17.
  */
class NativeMethodHandler(client: NativeDroidClient) {

  import NativeMethodHandler._

  final val LOAD_LIBRARY: Signature = new Signature("Ljava/lang/System;.loadLibrary:(Ljava/lang/String;)V")

  /**
    * If there are no so file found, assume any so file could be the candidate
    */
  val nativeMethodSoMap: MMap[Signature, (FileResourceUri, Either[String, Long])] = mmapEmpty

  val dynamicRegisterMap: MMap[String, (FileResourceUri, Long)] = mmapEmpty

  /**
    * Don't do this for large apps as it will try to resolve all the class.
    *
    * @param apk ApkGlobal
    */
  def buildNativeMethodMapping(apk: ApkGlobal): Unit = {
    val haveNativeClasses = apk.getApplicationClassCodes.filter{ case (_, sf) => sf.code.contains("NATIVE")}.keySet
    val progressBar = ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain")
    ProgressBarUtil.withProgressBar("Build native method to so file mapping...", progressBar)(haveNativeClasses, resolveNativeToSoMap(apk))
  }

  private def resolveNativeToSoMap(apk: ApkGlobal): JawaType => Unit = { typ =>
    val clazz = apk.getClassOrResolve(typ)
    if (clazz.isApplicationClass) {
      val nm = clazz.getDeclaredMethods.filter(_.isNative)
      if (nm.nonEmpty) {
        val soNames = resolveLoadLibrary(apk, typ)
        val soUris: MSet[FileResourceUri] = msetEmpty
        soNames.foreach { so =>
          client.getSoFileUri(apk.model.layout.outputSrcUri, so) match {
            case Some(soUri) =>
              client.getDynamicRegisterMap(soUri).foreach { case (name, addr) =>
                dynamicRegisterMap(name) = (soUri, addr)
              }
              soUris += soUri
            case None =>
          }
        }
        nm.foreach { n =>
          dynamicRegisterMap.get(n.getSubSignature) match {
            case Some((soUri, addr)) =>
              nativeMethodSoMap(n.getSignature) = (soUri, Right(addr))
            case None =>
              val jniFuncName = getJNIFunctionName(apk, n.getSignature)
              soUris.foreach { soUri =>
                if(client.hasSymbol(soUri, jniFuncName)) {
                  nativeMethodSoMap(n.getSignature) = (soUri, Left(jniFuncName))
                }
              }
          }
        }
      }
    }
  }

  private def resolveLoadLibrary(global: Global, typ: JawaType): ISet[String] = {
    val res: MSet[String] = msetEmpty
    val clazz = global.getClassOrResolve(typ)
    clazz.getDeclaredMethods.foreach { method =>
      if (clazz.isApplicationClass && method.isConcrete) {
        method.getBody.resolvedBody.locations foreach { l =>
          l.statement match {
            case cs: CallStatement =>
              if (cs.signature == LOAD_LIBRARY) {
                res ++= ExplicitValueFinder.findExplicitLiteralForArgs(method, l, cs.arg(0)).filter(_.isString).map(lit => s"lib${lit.getString}.so")
              }
            case _ =>
          }
        }
      }
    }
    res.toSet
  }

  def genSummary(apk: ApkGlobal, component: JawaType, sig: Signature, depth: Int): (String, String) = {
    val soUriOpt: Option[(FileResourceUri, Either[String, Long])] = nativeMethodSoMap.get(sig) match {
      case a@Some(_) => a
      case None =>
        resolveNativeToSoMap(apk)(sig.getClassType)
        nativeMethodSoMap.get(sig)
    }
    soUriOpt match {
      case Some((soFileUri, name_or_addr)) =>
        client.genSummary(soFileUri, component.jawaName, name_or_addr, sig, depth)
      case None =>
        ("", s"`${sig.signature}`:;")
    }
  }

  def analyseNativeActivity(apk: ApkGlobal, native_ac: ComponentInfo): Long = {
    val soNames: ISet[String] = native_ac.meta_datas.get("android.app.lib_name") match {
      case Some(libname) =>
        Set(s"lib$libname.so")
      case None =>
        resolveLoadLibrary(apk, native_ac.compType)
    }
    var soUris: IList[FileResourceUri] = soNames.flatMap { soName =>
      client.getSoFileUri(apk.model.layout.outputSrcUri, soName)
    }.toList
    if(soUris.isEmpty) {
      soUris = client.getAllSoFilePath(apk.model.layout.outputSrcUri)
    }
    val customEntry: Option[String] = native_ac.meta_datas.get("android.app.func_name")
    soUris.foreach { soUri =>
      if(client.hasNativeActivity(soUri, customEntry)) {
        return client.analyseNativeActivity(soUri, native_ac.compType.jawaName, customEntry)
      }
    }
    -1
  }

  def statisticsResolve(apk: ApkGlobal, i: Int): Unit = {
    val apkName = apk.projectName
    val nativeInfoMap: MMap[String, MMap[String, MMap[String, (String, String, IList[String])]]] = mmapEmpty
//    val soFiles = nativeInfoMap.getOrElseUpdate(apkName, mmapEmpty)
//    nativeMethodSoMap.foreach { case (sig, soName) =>
//      client.getSoFilePath(apk.model.layout.outputSrcUri, soName) match {
//        case Some(soPath) =>
//          val jniFuncName = getJNIFunctionName(apk, sig)
//          println(soPath + " " + jniFuncName + " " + sig + " " + DataCommunicator.serializeParameters(sig))
//          val funcs = soFiles.getOrElseUpdate(soPath, mmapEmpty)
//          funcs(jniFuncName) = (jniFuncName, jniSig, sig.getParameterTypes.map(_.jawaName))
//        case None =>
//      }
//    }
    if (nativeInfoMap(apkName).nonEmpty) {
//      DataCommunicator.serializeStatisticDatas(apk.model.layout.outputUri, i, nativeInfoMap)
    }
  }
}
