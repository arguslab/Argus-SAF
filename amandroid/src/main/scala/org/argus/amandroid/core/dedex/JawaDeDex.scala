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

import java.io._

import org.argus.jawa.core.util._
import org.argus.amandroid.core.decompile.DecompilerSettings
import org.argus.jawa.core.elements.{JavaKnowledge, JawaPackage, JawaType}
import org.jf.dexlib2.{DexFileFactory, Opcodes}
import org.jf.dexlib2.dexbacked.{DexBackedDexFile, DexBackedOdexFile, OatFile}
import org.jf.dexlib2.dexbacked.DexBackedDexFile.NotADexFile
import org.jf.dexlib2.dexbacked.DexBackedOdexFile.NotAnOdexFile
import org.jf.dexlib2.dexbacked.OatFile.NotAnOatFileException

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class JawaDeDex {
  private var codes: IMap[JawaType, String] = imapEmpty
  private var pkgNameMapping: IMap[JawaPackage, String] = imapEmpty
  private var recordNameMapping: IMap[JawaType, String] = imapEmpty
  private var procedureNameMapping: IMap[String, String] = imapEmpty
  private var attributeNameMapping: IMap[(String, JawaType), String] = imapEmpty
  def getCodes: IMap[JawaType, String] = codes
  def getPkgNameMapping: IMap[JawaPackage, String] = pkgNameMapping
  def getRecordNameMapping: IMap[JawaType, String] = recordNameMapping
  def getProcedureNameMapping: IMap[String, String] = procedureNameMapping
  def getAttributeNameMapping: IMap[(String, JawaType), String] = attributeNameMapping
  def haveRenamedElements: Boolean = pkgNameMapping.nonEmpty || recordNameMapping.nonEmpty || procedureNameMapping.nonEmpty || attributeNameMapping.nonEmpty
  def mapPackage(pkg: String): String = {
    val pkglist: MList[String] = mlistEmpty
    val jawapkg = JavaKnowledge.formatPackageStringToPackage(pkg)
    jawapkg.getPkgList foreach {
      pkg =>
        getPkgNameMapping.get(pkg) match {
          case Some(name) =>
            pkglist += name
          case None =>
            pkglist += pkg.name
        }
    }
    pkglist.mkString(".")
  }
  def mapRecord(className: String): String = {
    val typ = new JawaType(className)
    val pkgstr = typ.baseType.pkg match {
      case Some(pkg) => mapPackage(pkg.toPkgString("."))
      case None => ""
    }
    val classnamestr = getRecordNameMapping.get(typ) match {
      case Some(name) =>
        name
      case None =>
        typ.baseType.name
    }
    pkgstr + "." + classnamestr
  }
  
  def decompile(
      dexFileUri: FileResourceUri,
      settings: DecompilerSettings): Unit = {
    try {
      val dexFile = FileUtil.toFile(dexFileUri)
      val fileLength = dexFile.length
      if (fileLength < 40L) throw JawaDedexException(s"The ${dexFile.getName} file is too small to be a valid dex file.")
      if (fileLength > 2147483647L) throw JawaDedexException(s"The ${dexFile.getName} file is too large to read in.")
      val is = new BufferedInputStream(new FileInputStream(dexFile))
      val ddFile: DexBackedDexFile = {
        try {
          DexBackedDexFile.fromInputStream(Opcodes.forApi(settings.api), is)
        } catch {
          case _: NotADexFile =>
            try {
              DexBackedOdexFile.fromInputStream(Opcodes.forApi(settings.api), is)
            } catch {
              case _: NotAnOdexFile =>
                var oatFile: OatFile = null
                try {
                  oatFile = OatFile.fromInputStream(is)
                } catch {
                  case _: NotAnOatFileException =>
                }
                if(oatFile == null) {
                  throw JawaDedexException(s"${dexFile.getName} is not an apk, dex, odex or oat file.")
                } else if(oatFile.isSupportedVersion == 0) {
                  throw new DexFileFactory.UnsupportedOatVersionException(oatFile)
                } else {
                  oatFile.getDexFiles.get(0)
                }
            }
        }
      }
      val pscg = new JawaStyleCodeGenerator(ddFile, settings.strategy.recordFilter, settings.reporter)
      this.codes = pscg.generate(settings.listener, settings.progressBar)
      this.pkgNameMapping = pscg.pkgNameMapping.toMap
      this.recordNameMapping = pscg.recordNameMapping.toMap
      this.procedureNameMapping = pscg.procedureNameMapping.toMap
      this.attributeNameMapping = pscg.attributeNameMapping.toMap
    } catch {
      case ex: IOException =>
        System.err.println("I/O error: " + ex.getMessage)
        if(settings.debugMode)
          ex.printStackTrace()
      case ex: Exception =>
        System.err.println("Decompile error: " + ex.getMessage)
        if(settings.debugMode)
          ex.printStackTrace()
    }
  }
}

case class JawaDedexException(msg: String) extends Exception