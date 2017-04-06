/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import java.io.RandomAccessFile

import org.sireum.util._
import java.io.PrintStream

import hu.uw.pallergabor.dedexer._
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeoutException

import org.argus.jawa.core.util.FutureUtil
import org.argus.jawa.core.{JavaKnowledge, JawaPackage, JawaType}

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.{global => sc}
import scala.language.postfixOps

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * 
 * adapted from Dedexer hu.uw.pallergabor.dedexer.Dedexer
 */
class PilarDeDex {
  
  private var dexLogStream: Option[PrintStream] = None
  private val depFiles: MList[DexDependencyFile] = mlistEmpty
  
  private var pkgNameMapping: IMap[JawaPackage, String] = imapEmpty
  private var recordNameMapping: IMap[JawaType, String] = imapEmpty
  private var procedureNameMapping: IMap[String, String] = imapEmpty
  private var attributeNameMapping: IMap[(String, JawaType), String] = imapEmpty
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
      sourceFileUri: FileResourceUri,
      targetDirUri: Option[FileResourceUri],
      depsDirUri: Option[FileResourceUri],
      recordFilter: (JawaType => Boolean),
      dexlog: Boolean,
      debugMode: Boolean,
      listener: Option[PilarStyleCodeGeneratorListener] = None,
      genBody: Boolean): Unit = {
    val raf = new RandomAccessFile(FileUtil.toFilePath(sourceFileUri), "r")
    if(dexlog){
      if(targetDirUri.isDefined) {
        dexLogStream = Some(new PrintStream(FileUtil.toFilePath(targetDirUri.get) + File.separator + "dex.log"))
      } else {
        System.err.println("If want dexlog please specify the target dir.")
        return
      }
    }
    val (f, cancel) = FutureUtil.interruptableFuture[PilarStyleCodeGenerator] { () =>
        prepare(raf, sourceFileUri, targetDirUri, depsDirUri, recordFilter, dexlog, debugMode)
    }
    try {
      val pscg = Await.result(f, 20 seconds)
      pscg.generate(listener, genBody)
      raf.close()
      this.pkgNameMapping = pscg.pkgNameMapping.toMap
      this.recordNameMapping = pscg.recordNameMapping.toMap
      this.procedureNameMapping = pscg.procedureNameMapping.toMap
      this.attributeNameMapping = pscg.attributeNameMapping.toMap
    } catch {
      case ex: IOException =>
        System.err.println("I/O error: " + ex.getMessage)
        if(debugMode)
          ex.printStackTrace()
      case ex: UnknownInstructionException =>
        System.err.println(ex.getMessage)
      case _: TimeoutException =>
        System.err.println("Dedex time out.")
        cancel()
      case ex: Exception =>
        if(debugMode)
          ex.printStackTrace()
    }
    close()
  }

  private def prepare(
      raf: RandomAccessFile,
      sourceFileUri: FileResourceUri,
      targetDirUri: Option[FileResourceUri],
      depsDirUri: Option[FileResourceUri],
      recordFilter: (JawaType => Boolean),
      dexlog: Boolean,
      debugMode: Boolean): PilarStyleCodeGenerator = {
    val dexSignatureBlock = new DexSignatureBlock()
    dexSignatureBlock.setRandomAccessFile(raf)
    dexSignatureBlock.setDumpFile(dexLogStream.orNull)
    dexSignatureBlock.parse()

    var depsParser: DexDependencyParser = null
    val dexOffsetResolver: DexOffsetResolver = new DexOffsetResolver()
    if(depsDirUri.isDefined &&
      dexSignatureBlock.getDexOptimizationData != null &&
      dexSignatureBlock.getDexOptimizationData.isOptimized) {
      depsParser = new DexDependencyParser()
      depsParser.setDexSignatureBlock(dexSignatureBlock)
      depsParser.setRandomAccessFile(raf)
      depsParser.setDumpFile(dexLogStream.orNull)
      depsParser.parse()
      dexOffsetResolver.setDumpFile(dexLogStream.orNull)
      handleDependencies(depsDirUri.get, depsParser, dexOffsetResolver)
    }
    val dexPointerBlock = new DexPointerBlock()
    dexPointerBlock.setRandomAccessFile(raf)
    dexPointerBlock.setDumpFile(dexLogStream.orNull)
    dexPointerBlock.setDexSignatureBlock(dexSignatureBlock)
    dexPointerBlock.parse()

    val dexStringIdsBlock = new DexStringIdsBlock()
    dexStringIdsBlock.setRandomAccessFile(raf)
    dexStringIdsBlock.setDumpFile(dexLogStream.orNull)
    dexStringIdsBlock.setDexPointerBlock(dexPointerBlock)
    dexStringIdsBlock.setDexSignatureBlock(dexSignatureBlock)
    dexStringIdsBlock.parse()

    val dexTypeIdsBlock = new DexTypeIdsBlock()
    dexTypeIdsBlock.setRandomAccessFile(raf)
    dexTypeIdsBlock.setDumpFile(dexLogStream.orNull)
    dexTypeIdsBlock.setDexPointerBlock(dexPointerBlock)
    dexTypeIdsBlock.setDexStringIdsBlock(dexStringIdsBlock)
    dexTypeIdsBlock.parse()

    val dexProtoIdsBlock = new DexProtoIdsBlock()
    dexProtoIdsBlock.setRandomAccessFile(raf)
    dexProtoIdsBlock.setDumpFile(dexLogStream.orNull)
    dexProtoIdsBlock.setDexPointerBlock(dexPointerBlock)
    dexProtoIdsBlock.setDexStringIdsBlock(dexStringIdsBlock)
    dexProtoIdsBlock.setDexTypeIdsBlock(dexTypeIdsBlock)
    dexProtoIdsBlock.setDexSignatureBlock(dexSignatureBlock)
    dexProtoIdsBlock.parse()

    val dexFieldIdsBlock = new DexFieldIdsBlock()
    dexFieldIdsBlock.setRandomAccessFile(raf)
    dexFieldIdsBlock.setDumpFile(dexLogStream.orNull)
    dexFieldIdsBlock.setDexPointerBlock(dexPointerBlock)
    dexFieldIdsBlock.setDexStringIdsBlock(dexStringIdsBlock)
    dexFieldIdsBlock.setDexTypeIdsBlock(dexTypeIdsBlock)
    dexFieldIdsBlock.parse()

    val dexMethodIdsBlock = new DexMethodIdsBlock()
    dexMethodIdsBlock.setRandomAccessFile(raf)
    dexMethodIdsBlock.setDumpFile(dexLogStream.orNull)
    dexMethodIdsBlock.setDexPointerBlock(dexPointerBlock)
    dexMethodIdsBlock.setDexStringIdsBlock(dexStringIdsBlock)
    dexMethodIdsBlock.setDexTypeIdsBlock(dexTypeIdsBlock)
    dexMethodIdsBlock.setDexProtoIdsBlock(dexProtoIdsBlock)
    dexMethodIdsBlock.parse()

    val dexClassDefsBlock = new DexClassDefsBlock()
    dexClassDefsBlock.setRandomAccessFile(raf)
    dexClassDefsBlock.setDumpFile(dexLogStream.orNull)
    dexClassDefsBlock.setDexPointerBlock(dexPointerBlock)
    dexClassDefsBlock.setDexStringIdsBlock(dexStringIdsBlock)
    dexClassDefsBlock.setDexTypeIdsBlock(dexTypeIdsBlock)
    dexClassDefsBlock.setDexFieldIdsBlock(dexFieldIdsBlock)
    dexClassDefsBlock.setDexMethodIdsBlock(dexMethodIdsBlock)
    dexClassDefsBlock.setDexSignatureBlock(dexSignatureBlock)
    dexClassDefsBlock.parse()
    if(dexOffsetResolver != null)
      dexOffsetResolver.addToOffsetResolver(dexClassDefsBlock)

    new PilarStyleCodeGenerator(
      dexSignatureBlock,
      dexStringIdsBlock,
      dexTypeIdsBlock,
      dexFieldIdsBlock,
      dexMethodIdsBlock,
      dexClassDefsBlock,
      dexOffsetResolver,
      raf,
      targetDirUri,
      dexLogStream,
      recordFilter)
  }
  
  private def handleDependencies(
      depsDirUri: FileResourceUri,
      depsParser: DexDependencyParser,
      resolver: DexOffsetResolver): Boolean = {
    var error = false
    for(i <- 0 until depsParser.getDependencySize) {
      val dependencyFileName = depsParser.getDependencyElement(i)
      val slashIndex = dependencyFileName.lastIndexOf('/')
      val shortFileName = 
        if(slashIndex < 0) dependencyFileName
        else dependencyFileName.substring(slashIndex + 1)
      var raf: RandomAccessFile = null
      var f: File = null
      try {
        f = new File(FileUtil.toFilePath(depsDirUri), shortFileName)
        raf = new RandomAccessFile(f, "r")
        println( "Reading dependency file " + f +
            " (derived from ODEX file dependency "+
            dependencyFileName + ")" )
        val depFile: DexDependencyFile = new DexDependencyFile(raf, dexLogStream.orNull)
        depFile.setDexOffsetResolver(resolver)
        depFile.parse()
        depFiles += depFile
        raf.close()
      } catch {
          case _: IOException =>
            System.err.println("Cannot open dependency file: " + f +
                " (derived from ODEX file dependency " + dependencyFileName + ")")
            error = true
      }
    }
    error
  }
  
  private def close() = {
    if(dexLogStream.isDefined)
      dexLogStream.get.close()
  }
}