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

import org.sireum.util._
import org.argus.jawa.core.backend.JavaPlatform
import org.argus.jawa.core.classpath._
import org.argus.jawa.core.io._
import com.google.common.cache.LoadingCache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import org.argus.jawa.core.classfile.ClassfileParser
import org.argus.jawa.core.sourcefile.SourcefileParser

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait JawaClasspathManager extends JavaKnowledge { self: Global =>
  
  private final val TITLE = "JawaClasspathManager"
  
  /**
   * load code from given root dir
   */
  def load(fileRootUri: FileResourceUri, ext: String, summary: LibraryAPISummary): Unit = {
    val fileUris = FileUtil.listFiles(fileRootUri, ext, recursive = true)
    fileUris.foreach{
      fileUri =>
        val source = new FgSourceFile(new PlainFile(FileUtil.toFile(fileUri)))
        val codes = source.getClassCodes
        val classTypes: MSet[JawaType] = msetEmpty
        codes.foreach{
          code =>
            try {
              val className = LightWeightPilarParser.getClassName(code)
              classTypes += JavaKnowledge.getTypeFromJawaName(className)
            } catch {
              case ie: InterruptedException => throw ie
              case e: Exception => reporter.warning(TITLE, e.getMessage)
            }
        }
        classTypes.foreach {
          typ =>
            if (summary.isLibraryClass(typ)) {
              this.userLibraryClassCodes(typ) = source
            } else {
              this.applicationClassCodes(typ) = source
            }
        }
    }
  }
  
  def getClassCategoryFromClassPath(typ: JawaType): ClassCategory.Value = {
    if (this.applicationClassCodes.contains(typ)) {
      ClassCategory.APPLICATION
    } else {
      if (this.userLibraryClassCodes.contains(typ)) {
        ClassCategory.USER_LIBRARY
      } else {
        ClassCategory.SYSTEM_LIBRARY
      }
    }
  }
  
  /**
   * map from class name to jawa code of library. E.g. class type java.lang.Object to its file
   */
  protected val userLibraryClassCodes: MMap[JawaType, SourceFile] = mmapEmpty
  
  /**
   * map from class name to jawa code of app. E.g. record name java.lang.MyObject to its file
   */
  protected val applicationClassCodes: MMap[JawaType, SourceFile] = mmapEmpty
  
  def getUserLibraryClassCodes: IMap[JawaType, SourceFile] = this.userLibraryClassCodes.toMap
  
  def getApplicationClassCodes: IMap[JawaType, SourceFile] = this.applicationClassCodes.toMap
  
  // platform specific elements

  private var javaLibrary: String = ""
  
  def setJavaLib(path: String): Unit = {
    cachedClassRepresentation.invalidateAll()
    javaLibrary = path
  }
  
  protected class GlobalPlatform extends {
    val global: this.type = this
    val javaLib: String = javaLibrary
  } with JavaPlatform

  lazy val platform = new GlobalPlatform

  def classpathImpl: ClasspathRepresentationType.Value = ClasspathRepresentationType.Flat
  
  def classPath: ClassFileLookup = classpathImpl match {
    case ClasspathRepresentationType.Flat => flatClassPath
    case ClasspathRepresentationType.Recursive => recursiveClasspath
  }

  private def recursiveClasspath: Classpath = platform.classPath

  private def flatClassPath: FlatClasspath = platform.flatClassPath
  
  protected val cachedClassRepresentation: LoadingCache[JawaType, Option[ClassRepresentation]] = CacheBuilder.newBuilder()
    .maximumSize(1000).build(
        new CacheLoader[JawaType, Option[ClassRepresentation]]() {
          def load(typ: JawaType): Option[ClassRepresentation] = {
            classPath.findClass(typ.name)
          }
        })
  
  def containsClassFile(typ: JawaType): Boolean = {
    this.applicationClassCodes.contains(typ) ||
    this.userLibraryClassCodes.contains(typ) ||
    cachedClassRepresentation.get(typ).isDefined
  }
  
  /**
   * get procedure's containing record's code
   */
  def getMethodCode(sig: Signature): Option[String] = {
    val typ = sig.getClassType
    this.applicationClassCodes.get(typ) match {
      case Some(asrc) =>
        val recordCode = getClassCode(asrc.file, ResolveLevel.BODY)
        LightWeightPilarParser.getCode(recordCode, sig.signature)
      case None =>
        this.userLibraryClassCodes.get(typ) match {
          case Some(usrc) =>
            val recordCode = getClassCode(usrc.file, ResolveLevel.BODY)
            LightWeightPilarParser.getCode(recordCode, sig.signature)
          case None =>
            None
        }
    }
  }
  
  def getMyClass(typ: JawaType): Option[MyClass] = {
    this.applicationClassCodes.get(typ) match {
      case Some(asrc) =>
        SourcefileParser.parse(asrc, ResolveLevel.HIERARCHY, reporter).get(typ)
      case None =>
        this.userLibraryClassCodes.get(typ) match {
          case Some(usrc) =>
            SourcefileParser.parse(usrc, ResolveLevel.HIERARCHY, reporter).get(typ)
          case None =>
            cachedClassRepresentation.get(typ) match {
              case Some(cs) =>
                ClassfileParser.parse(cs.binary.get).get(typ)
              case None =>
                None
            }
        }
    }
  }
  
  def getClassRepresentation(typ: JawaType): Option[ClassRepresentation] = {
    this.cachedClassRepresentation.get(typ)
  }
}

object ClasspathRepresentationType extends Enumeration {
  val Flat, Recursive = Value
}