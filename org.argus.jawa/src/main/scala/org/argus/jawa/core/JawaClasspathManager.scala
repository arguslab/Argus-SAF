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

import com.google.common.cache.{Cache, CacheBuilder, CacheLoader, LoadingCache}
import org.argus.jawa.core.backend.JavaPlatform
import org.argus.jawa.core.backend.classpath._
import org.argus.jawa.core.frontend.MyClass
import org.argus.jawa.core.frontend.classfile.JavaClassFile
import org.argus.jawa.core.frontend.javafile.JavaSourceFile
import org.argus.jawa.core.frontend.jawafile.JawaSourceFile
import org.argus.jawa.core.io._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait JawaClasspathManager extends JavaKnowledge { self: Global =>
  
  private final val TITLE = "JawaClasspathManager"

  protected var libSummary: LibraryAPISummary = NoLibraryAPISummary

  def setLibSummary(sum: LibraryAPISummary): Unit = libSummary = sum

  /**
    * load code from given root dir
    */
  def load(fileRootUri: FileResourceUri, ext: String): IMap[JawaType, SourceFile] = {
    val fileUris = FileUtil.listFiles(fileRootUri, ext, recursive = true)
    fileUris.flatMap{ fileUri =>
      load(fileUri)
    }.toMap
  }

  /**
    * load code from given file
    */
  def load(fileUri: FileResourceUri): IMap[JawaType, SourceFile] = {
    fileUri match {
      case jawafile if jawafile.endsWith(Constants.JAWA_FILE_EXT) => loadJawa(FileUtil.toFile(jawafile))
      case javafile if javafile.endsWith(Constants.JAVA_FILE_EXT) => loadJava(FileUtil.toFile(javafile))
      case classfile if classfile.endsWith(Constants.CLASS_FILE_EXT) => loadClass(FileUtil.toFile(classfile))
      case _ =>
        reporter.warning(TITLE, s"Try to load class from unknown source file: $fileUri")
        imapEmpty
    }
  }

  private def loadJawa(filePath: Path): IMap[JawaType, SourceFile] = {
    val source = new JawaSourceFile(new PlainFile(filePath))
    val codes = source.getClassCodes
    val classTypes: MSet[JawaType] = msetEmpty
    codes.foreach{ code =>
      try {
        val className = LightWeightJawaParser.getClassName(code)
        classTypes += JavaKnowledge.getTypeFromJawaName(className)
      } catch {
        case e: Exception => reporter.warning(TITLE, e.getMessage)
      }
    }
    classTypes.map { typ =>
      if (libSummary.isLibraryClass(typ)) {
        this.userLibraryClassCodes(typ) = source
      } else {
        this.applicationClassCodes(typ) = source
      }
      typ -> source
    }.toMap
  }

  private def loadJava(filePath: Path): IMap[JawaType, SourceFile] = {
    val source = new JavaSourceFile(self, new PlainFile(filePath))
    source.getTypes.map { typ =>
      if (libSummary.isLibraryClass(typ)) {
        this.userLibraryClassCodes(typ) = source
      } else {
        this.applicationClassCodes(typ) = source
      }
      typ -> source
    }.toMap
  }

  private def loadClass(filePath: Path): IMap[JawaType, SourceFile] = {
    val source = new JavaClassFile(new PlainFile(filePath))
    val typ = source.getType
    if (libSummary.isLibraryClass(typ)) {
      this.userLibraryClassCodes(typ) = source
    } else {
      this.applicationClassCodes(typ) = source
    }
    Map(typ -> source)
  }

  /**
    * load code from given string
    */
  def loadJawaCode(codes: IMap[JawaType, String]): Unit = {
    codes.foreach { case (typ, code) =>
      try {
        val source = new JawaSourceFile(new StringFile(code))
        if (libSummary.isLibraryClass(typ)) {
          this.userLibraryClassCodes(typ) = source
        } else {
          this.applicationClassCodes(typ) = source
        }
      } catch {
        case e: Exception => reporter.warning(TITLE, e.getMessage)
      }
    }
  }

  /**
    * Used to load anonymous class, local class.
    */
  def loadJavaClass(typ: JawaType, src: JavaSourceFile): Unit = {
    if(libSummary.isLibraryClass(typ)) {
      this.userLibraryClassCodes(typ) = src
    } else {
      this.applicationClassCodes(typ) = src
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
    this.cachedClassRepresentation.get(typ).isDefined
  }

  protected val cachedMyClass: Cache[JawaType, MyClass] = CacheBuilder.newBuilder()
    .maximumSize(1000).build[JawaType, MyClass]()
  
  def getMyClass(typ: JawaType): Option[MyClass] = {
    Option(cachedMyClass.getIfPresent(typ)) match {
      case mc @ Some(_) => mc
      case None =>
        val mcs: IMap[JawaType, MyClass] = this.applicationClassCodes.get(typ) match {
          case Some(asrc) =>
            asrc.parse(reporter)
          case None =>
            this.userLibraryClassCodes.get(typ) match {
              case Some(usrc) =>
                usrc.parse(reporter)
              case None =>
                this.cachedClassRepresentation.get(typ) match {
                  case Some(cs) =>
                    cs.binary match {
                      case Some(bin) =>
                        val classfile = new JavaClassFile(bin)
                        classfile.parse(reporter)
                      case None =>
                        imapEmpty
                    }
                  case None =>
                    imapEmpty
                }
            }
        }
        mcs.foreach{ case (t, mc) =>
          cachedMyClass.put(t, mc)
        }
        mcs.get(typ)
    }

  }
}

object ClasspathRepresentationType extends Enumeration {
  val Flat, Recursive = Value
}