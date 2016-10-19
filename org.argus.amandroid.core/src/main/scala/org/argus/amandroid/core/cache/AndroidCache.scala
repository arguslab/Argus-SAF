/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.cache

import org.sireum.util._
import java.io._
import java.util.zip.GZIPOutputStream
import java.util.zip.GZIPInputStream

import org.argus.jawa.core.util.{CacheProvider, FileCaseFactory}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class AndroidCacheFile[K] extends CacheProvider[K] with FileCaseFactory[K]{
  
  val cacheMap: MMap[K, (Any, Int)] = mmapEmpty
  var size: Int = 0
  var removePercent: Int = 20
  var serializer: (Any, OutputStream) --> Unit = null
  var unSerializer: InputStream --> Any = null
  var outer: GZIPOutputStream = null
  var inner: GZIPInputStream = null
  var rootDirectory: FileResourceUri = null

  def save[T](key: K, value: T) = {
    require(!rootDirectory.equals(null))
    setFileOutputStream(key)
    serializer((value, outer))
    outer.close()
  }
  
  def save[T](key: K, fileName: K, value: T) = {
    require(!rootDirectory.equals(null))
    setFileOutputStream(key, fileName)
    serializer((value, outer))
    outer.close()
  }

  def load[T](key: K): T = {
    require(!rootDirectory.equals(null))
    if(cacheMap.contains(key)){
      cacheUpdate(key)
      cacheMap(key)._1.asInstanceOf[T]
    } else {
      setFileInputStream(key)
      val value = unSerializer(inner).asInstanceOf[T]
      inner.close()
      if(size == 0){
        //do nothing
      } else if(cacheMap.size <= size){
        cacheMap(key) = (value, 1)
      } else {
        collectCacheMap()
        cacheMap(key) = (value, 1)
      }
      value
    }
  }
  
  def load[T](key: K, fileName: K): T = {
    require(!rootDirectory.equals(null))
//    if(cacheMap.contains(key)){
//      cacheUpdate(key)
//      cacheMap(key)._1.asInstanceOf[T]
//    } else {
      setFileInputStream(key, fileName)
      val value = unSerializer(inner).asInstanceOf[T]
      inner.close()
      if(size == 0){
        //do nothing
      } else if(cacheMap.size <= size){
        cacheMap(key) = (value, 1)
      } else {
        collectCacheMap()
        cacheMap(key) = (value, 1)
      }
      value
//    }
  }
  
  def setCacheSize(s: Int) = {
    size = s
  }
  
  def setRemovePercent(p: Int) {
    assert(p != 0)
    removePercent = p
  }
  
  def cacheUpdate(key: K) = {
    cacheMap(key) = (cacheMap(key)._1, cacheMap(key)._2 + 1)
  }
  
  def collectCacheMap() = {
    val i = (size * removePercent) / 100
    cacheMap.toSeq.sortBy(_._2._2).dropRight(i)
  }
  
  def setValueSerializer(f: (Any, OutputStream) --> Unit, g: InputStream --> Any) = {
    serializer = f
    unSerializer = g
  }
  
  def setRootDirectory(path: FileResourceUri) = {
    rootDirectory = path
  }
  
  def formatProcedureUri(pUri: ResourceUri): String = {
    pUri.replaceAll("jawa:/procedure/[a-zA-Z0-9]*/%5B%7C", "")
        .replaceAll("%7C%5D/[0-9]*/[0-9]*/", "")
        .replaceAll("[:./;\\ ]", "")
        .replaceAll("@", "_AT_")
        .replaceAll("=", "_EQ_")
        .replaceAll("%3[CE]", "")
        .replaceAll("[\\[\\]()<>\"\\|]", "")
  }
  
  def fileNameBuilder(pUri: ResourceUri): FileResourceUri = {
    formatProcedureUri(pUri) + ".xml.zip"
  }
  
  def fileNameBuilder(pUri: ResourceUri, name: ResourceUri): FileResourceUri = {
    formatProcedureUri(pUri) + "/" + name + ".xml.zip"
  }
  
  def setFileInputStream(key: K) = {
    var fileName: String = null
    key match {
      case pUri: ResourceUri =>
        fileName = rootDirectory + fileNameBuilder(pUri)
      case _ =>
    }
    inner = new GZIPInputStream(new FileInputStream(fileName))
  }
    
  def setFileOutputStream(key: K) = {
    var fileName: String = null
    key match {
      case pUri: ResourceUri =>
        fileName = rootDirectory + fileNameBuilder(pUri)
      case _ =>
    }
    val file = new File(fileName)
    outer = new GZIPOutputStream(new FileOutputStream(file))
  }
  
  def setFileInputStream(key: K, name: K) = {
    var fileName: String = null
    key match {
      case pUri: ResourceUri =>
        val fileDir = new File(rootDirectory + formatProcedureUri(pUri) + "/")
        if(!fileDir.exists()) fileDir.mkdir()
        fileName = rootDirectory + fileNameBuilder(pUri, name.asInstanceOf[ResourceUri])
      case _ =>
    }
    inner = new GZIPInputStream(new FileInputStream(fileName))
  }
    
  def setFileOutputStream(key: K, name: K) = {
    var fileName: String = null
    key match {
      case pUri: ResourceUri =>
        val fileDir = new File(rootDirectory + formatProcedureUri(pUri) + "/")
        if(!fileDir.exists()){fileDir.mkdir()}
        fileName = rootDirectory + fileNameBuilder(pUri, name.asInstanceOf[ResourceUri])
      case _ =>
    }
    val file = new File(fileName)
    outer = new GZIPOutputStream(new FileOutputStream(file))
  }
}
