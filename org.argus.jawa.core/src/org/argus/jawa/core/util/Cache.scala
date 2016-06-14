/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import org.sireum.util._
import java.io._
import java.util.zip._

/**
 * Cache provider for save Object to predefined factory and load Object from
 * cacheMap or factory.
 * 
 * For save Object you can use save[T](key: Cache.key, value: T) to save Object
 * which type is T to factory.
 * 
 * For load Object you can use load[T](key: Cache.key), if the Object exist in
 * cacheMap load it from cacheMap, if not load it from factory.
 * 
 * Use the cache provider you need to configuration the size of cacheMap,
 * remove strategy, serializer and unSerializer.
 * 
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait CacheProvider[K] {
  def cacheMap: MMap[K, (Any, Int)]
  var size: Int
  var removePercent: Int
  var serializer: (Any, OutputStream) --> Unit
  var unSerializer: InputStream --> Any
  
  /**
   * Save 'value' to file.
   * 
   * Need to preset: addValueSerializer.
   * 
   * @param key    generate file name.
   * @param value     the Object (which type is T) you want to store.
   */
  def save[T](key: K, value: T)
  
  /**
   * Load object from either cacheMap or file.
   * If the Object exist in cacheMap load it from cacheMap, otherwise load it from file
   * and store it into cacheMap. When the cacheMap full, based on your preset strategy
   * collect some of the items in cacheMap.
   * 
   * Need to preset: setCacheSize, setRemovePercent, addValueSerializer.
   * 
   * @param key     1. generate file name; 2. key in the cacheMap.
   * @return      Object which type is T
   */
  def load[T](key: K): T
  
  /**
   * Define the size of cacheMap.
   * 
   * @param size     It's an Int number which defines size of the cacheMap.
   */
  def setCacheSize(size: Int)
  
  /**
   * If the cacheMap is full, based on the percent defined here to remove proper
   * percent of items from cacheMap.
   * 
   * @param p     Percent of items need to remove. 
   */
  def setRemovePercent(p: Int)
  
  /**
   * When one of the item used in the cacheMap, first update the item used number.
   * 
   * @param key     key of the cacheMap.
   */
  def cacheUpdate(key: K)
  
  /**
   * Based on percent number, remove items from cacheMap.
   */
  def collectCacheMap()
  
  /**
   * Set serializer and unserializer to covert value to proper type.
   * 
   * @param f     serializer, which convert any type to string and put it to 
   * output stream.
   * @param g     unserializer, which get string from input stream and convert
   * to any type.
   */
  def setValueSerializer(f: (Any, OutputStream) --> Unit, g: InputStream --> Any)
}

/**
 * Define the file-based case factory. Supply method to set file directory, and
 * handle write and load action for CacheProvider.
 */
trait FileCaseFactory[K] {
  var rootDirectory: FileResourceUri
  var outer: GZIPOutputStream
  var inner: GZIPInputStream
  
  /**
   * Set the root directory of the factory.
   * 
   * @param path    root directory of the factory.
   */
  def setRootDirectory(path: FileResourceUri)
  
  /**
   * Set file input stream.
   * First, use key to generate proper file name.
   * Second, use file name and rootDirectory to set the stream.
   * 
   * @param key    generate proper file name.
   */
  def setFileInputStream(key: K)
  
  /**
   * Set file output stream.
   * First, use key to generate proper file name.
   * Second, use file name and rootDirectory to set the stream.
   * 
   * @param key    generate proper file name.
   */
  def setFileOutputStream(key: K)
}
