/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.util

import org.argus.jawa.core.util.PropertyProvider.Map

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
object Property {
  type Key = AnyRef
  type ImmutableKey = Immutable
  type ImmutableProperties = IMap[Property.ImmutableKey, Immutable]
}

object PropertyProvider {
  type Map = MMap[Property.Key, Any]
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait PropertyProvider {
  def propertyMap : PropertyProvider.Map

  def propertyEmpty : Boolean = propertyMap.isEmpty

  def apply[T](key : Property.Key) : T = getProperty[T](key)

  def update[T](key : Property.Key, value : T) : Unit = setProperty[T](key, value)

  def ?(key : Property.Key) : Boolean = propertyMap.contains(key)

  def removeProperty(key : Property.Key): Option[Any] = propertyMap.remove(key)

  def getProperty[T](key : Property.Key): T = {
    assert(propertyMap.contains(key))

    val v = propertyMap(key)
    v.asInstanceOf[T]
  }

  def getPropertyOrElse[T](key : Property.Key, defaultValue : => T): T =
    if (propertyMap.contains(key)) getProperty[T](key) else defaultValue

  def getPropertyOrElseUpdate[T](key : Property.Key, initValue : => T): T = {
    if (propertyMap.contains(key))
      getProperty[T](key)
    else {
      val result = initValue
      setProperty(key, result)
      result
    }
  }

  def setProperty[T](key : Property.Key, value : T): Option[T] = {
    val old = propertyMap.get(key)
    propertyMap(key) = value
    old match {
      case Some(_) => Some(old.asInstanceOf[T])
      case _       => None
    }
  }
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait PropertyProviderInit extends PropertyProvider {
  private[util] var _propertyMap : PropertyProvider.Map = _
  private[util] def propertyMap_=(pp : PropertyProvider.Map) {
    _propertyMap = pp
  }
  private[util] def init : PropertyProvider.Map
  override def propertyEmpty : Boolean =
    _propertyMap == null || _propertyMap.isEmpty
  def propertyMap: Map = {
    if (_propertyMap == null)
      _propertyMap = init
    _propertyMap
  }
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait PropertyProviderInitLinked extends PropertyProviderInit {
  private[util] def init = mlinkedMapEmpty
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait PropertyProviderInitHash extends PropertyProviderInit {
  private[util] def init = mmapEmpty
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait PropertyProviderContext[T <: PropertyProvider] {
  private var _context : T = _
  def context(pp : T) : this.type = { _context = pp; this }
  def context : T = _context
  def make(pp : T) : PropertyProviderContext[T]
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
object PropertyAdapter {
  def has[T](pp : PropertyProvider, propKey : Property.Key)(implicit m : Manifest[T]): Boolean =
    pp ? propKey

  def map[T, R](pp : PropertyProvider, propKey : Property.Key)(f : T => R) //
               (implicit a : Adapter[PropertyProvider, T]) : Option[R] =
    if (has(pp, propKey)) Some(f(a.adapt(pp))) else None
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
trait ImmutablePropertyProvider[Self <: ImmutablePropertyProvider[Self]] extends SelfType[Self] {
  import Property._

  def properties : ImmutableProperties

  def ?(key : ImmutableKey) : Boolean = properties.contains(key)

  def removeProperty(key : ImmutableKey) : Self =
    make(properties - key)

  def getProperty[T <: Immutable](key : ImmutableKey): T = {
    assert(properties.contains(key))

    val v = properties(key)
    v.asInstanceOf[T]
  }

  def getPropertyOrElse[T <: Immutable](key : ImmutableKey, defaultValue : => T): T =
    if (properties.contains(key))
      getProperty[T](key)
    else
      defaultValue

  def getPropertyOrElseUpdate[T <: Immutable](key : ImmutableKey, initValue : => T) : (Self, T) =
    if (properties.contains(key))
      (self, getProperty[T](key))
    else {
      val result = initValue
      (setProperty(key, result), result)
    }

  def setProperty[T <: Immutable](key : ImmutableKey, value : T) : Self =
    make(properties + (key -> value))

  protected def make(properties : ImmutableProperties) : Self
}

/**
  * @author <a href="mailto:robby@k-state.edu">Robby</a>
  */
object ImmutablePropertyAdapter {
  def has[Self <: ImmutablePropertyProvider[Self], T](
                                                       pp : ImmutablePropertyProvider[Self], propKey : Property.ImmutableKey) //
                                                     (implicit m : Manifest[T]): Boolean =
    pp ? propKey

  def map[Self <: ImmutablePropertyProvider[Self], T, R] //
  (pp : ImmutablePropertyProvider[Self], propKey : Property.ImmutableKey) //
  (f : T => R)(implicit a : Adapter[ImmutablePropertyProvider[Self], T]) : Option[R] =
    if (has(pp, propKey)) Some(f(a.adapt(pp))) else None
}
