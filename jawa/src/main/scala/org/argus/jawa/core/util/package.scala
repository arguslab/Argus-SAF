/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

/**
 * @author <a href="mailto:robby@k-state.edu">Robby</a>
 */
package object util {
  type FileResourceUri = String
  type ResourceUri = String

  type CSeq[T] = scala.collection.Seq[T]
  type CMap[K, V] = scala.collection.Map[K, V]
  type CSet[T] = scala.collection.Set[T]

  type GenSeq[T] = scala.collection.GenSeq[T]

  type MSeq[T] = scala.collection.mutable.Seq[T]
  type MBitSet = scala.collection.mutable.BitSet
  type MBuffer[T] = scala.collection.mutable.Buffer[T]
  type MArray[T] = scala.collection.mutable.ArrayBuffer[T]
  type MList[T] = scala.collection.mutable.ListBuffer[T]
  type MMap[K, V] = scala.collection.mutable.Map[K, V]
  type MIdMap[K, V] = MMap[K, V]
  type MConcMap[K, V] = scala.collection.concurrent.Map[K, V]
  type MSet[T] = scala.collection.mutable.Set[T]
  type MLinkedSet[T] = scala.collection.mutable.LinkedHashSet[T]
  type MLinkedMap[K, V] = scala.collection.mutable.LinkedHashMap[K, V]
  type MIdSet[T] = MMap[T, T]

  @inline
  def mbitsetEmpty() : MBitSet = scala.collection.mutable.BitSet.empty

  @inline
  def mbitsetEmpty(size : Int) : MBitSet = new scala.collection.mutable.BitSet(size)

  @inline
  def marrayEmpty[T] : MArray[T] = scala.collection.mutable.ArrayBuffer.empty[T]

  @inline
  def mlistEmpty[T] : MList[T] = scala.collection.mutable.ListBuffer.empty[T]

  @inline
  def mmapEmpty[K, V] : MMap[K, V] = scala.collection.mutable.Map.empty[K, V]

  @inline
  def mlinkedSetEmpty[T] : MLinkedSet[T] = scala.collection.mutable.LinkedHashSet.empty[T]

  @inline
  def mlinkedMapEmpty[K, V] : MLinkedMap[K, V] = scala.collection.mutable.LinkedHashMap.empty[K, V]

  @inline
  def msetEmpty[T] : MSet[T] = scala.collection.mutable.Set.empty[T]

  @inline
  def idmapEmpty[K, V] : MIdMap[K, V] = {
    import scala.collection.JavaConverters._

    new java.util.IdentityHashMap[K, V].asScala
  }

  @inline
  def idsetEmpty[T] : MIdSet[T] = {
    import scala.collection.JavaConverters._

    new java.util.IdentityHashMap[T, T].asScala
  }

  @inline
  def idmapEmpty[K, V](initialCapacity : Int) : MMap[K, V] = {
    import scala.collection.JavaConverters._

    new java.util.IdentityHashMap[K, V](initialCapacity).asScala
  }

  @inline
  def cmapEmpty[K, V] : MConcMap[K, V] = {
    import scala.collection.JavaConverters._
    new java.util.concurrent.ConcurrentHashMap[K, V]().asScala
  }

  type IBitSet = scala.collection.immutable.BitSet
  type ISeq[T] = scala.collection.immutable.Seq[T]
  type IVector[T] = scala.collection.immutable.Vector[T]
  type IList[T] = scala.collection.immutable.List[T]
  type IMap[K, V] = scala.collection.immutable.Map[K, V]
  type ILinkedMap[K, V] = scala.collection.immutable.ListMap[K, V]
  type ISortedMap[K, V] = scala.collection.immutable.SortedMap[K, V]
  type ISet[T] = scala.collection.immutable.Set[T]
  type ISortedSet[T] = scala.collection.immutable.SortedSet[T]

  @inline
  def ibitsetEmpty : IBitSet = scala.collection.immutable.BitSet.empty

  @inline
  def ilistEmpty[T] : IList[T] = scala.collection.immutable.List.empty[T]

  @inline
  def ilist[T](args : T*) : IList[T] = List(args : _*)

  @inline
  def ivectorEmpty[T] : IVector[T] = scala.collection.immutable.Vector.empty[T]

  @inline
  def ivector[T](args : T*) : IVector[T] = Vector(args : _*)

  @inline
  def imapEmpty[K, V] : IMap[K, V] = scala.collection.immutable.Map.empty[K, V]

  @inline
  def ilinkedMapEmpty[K, V] : ILinkedMap[K, V] = scala.collection.immutable.ListMap.empty[K, V]

  @inline
  def ilinkedMap[K, V](ps : (K, V)*) : ILinkedMap[K, V] = {
    var r = ilinkedMapEmpty[K, V]
    for (p <- ps)
      r = r + p
    r
  }

  @inline
  def isortedMapEmpty[K, V](implicit ev$1: K => Ordered[K]) : ISortedMap[K, V] = scala.collection.immutable.SortedMap.empty[K, V]

  @inline
  def isetEmpty[T] : ISet[T] = scala.collection.immutable.Set.empty[T]

  @inline
  def isortedSetEmpty[T](implicit ev$1: T => Ordered[T]) : ISortedSet[T] = scala.collection.immutable.SortedSet.empty[T]

  def mmapGetOrElseUpdateT[K, V] //
  (map : MMap[K, V], key : K,
   defaultValue : => V, keyTransformer : K => K) : V =
    map.get(key) match {
      case Some(v) => v
      case _ =>
        val v = defaultValue
        map(keyTransformer(key)) = v
        v
    }

  @inline
  def cintersect[T](s1 : CSet[T], s2 : CSet[T]): CSet[T] = s1.intersect(s2)

  @inline
  def cunion[T](s1 : CSet[T], s2 : CSet[T]): CSet[T] = s1.union(s2)

  @inline
  def bigCIntersect[T](it : Iterable[CSet[T]]) : CSet[T] =
    it.size match {
      case 0 => Set()
      case 1 => it.iterator.next
      case _ => it.reduce(cintersect[T])
    }

  @inline
  def bigCUnion[T](it : Iterable[CSet[T]]) : CSet[T] =
    it.size match {
      case 0 => Set()
      case 1 => it.iterator.next
      case _ => it.reduce(cunion[T])
    }

  @inline
  def iintersect[T](s1 : ISet[T], s2 : ISet[T]): ISet[T] = s1.intersect(s2)

  @inline
  def iunion[T](s1 : ISet[T], s2 : ISet[T]): ISet[T] = s1.union(s2)

  @inline
  def bigIIntersect[T](it : Iterable[ISet[T]]) : ISet[T] =
    it.size match {
      case 0 => Set()
      case 1 => it.iterator.next
      case _ => it.reduce(iintersect[T])
    }

  @inline
  def bigIUnion[T](it : Iterable[ISet[T]]) : ISet[T] =
    it.size match {
      case 0 => Set()
      case 1 => it.iterator.next
      case _ => it.reduce(iunion[T])
    }

  @inline
  def truePredicate1[T](t : T) : Boolean = true

  @inline
  def truePredicate2[T1, T2](t1 : T1, t2 : T2) : Boolean = true

  @inline
  def truePredicate3[T1, T2, T3](t1 : T1, t2 : T2, t3 : T3) : Boolean = true

  @inline
  def falsePredicate1[T](t : T) : Boolean = false

  @inline
  def falsePredicate2[T1, T2](t1 : T1, t2 : T2) : Boolean = false

  @inline
  def falsePredicate3[T1, T2, T3](t1 : T1, t2 : T2, t3 : T3) : Boolean = false

  type -->[D, I] = PartialFunction[D, I]
  type VisitorFunction = Any --> Boolean
}  
