/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex.`type`

import org.argus.jawa.core.ast.{DefSymbol, JawaSymbol, RefSymbol}
import org.argus.jawa.core.io.Position

/**
 * The Indexes trait is mixed in by refactorings that need an index.
 * It provides several lookup functions to find references and decla-
 * rations of symbols.
 *
 * The IndexLookup trait has been separated into two traits: the
 * TrivialIndexLookup simply gives access to the underlying data,
 * whereas the IndexLookup that is used by clients contains more
 * expensive operations.
 *
 * An implementation can be found in GlobalIndexes.
 */
trait Indexes {

  this: CompilerAccess =>

  trait IndexLookup {

    /**
     * Returns all defined symbols, i.e. symbols
     * of DefTrees.
     */
    def allDefinedSymbols(): List[DefSymbol]

    /**
     * Returns all symbols that are part of the index,
     * either referenced or defined. This also includes
     * symbols from the library that are used
     * in the compilation units.
     */
    def allSymbols(): List[JawaSymbol]

    /**
     * For a given Symbol, tries to find the tree that declares it.
     * The result tree can have an offset position.
     */
    def declaration(s: RefSymbol): Option[DefSymbol]

    /**
     * For a given Symbol, returns all trees that directly
     * reference the symbol. This does not include parents
     * of trees that reference a symbol, e.g. for a method
     * call, the Select tree is returned, but not its parent
     * Apply tree.
     *
     * Only returns trees with a range position.
     */
    def references(s: DefSymbol): List[RefSymbol]

    /**
     * For a given Symbol, returns all trees that reference or
     * declare the symbol that have a range position.
     */
    def occurences(s: JawaSymbol): List[JawaSymbol]

//    /**
//     * For the given Symbol - which is a class - returns a
//     * list of all sub- and super classes, in no particular order.
//     */
//    def completeClassHierarchy(s: TypeDefSymbol): List[TypeDefSymbol] =
//      (s :: (allDefinedSymbols.filter(_.ancestors contains s))).flatMap(s => s :: s.ancestors).filter(_.pos.isDefined).distinct
//
//    /**
//     * Returns all overrides of the symbol s.
//     */
//    def overridesInClasses(s: MethodDefSymbol): List[MethodDefSymbol] =
//      completeClassHierarchy(s.enclosingTopLevelClass) map s.overridingSymbol filter (_.pos.isDefined)

    /**
     * From a position, returns the symbols that contain a tree
     * reference to that position.
     *
     * This operation is expensive because it needs to scan all
     * trees in the index.
     */
    def positionToSymbol(p: Position): List[JawaSymbol]

    /**
     * Add more convenience functions here..
     */
  }

  def index: IndexLookup
}
