/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.reachingDefinitionAnalysis

import org.sireum.pilar.symbol.SymbolTable
import org.sireum.alir.DefRef
import org.sireum.alir.VarAccesses
import org.sireum.pilar.ast._
import org.sireum.util._
import org.sireum.alir.Slot
import org.sireum.pilar.symbol.H
import org.sireum.alir.VarSlot
import org.sireum.pilar.symbol.Symbol.pp2r

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class JawaVarAccesses(st: SymbolTable) extends VarAccesses {
  def localVarAccesses(procedureUri: ResourceUri): CSet[Slot] =
    procedureLocalAccessCache(procedureUri)

  def globalVarReads(procedureUri: ResourceUri): CSet[Slot] =
    procedureGlobalReadCache(procedureUri)

  def globalVarWrites(procedureUri: ResourceUri): CSet[Slot] =
    procedureGlobalWriteCache(procedureUri)

  def strongGlobalVarWrites(procedureUri: ResourceUri): CSet[Slot] =
    Set()

  private val (procedureLocalAccessCache, procedureGlobalReadCache, procedureGlobalWriteCache) = {
    val localAccesses = mmapEmpty[ResourceUri, MSet[Slot]]
    val globalReads = mmapEmpty[ResourceUri, MSet[Slot]]
    val globalWrites = mmapEmpty[ResourceUri, MSet[Slot]]

    def init() {
      var accessLocalVars = msetEmpty[Slot]
      var readGlobalVars = msetEmpty[Slot]
      var writtenGlobalVars = msetEmpty[Slot]

      def addLocalAccess(ne: NameExp) =
        if (H.isLocalVar(ne.name))
          accessLocalVars += VarSlot(ne.name.uri)

      val visitor = Visitor.build({
        case a: Assignment =>
          val lhss = PilarAstUtil.getLHSs(a)
          for (NameExp(name) <- lhss.keys)
            if (name.hasResourceInfo && H.isGlobalVar(name))
              writtenGlobalVars += VarSlot(name.uri)
          Visitor.build({
            case ne: NameExp =>
              if (ne.name.hasResourceInfo)
                if (H.isGlobalVar(ne.name) && !lhss.contains(ne))
                  readGlobalVars += VarSlot(ne.name.uri)
                else
                  addLocalAccess(ne)
              false
          })(a)
          false
        case ne: NameExp =>
          if (ne.name.hasResourceInfo)
            if (H.isGlobalVar(ne.name))
              readGlobalVars += VarSlot(ne.name.uri)
            else
              addLocalAccess(ne)
          false
      })

      st.procedureSymbolTables.foreach { pst =>
        val p = pst.procedure
        p.params.foreach{
          case param=>
            if (H.isLocalVar(param.name))
            	accessLocalVars += VarSlot(param.name.uri)
        }
        visitor(p)
        localAccesses(pst.procedureUri) = accessLocalVars
        globalReads(pst.procedureUri) = readGlobalVars
        globalWrites(pst.procedureUri) = writtenGlobalVars
        accessLocalVars = msetEmpty[Slot]
        readGlobalVars = msetEmpty[Slot]
        writtenGlobalVars = msetEmpty[Slot]
      }
    }
    init()
    (localAccesses, globalReads, globalWrites)
  }
}

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
final class JawaDefRef(st: SymbolTable, val varAccesses: VarAccesses, callref: Boolean)
  extends DefRef {

  val TITLE = "AmandroidDefRef"
  
  def definitions(a: Assignment): ISet[Slot] = {
    strongDefinitions(a)
  }
    
  def strongDefinitions(a: Assignment): ISet[Slot] =
    defCache.getOrElseUpdate(a, {
      val lhss = PilarAstUtil.getLHSs(a)
      var result = isetEmpty[Slot]
      for (ne @ NameExp(_) <- lhss.keys) {
        if(!ne.name.name.contains("@@")) {
          result = result + VarSlot(ne.name.uri)
        }
      }
      result
    })

  def references(a: Action): ISet[Slot] =
    refCache.getOrElseUpdate(a, getRefs(a))

  def references(j: Jump): ISet[Slot] =
    refCache.getOrElseUpdate(j, getRefs(j))

  def callReferences(j: CallJump): ISeq[ISet[Slot]] = {
    if(callref){
      val arg = j.callExp.arg
      arg match {
        case e: TupleExp =>
          val result = e.exps.map { exp => refCache.getOrElseUpdate(exp, getRefs(exp)) }
          result
        case e =>
          ivector(refCache.getOrElseUpdate(j, getRefs(e)))
      }
    }
    else ivectorEmpty
  }

  def callDefinitions(j: CallJump): ISeq[ISet[Slot]] = {
    callReferences(j)
  }

  private def getRefs(n: PilarAstNode): ISet[Slot] = {
    var result = isetEmpty[Slot]
    val lhss = PilarAstUtil.getLHSs(n)
    Visitor.build({
      case ne: NameExp =>
        if (!lhss.contains(ne) && ne.name.hasResourceInfo)
          result = result + VarSlot(ne.name.uri)
        false
    })(n)
    result
  }

  private val defCache = idmapEmpty[Assignment, ISet[Slot]]
  private val refCache = idmapEmpty[PilarAstNode, ISet[Slot]]
}
