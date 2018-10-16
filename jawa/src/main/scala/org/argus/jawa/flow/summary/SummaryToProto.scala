/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.summary

import org.argus.jawa.flow.summary.susaf.rule._

object SummaryToProto {

  def toProto(fa: SuFieldAccess): summary.SuFieldAccess = {
    summary.SuFieldAccess(fa.fieldName)
  }

  def toProto(aa: SuArrayAccess): summary.SuArrayAccess = {
    summary.SuArrayAccess()
  }

  def toProto(ha: HeapAccess): summary.HeapAccess = {
    ha match {
      case fa: SuFieldAccess =>
        summary.HeapAccess(heapAccess = summary.HeapAccess.HeapAccess.FieldAccess(toProto(fa)))
      case aa: SuArrayAccess =>
        summary.HeapAccess(heapAccess = summary.HeapAccess.HeapAccess.ArrayAccess(toProto(aa)))
    }
  }

  def toProto(heap: SuHeap): summary.SuHeap = {
    summary.SuHeap(heap.indices.map(toProto))
  }

  def toProto(arg: SuArg): summary.SuArg = {
    summary.SuArg(num = arg.num, heap = arg.heapOpt.map(toProto))
  }

  def toProto(global: SuGlobal): summary.SuGlobal = {
    summary.SuGlobal(fqn = global.fqn, heap = global.heapOpt.map(toProto))
  }

  def toProto(ret: SuRet): summary.SuRet = {
    summary.SuRet(heap = ret.heapOpt.map(toProto))
  }

  def toProto(th: SuThis): summary.SuThis = {
    summary.SuThis(heap = th.heapOpt.map(toProto))
  }

  def toProto(hb: HeapBase): summary.HeapBase = {
    hb match {
      case arg: SuArg =>
        summary.HeapBase(heapBase = summary.HeapBase.HeapBase.Arg(toProto(arg)))
      case global: SuGlobal =>
        summary.HeapBase(heapBase = summary.HeapBase.HeapBase.Global(toProto(global)))
      case ret: SuRet =>
        summary.HeapBase(heapBase = summary.HeapBase.HeapBase.Ret(toProto(ret)))
      case th: SuThis =>
        summary.HeapBase(heapBase = summary.HeapBase.HeapBase.This(toProto(th)))
    }
  }

  def toProto(lhs: RuleLhs): summary.RuleLhs = {
    lhs match {
      case arg: SuArg =>
        summary.RuleLhs(ruleLhs = summary.RuleLhs.RuleLhs.Arg(toProto(arg)))
      case global: SuGlobal =>
        summary.RuleLhs(ruleLhs = summary.RuleLhs.RuleLhs.Global(toProto(global)))
      case ret: SuRet =>
        summary.RuleLhs(ruleLhs = summary.RuleLhs.RuleLhs.Ret(toProto(ret)))
      case th: SuThis =>
        summary.RuleLhs(ruleLhs = summary.RuleLhs.RuleLhs.This(toProto(th)))
    }
  }

  def toProto(loc: SuLocation): summary.SuLocation = {
    loc match {
      case vloc: SuVirtualLocation =>
        summary.SuLocation(suLocation = summary.SuLocation.SuLocation.VirtualLocation(toProto(vloc)))
      case cloc: SuConcreteLocation =>
        summary.SuLocation(suLocation = summary.SuLocation.SuLocation.ConcreteLocation(toProto(cloc)))
    }
  }

  def toProto(vloc: SuVirtualLocation): summary.SuVirtualLocation = {
    summary.SuVirtualLocation()
  }

  def toProto(cloc: SuConcreteLocation): summary.SuConcreteLocation = {
    summary.SuConcreteLocation(loc = cloc.loc)
  }

  def toProto(co: SuClassOf): summary.SuClassOf = {
    summary.SuClassOf(ruleRhs = Some(toProto(co.rhs)), suLocation = Some(toProto(co.loc)))
  }

  def toProto(java: SuJavaType): summary.SuJavaType = {
    summary.SuJavaType(javaType = Some(java.typ.javaType))
  }

  def toProto(string: SuString): summary.SuString = {
    summary.SuString(str = string.str)
  }

  def toProto(typ: SuType): summary.SuType = {
    typ match {
      case java: SuJavaType =>
        summary.SuType(suType = summary.SuType.SuType.SuJavaType(toProto(java)))
      case string: SuString =>
        summary.SuType(suType = summary.SuType.SuType.SuString(toProto(string)))
    }
  }

  def toProto(ins: SuInstance): summary.SuInstance = {
    summary.SuInstance(suTyp = Some(toProto(ins.typ)), suLocation = Some(toProto(ins.loc)))
  }

  def toProto(rhs: RuleRhs): summary.RuleRhs = {
    rhs match {
      case arg: SuArg =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.Arg(toProto(arg)))
      case global: SuGlobal =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.Global(toProto(global)))
      case ret: SuRet =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.Ret(toProto(ret)))
      case th: SuThis =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.This(toProto(th)))
      case co: SuClassOf =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.ClassOf(toProto(co)))
      case ins: SuInstance =>
        summary.RuleRhs(ruleRhs = summary.RuleRhs.RuleRhs.Instance(toProto(ins)))
    }
  }

  def toProto(cr: ClearRule): summary.ClearRule = {
    summary.ClearRule(heapBase = Some(toProto(cr.v)))
  }

  def toProto(br: BinaryRule): summary.BinaryRule = {
    val ops = br.ops match {
      case Ops.`+=` => summary.BinaryRule.Ops.PLUS_EQ
      case Ops.`-=` => summary.BinaryRule.Ops.MINUS_EQ
      case Ops.`=` => summary.BinaryRule.Ops.EQ
    }
    summary.BinaryRule(ruleLhs = Some(toProto(br.lhs)), ops = ops, ruleRhs = Some(toProto(br.rhs)))
  }

  def toProto(su_rule: HeapSummaryRule): summary.HeapSummaryRule = {
    su_rule match {
      case cr: ClearRule =>
        summary.HeapSummaryRule(summary.HeapSummaryRule.HeapSummaryRule.ClearRule(toProto(cr)))
      case br: BinaryRule =>
        summary.HeapSummaryRule(summary.HeapSummaryRule.HeapSummaryRule.BinaryRule(toProto(br)))
    }
  }

  def toProto(su: HeapSummary): summary.HeapSummary = {
    summary.HeapSummary(methodSignature = Some(su.sig.method_signature), rules = su.rules.map(toProto))
  }
}
