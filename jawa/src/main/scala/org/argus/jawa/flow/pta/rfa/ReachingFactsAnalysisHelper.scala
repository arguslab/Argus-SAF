/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.flow.pta.rfa

import org.argus.jawa.flow.pta._
import org.argus.jawa.flow.Context
import org.argus.jawa.core.ast._
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ReachingFactsAnalysisHelper {
  final val TITLE = "ReachingFactsAnalysisHelper"
  def getFactMap(s: ISet[RFAFact]): IMap[PTASlot, ISet[Instance]] = {
    s.groupBy(_.slot).mapValues(_.map(_.ins))
  }

  def getHeapFacts(s: ISet[RFAFact]): ISet[RFAFact] = {
    s.filter(_.s.isInstanceOf[HeapSlot])
  }

  def getRelatedFactsForArg(slot: VarSlot, s: ISet[RFAFact]): ISet[RFAFact] = {
    val bFacts = s.filter(fact=> slot.getId == fact.s.getId).map(fact => RFAFact(slot, fact.ins))
    val rhFacts = getRelatedHeapFactsFrom(bFacts, s)
    bFacts ++ rhFacts
  }

  def getRelatedHeapFactsFrom(fromFacts: ISet[RFAFact], s: ISet[RFAFact]): ISet[RFAFact] = {
    val insts = fromFacts.map(f => f.ins)
    getRelatedHeapFacts(insts, s)
  }
  
  def getRelatedHeapFacts(insts: ISet[Instance], s: ISet[RFAFact]): ISet[RFAFact] = {
    val hs = getHeapFacts(s)
    var processed: ISet[Instance] = isetEmpty
    var result: ISet[RFAFact] = isetEmpty
    val worklist = new WorklistAlgorithm[Instance] {
      override def processElement(ins: Instance): Unit = {
        processed += ins
        val facts = hs.filter(_.s.asInstanceOf[HeapSlot].matchWithInstance(ins))
        result ++= facts
        worklist = facts.map { case RFAFact(_, v) => v }.diff(processed) ++: worklist
      }
    }
    worklist.run(worklist.worklist = insts.toList)
    result
  }

  def cleanHeap(facts: ISet[RFAFact]): ISet[RFAFact] = {
    val root: ISet[RFAFact] = facts.filter { fact => fact.slot.isInstanceOf[NameSlot]}
    root ++ ReachingFactsAnalysisHelper.getRelatedHeapFactsFrom(root, facts)
  }

  def getGlobalFacts(s: ISet[RFAFact]): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    for (fact <- s){
      fact.s match{
        case _: StaticFieldSlot =>
          result += fact
          result ++= getRelatedHeapFacts(Set(fact.ins), s)
        case _ =>
      }
    }
    result
  }

  def aggregate(facts: ISet[RFAFact]): ISet[RFAFact] = {
    val kill: MSet[RFAFact] = msetEmpty
    val gen: MSet[RFAFact] = msetEmpty
    getFactMap(facts).foreach { case (slot, inss) =>
      val sametype: MMap[JawaType, (MSet[Instance], MSet[InstanceAggregate])] = mmapEmpty
      inss.foreach { ins =>
        val (instances, aggres) = sametype.getOrElseUpdate(ins.typ, (msetEmpty, msetEmpty))
        ins match {
          case aggre: InstanceAggregate =>
            aggres += aggre
          case _ =>
            instances += ins
        }
      }
      sametype.foreach { case (typ, (instances, aggres)) =>
        val ia = if(aggres.nonEmpty) aggres.headOption else if(instances.size > 10) Some(InstanceAggregate(typ)) else None
        ia match {
          case Some(aggre) =>
            kill ++= instances.map(RFAFact(slot, _)) ++ aggres.map(RFAFact(slot, _))
            aggre.addInstances(instances.toSet)
            aggre.addInstanceAggregates(aggres.toSet)
            gen += RFAFact(slot, aggre)
          case None =>
        }
      }
    }
    facts -- kill ++ gen
  }

  def getInstanceFromType(typ: JawaType, currentContext: Context): Option[Instance] = {
    typ match{
      case pt if pt.isPrimitive => None
      case ot if ot.jawaName == "java.lang.String" =>
        Some(PTAPointStringInstance(currentContext.copy))
      case ot if ot.isObject =>
        Some(PTAInstance(ot, currentContext.copy))
    }
  }

  def getUnknownObject(
      calleeMethod: JawaMethod,
      s: ISet[RFAFact],
      retOpt: Option[String],
      recvOpt: Option[String],
      args: Seq[String],
      currentContext: Context): (ISet[RFAFact], ISet[RFAFact]) = {
    var genFacts: ISet[RFAFact] = isetEmpty
    val killFacts: ISet[RFAFact] = isetEmpty
    val argSlots = (recvOpt ++ args).toList.map(arg=>VarSlot(arg))
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val argValues = s.filter(f => f.s == argSlot).map(_.v)
      val typ: JawaType =
        if(!calleeMethod.isStatic && i == 0) calleeMethod.getDeclaringClass.typ
        else if(!calleeMethod.isStatic) calleeMethod.getSignature.getParameterTypes(i - 1)
        else calleeMethod.getSignature.getParameterTypes(i)
      if(typ.isObject && !typ.isArray) {
        val influencedFields = Set(Constants.ALL_FIELD_FQN(typ))
        argValues.foreach { ins =>
          for (f <- influencedFields) {
            val fs = FieldSlot(ins, f.fieldName)
            val uins = PTAInstance(JavaKnowledge.OBJECT.toUnknown, currentContext)
            genFacts += RFAFact(fs, uins)
          }
        }
      }
    }
    retOpt match {
      case Some(retVar) =>
        val retTyp = calleeMethod.getReturnType
        retTyp match {
          case ot if ot.isObject =>
            val slot = VarSlot(retVar)
            val value =
              if(retTyp.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
              else PTAInstance(ot.toUnknown, currentContext)
            genFacts += RFAFact(slot, value)
          case _ =>
        }
      case None =>
    }
    (genFacts, killFacts)
  }

  def getUnknownObjectForClinit(calleeMethod: JawaMethod, currentContext: Context): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    val record = calleeMethod.getDeclaringClass
    record.getDeclaredStaticObjectTypeFields.foreach{ field =>
      result += RFAFact(StaticFieldSlot(field.FQN.fqn), PTAInstance(field.getType.toUnknown, currentContext))
    }
    result
  }

  def getExceptionFacts(a: Assignment, s: ISet[RFAFact], currentContext: Context): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    a match{
      case _: AssignmentStatement =>
        val thrownExcNames = ExceptionCenter.getExceptionMayThrowFromStatement(a)
        thrownExcNames.foreach{ excName =>
          if(excName != ExceptionCenter.THROWABLE) {
            val ins = PTAInstance(excName, currentContext.copy)
            result += RFAFact(VarSlot(ExceptionCenter.EXCEPTION_VAR_NAME), ins)
          }
        }
      case _ =>
    }
    result
  }

  def updatePTAResultVar(varName: String, currentContxt: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    val slot = VarSlot(varName)
    s.filter { fact =>
      fact.s == slot
    }.foreach(f => ptaresult.addInstance(currentContxt, slot, f.v))
  }

  def updatePTAResultLHS(lhs: Expression with LHS, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    lhs match {
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach { ins =>
          ptaresult.addInstance(currentContext, baseSlot, ins)
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach { ins =>
          ptaresult.addInstance(currentContext, baseSlot, ins)
        }
      case _ =>
    }
  }

  private def resolvePTAResultAccessExp(ae: AccessExpression, typ: JawaType, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    val baseSlot = VarSlot(ae.base)
    val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map{ f =>
      ptaresult.addInstance(currentContext, baseSlot, f.v)
      f.v
    }
    baseValue.foreach{ ins =>
      if(ins.isNull){}
      else {
        val fieldSlot = FieldSlot(ins, ae.fieldName)
        s.filter { fact => fact.s == fieldSlot }.foreach(f => ptaresult.addInstance(currentContext, fieldSlot, f.v))
        s.foreach { fact =>
          fact.s match {
            case slot: FieldSlot if slot.ins == ins && slot.fieldName == Constants.ALL_FIELD && typ.isObject =>
              val uIns = PTAInstance(typ.toUnknown, fact.v.defSite)
              ptaresult.addInstance(currentContext, fieldSlot, uIns)
            case _ =>
          }
        }
      }
    }
  }

  private def resolvePTAResultIndexingExp(ie: IndexingExpression, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    val baseSlot = VarSlot(ie.base)
    val baseValue: ISet[Instance] = s.filter { fact => fact.s.getId == baseSlot.getId }.map{ f =>
      ptaresult.addInstance(currentContext, baseSlot, f.v)
      f.v
    }
    baseValue.foreach{ ins =>
      if(ins.isNull){}
      else if(ins.isUnknown){
        val arraySlot = ArraySlot(ins)
        val temp = s.filter { fact => fact.s == arraySlot }.map{ f =>
          ptaresult.addInstance(currentContext, arraySlot, f.v)
          f.v
        }
        if(temp.isEmpty){
          if(ins.typ.dimensions > 0) {
            val baseType = new JawaType(ins.typ.baseType, ins.typ.dimensions - 1)
            if(baseType.isObject) {
              val uIns = PTAInstance(baseType, currentContext)
              ptaresult.addInstance(currentContext, arraySlot, uIns)
            }
          }
        }
      }
      else{
        val arraySlot = ArraySlot(ins)
        s.filter { fact => fact.s == arraySlot }.foreach(f => ptaresult.addInstance(currentContext, arraySlot, f.v))
      }
    }
  }

  def updatePTAResultRHS(rhs: Expression with RHS, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    updatePTAResultExp(rhs, currentContext, s, ptaresult)
  }

  def updatePTAResultCallJump(cs: CallStatement, callerContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, afterCall: Boolean): Unit = {
    (cs.recvOpt ++ cs.args).foreach(updatePTAResultCallArg(_, callerContext, s, ptaresult, afterCall))
  }

  def updatePTAResultExp(exp: Expression, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult): Unit = {
    exp match{
      case be: BinaryExpression =>
        val slotlhs = VarSlot(be.left.varName)
        s.filter { fact => fact.s == slotlhs }.foreach{ f =>
          ptaresult.addInstance(currentContext, slotlhs, f.v)
        }
        be.right match {
          case Left(r) =>
            val slotrhs = VarSlot(r.varName)
            s.filter { fact => fact.s == slotrhs }.foreach{ f =>
              ptaresult.addInstance(currentContext, slotrhs, f.v)
            }
          case Right(_) =>
        }
      case vne: VariableNameExpression =>
        val slot = VarSlot(vne.name)
        s.filter { fact => fact.s == slot }.foreach(f => ptaresult.addInstance(currentContext, slot, f.v))
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        s.filter { fact => fact.s == slot }.foreach(f => ptaresult.addInstance(currentContext, slot, f.v))
      case ae: AccessExpression =>
        resolvePTAResultAccessExp(ae, ae.typ, currentContext, s, ptaresult)
      case ie: IndexingExpression =>
        resolvePTAResultIndexingExp(ie, currentContext, s, ptaresult)
      case ce: CastExpression =>
        val slot = VarSlot(ce.varName)
        s.filter { fact => fact.s == slot }.foreach{ f =>
          ptaresult.addInstance(currentContext, slot, f.v)
        }
      case _=>
    }
  }

  private def updatePTAResultCallArg(arg: String, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, afterCall: Boolean): Unit = {
    val slot = VarSlot(arg)
    getRelatedFactsForArg(slot, s).foreach { f =>
      if(afterCall) {
        ptaresult.addInstanceAfterCall(currentContext, f.s, f.v)
      } else {
        ptaresult.addInstance(currentContext, f.s, f.v)
      }
    }
  }
  
  private def getHeapUnknownFactsExp(exp: Expression, currentContext: Context, ptaresult: PTAResult): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    exp match {
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        val value = ptaresult.pointsToSet(currentContext, slot)
        if(value.isEmpty) {
          val typ = sfae.typ
          val newUnknown =
            if(typ.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
            else PTAInstance(typ.toUnknown, currentContext)
          result += RFAFact(slot, newUnknown)
          ptaresult.addInstance(currentContext, slot, newUnknown)
        }
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.varSymbol.varName)
        val baseValue = ptaresult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach { ins =>
          val fieldSlot = FieldSlot(ins, ae.fieldName)
          val fieldValue = ptaresult.pointsToSet(currentContext, fieldSlot)
          if(fieldValue.isEmpty) {
            val typ = ae.typ
            val newUnknown =
              if(typ.jawaName == "java.lang.String") PTAPointStringInstance(ins.defSite)
              else PTAInstance(typ.toUnknown, ins.defSite)
            result += RFAFact(fieldSlot, newUnknown)
            ptaresult.addInstance(currentContext, fieldSlot, newUnknown)
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = ptaresult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach { ins =>
          val arraySlot = ArraySlot(ins)
          val arrayValue = ptaresult.pointsToSet(currentContext, arraySlot)
          if(arrayValue.isEmpty) {
            val originalType = ins.typ
            val dim = if(originalType.dimensions == 0) 0 else originalType.dimensions - 1
            val newType = new JawaType(originalType.baseType, dim)
            val newUnknown =
              if(newType.jawaName == "java.lang.String") PTAPointStringInstance(ins.defSite)
              else PTAInstance(newType.toUnknown, ins.defSite)
            result += RFAFact(arraySlot, newUnknown)
            ptaresult.addInstance(currentContext, arraySlot, newUnknown)
          }
        }
      case _ =>
    }
    result
  }
  
  def getHeapUnknownFacts(rhs: Expression with RHS, currentContext: Context, ptaresult: PTAResult): ISet[RFAFact] = {
    getHeapUnknownFactsExp(rhs, currentContext, ptaresult)
  }

  def processLHS(lhs: Expression with LHS, currentContext: Context, ptaresult: PTAResult): IMap[PTASlot, Boolean] = {
    val result: MMap[PTASlot, Boolean] = mmapEmpty
    lhs match{
      case vne: VariableNameExpression =>
        val slot = VarSlot(vne.name)
        result(slot) = true
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        result(slot) = true
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue = ptaresult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach { ins =>
          if(ins.isNull) {}
          else{
            if(baseValue.size>1) result(FieldSlot(ins, ae.fieldName)) = false
            else result(FieldSlot(ins, ae.fieldName)) = true
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = ptaresult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach{ ins =>
          result(ArraySlot(ins)) = false
        }
    }
    result.toMap
  }
  
  def processRHS(
      rhs: Expression with RHS,
      currentContext: Context,
      ptaResult: PTAResult): (ISet[Instance], ISet[RFAFact]) = {
    var result: ISet[Instance] = isetEmpty
    var extraFacts: ISet[RFAFact] = isetEmpty
    rhs match{
      case vne: VariableNameExpression =>
        val slot = VarSlot(vne.name)
        val value: ISet[Instance] = ptaResult.pointsToSet(currentContext, slot)
        result ++= value
      case sfae: StaticFieldAccessExpression =>
        val slot = StaticFieldSlot(sfae.name)
        val value: ISet[Instance] = ptaResult.pointsToSet(currentContext, slot)
        result ++= value
      case ce: ConstClassExpression =>
        val classInstance = PTAInstance(JavaKnowledge.CLASS, currentContext)
        val fs = FieldSlot(classInstance, "name")
        val ins = PTAConcreteStringInstance(ce.typExp.typ.name, currentContext)
        extraFacts += RFAFact(fs, ins)
        ptaResult.addInstance(currentContext, fs, ins)
        result += classInstance
      case _: NullExpression =>
        val inst = JavaKnowledge.OBJECT.toUnknown
        val ins = PTAInstance(inst, currentContext)
        val value: ISet[Instance] = Set(ins)
        result ++= value
      case le: LiteralExpression =>
        if(le.isString){
          val ins = PTAConcreteStringInstance(le.getString, currentContext)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        } else if(le.isInt && le.getInt == 0){
          val inst = JavaKnowledge.OBJECT.toUnknown
          val ins = PTAInstance(inst, currentContext)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        }
      case ne: Expression with New =>
        val ins =
          if(ne.typ == new JawaType("java.lang.String")){
            PTAConcreteStringInstance("", currentContext)
          } else {
            PTAInstance(ne.typ, currentContext)
          }
        result += ins
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else {
            val fieldSlot = FieldSlot(ins, ae.fieldName)
            var fieldValue: ISet[Instance] = ptaResult.pointsToSet(currentContext, fieldSlot)
            result ++= fieldValue
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(currentContext, baseSlot)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else {
            val arraySlot = ArraySlot(ins)
            val arrayValue: ISet[Instance] = ptaResult.pointsToSet(currentContext, arraySlot)
            result ++= arrayValue
          }
        }
      case ce: CastExpression =>
        val castTyp = ce.typ.typ
        val insOpt =
          if(castTyp.jawaName == "java.lang.String"){
            Some(PTAPointStringInstance(currentContext))
          } else if (castTyp.isObject) {
            Some(PTAInstance(castTyp, currentContext))
          } else None
        insOpt match {
          case Some(ins) =>
            val slot = VarSlot(ce.varName)
            val value: ISet[Instance] = ptaResult.pointsToSet(currentContext, slot)
            result ++= value.map{ v =>
              if(v.isUnknown){
                PTAInstance(ins.typ.toUnknown, v.defSite)
              } else {
                v
              }
            }
          case _ =>
        }
      case _=>
    }
    (result, extraFacts)
  }

  def isObjectTypeRegAssignment(a: AssignmentStatement): Boolean = {
    a.kind == "object"
  }
  
  def isStaticFieldRead(a: AssignmentStatement): Boolean = {
    var result = false
    if(isObjectTypeRegAssignment(a)) {
      a.rhs match {
        case _: StaticFieldAccessExpression =>
          result = true
        case _ =>
      }
    }
    result
  }
  
  def isStaticFieldWrite(a: AssignmentStatement): Boolean = {
    var result = false
    if(isObjectTypeRegAssignment(a)) {
      a.lhs match {
        case _: StaticFieldAccessExpression =>
          result = true
        case _ =>
      }
    }
    result
  }
}
