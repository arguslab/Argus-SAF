/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.alir.pta.reachingFactsAnalysis

import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.Context
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ReachingFactsAnalysisHelper {
  final val TITLE = "ReachingFactsAnalysisHelper"
  def getFactMap(s: ISet[RFAFact])(implicit factory: RFAFactFactory): Map[PTASlot, Set[Int]] = {
    s.groupBy(_.slot).mapValues(_.map(_.ins))
  }

  def getHeapFacts(s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    s.filter(_.s.isInstanceOf[HeapSlot])
  }

  def getRelatedFactsForArg(slot: VarSlot, s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val bFacts = s.filter(fact=> slot.getId == fact.s.getId).map(fact => RFAFact(slot, fact.ins))
    val rhFacts = getRelatedHeapFactsFrom(bFacts, s)
    bFacts ++ rhFacts
  }

  def getRelatedHeapFactsFrom(fromFacts: ISet[RFAFact], s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val insts = fromFacts.map(f => f.ins)
    getRelatedHeapFacts(insts, s)
  }
  
  def getRelatedHeapFacts(insts: ISet[Int], s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val hs = getHeapFacts(s)
    var processed: ISet[Int] = isetEmpty
    var result: ISet[RFAFact] = isetEmpty
    val worklist = new WorklistAlgorithm[Int] {
      override def processElement(ins: Int): Unit = {
        processed += ins
        val facts = hs.filter(_.s.asInstanceOf[HeapSlot].matchWithInstance(factory.getInstance(ins)))
        result ++= facts
        worklist = facts.map { case RFAFact(_, v) => v }.diff(processed) ++: worklist
      }
    }
    worklist.run(worklist.worklist = insts.toList)
    result
  }

  def getGlobalFacts(s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
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

  def getInstanceFromType(typ: JawaType, currentContext: Context): Option[Instance] = {
    typ match{
      case pt if pt.isPrimitive => None
      case ot if ot.jawaName == "java.lang.String" =>
        Some(PTAPointStringInstance(currentContext.copy))
      case ot if ot.isObject =>
        Some(PTAInstance(ot, currentContext.copy, isNull_ = false))
    }
  }
  
  def getReturnFact(rType: JawaType, retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): Option[RFAFact] = {
    getInstanceFromType(rType, currentContext) map(new RFAFact(VarSlot(retVar, isBase = false, isArg = false), _))
  }

  def getUnknownObject(calleeMethod: JawaMethod, s: PTAResult, args: Seq[String], retVar: String, currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
    var genFacts: ISet[RFAFact] = isetEmpty
    val killFacts: ISet[RFAFact] = isetEmpty
    val argSlots = args.map(arg=>VarSlot(arg, isBase = false, isArg = true))
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val argValues = s.pointsToSet(argSlot, currentContext)
      val typ: JawaType = 
        if(!calleeMethod.isStatic && i == 0) calleeMethod.getDeclaringClass.typ
        else if(!calleeMethod.isStatic) calleeMethod.getSignature.getParameterTypes(i - 1)
        else calleeMethod.getSignature.getParameterTypes(i)
      val influencedFields = Set(Constants.ALL_FIELD_FQN(typ))
      argValues.foreach { ins =>
        for(f <- influencedFields) {
          val fs = FieldSlot(ins, f.fieldName)
          val uins = PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext, isNull_ = false)
          genFacts += new RFAFact(fs, uins)
        }
      }
    }
//    killFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(argValues, s)
    val retTyp = calleeMethod.getReturnType
    retTyp match {
      case ot if ot.isObject =>
        val slot = VarSlot(retVar, isBase = false, isArg = false)
        val value =
          if(retTyp.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
          else PTAInstance(ot.toUnknown, currentContext, isNull_ = false)
        genFacts += new RFAFact(slot, value)
      case _ =>
    }
    (genFacts, killFacts)
  }

  def getUnknownObjectForClinit(calleeMethod: JawaMethod, currentContext: Context)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    val record = calleeMethod.getDeclaringClass
    record.getDeclaredStaticObjectTypeFields.foreach{
      field =>
        result += new RFAFact(StaticFieldSlot(field.FQN), PTAInstance(field.getType.toUnknown, currentContext, isNull_ = false))
    }
    result
  }
  
  def updatePTAResultLHS(lhs: Expression with LHS, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    lhs match {
      case _: NameExpression =>
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base, isBase = true, isArg = false)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach {
          ins =>
            ptaresult.addInstance(baseSlot, currentContext, ins)
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base, isBase = true, isArg = false)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach {
          ins =>
            ptaresult.addInstance(baseSlot, currentContext, ins)
        }
      case _ =>
    }
  }
  
  private def resolvePTAResultAccessExp(ae: AccessExpression, typ: JawaType, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory) = {
    val baseSlot = VarSlot(ae.base, isBase = true, isArg = false)
    val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map{ f =>
      ptaresult.addInstance(baseSlot, currentContext, f.v)
      f.v
    }
    baseValue.foreach{ ins =>
      if(ins.isNull){}
      else {
        val fieldSlot = FieldSlot(ins, ae.fieldName)
        s.filter { fact => fact.s == fieldSlot }.foreach(f => ptaresult.addInstance(fieldSlot, currentContext, f.v))
        s.foreach { fact =>
          fact.s match {
            case slot: FieldSlot if slot.ins == ins && slot.fieldName == Constants.ALL_FIELD && typ.isObject =>
              val definingTyp = typ
              val defCls = global.getClassOrResolve(definingTyp)
              if (defCls.hasField(ae.fieldName)) {
                val uIns = PTAInstance(typ.toUnknown, fact.v.defSite, isNull_ = false)
                ptaresult.addInstance(fieldSlot, currentContext, uIns)
              }
            case _ =>
          }
        }
      }
    }
  }
  
  private def resolvePTAResultIndexingExp(ie: IndexingExpression, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory) = {
    val baseSlot = VarSlot(ie.base, isBase = true, isArg = false)
    val baseValue: ISet[Instance] = s.filter { fact => fact.s.getId == baseSlot.getId }.map{
      f => 
        ptaresult.addInstance(baseSlot, currentContext, f.v)
        f.v
    }
    baseValue.foreach{
      ins =>
        if(ins.isNull){}
        else if(ins.isUnknown){
          val arraySlot = ArraySlot(ins)
          val temp = s.filter { fact => fact.s == arraySlot }.map{
            f => 
              ptaresult.addInstance(arraySlot, currentContext, f.v)
              f.v
          }
          if(temp.isEmpty){
            if(!(JavaKnowledge.isJavaPrimitive(ins.typ.baseTyp) && ins.typ.dimensions <= 1)) {
              val uIns = PTAInstance(JawaType(ins.typ.baseType, ins.typ.dimensions - 1), currentContext, isNull_ = false)
              ptaresult.addInstance(arraySlot, currentContext, uIns)
            }
          }
        }
        else{
          val arraySlot = ArraySlot(ins)
          s.filter { fact => fact.s == arraySlot }.foreach(f => ptaresult.addInstance(arraySlot, currentContext, f.v))
        }
    }
  }
  
  def updatePTAResultRHS(rhs: Expression with RHS, typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory): Unit = {
    updatePTAResultExp(rhs, typ, currentContext, s, ptaresult, global)
  }
  
  def updatePTAResultCallJump(cs: CallStatement, callerContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    (cs.recvOpt ++ cs.args).foreach(updatePTAResultCallArg(_, callerContext, s, ptaresult))
  }
  
  def updatePTAResultExp(exp: Expression, typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory): Unit = {
    exp match{
      case be: BinaryExpression =>
        val slotlhs = VarSlot(be.left.varName, isBase = false, isArg = false)
        s.filter { fact => fact.s == slotlhs }.foreach{
          f =>
            ptaresult.addInstance(slotlhs, currentContext, f.v)
        }
        be.right match {
          case Left(r) =>
            val slotrhs = VarSlot(r.varName, isBase = false, isArg = false)
            s.filter { fact => fact.s == slotrhs }.foreach{
              f =>
                ptaresult.addInstance(slotrhs, currentContext, f.v)
            }
          case Right(_) =>
        }
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
        slot match {
          case ss: StaticFieldSlot =>
            s.filter { fact => fact.s == ss }.foreach(f => ptaresult.addInstance(ss, currentContext, f.v))
          case vs: VarSlot =>
            s.filter { fact => fact.s == vs }.foreach(f => ptaresult.addInstance(slot, currentContext, f.v))
          case _ =>
        }
//      case ce: ConstClassExpression =>
//        val slot = ClassSlot(ce.typExp.typ)
//        val ci = ClassInstance(ce.typExp.typ, currentContext)
//        ptaresult.addInstance(slot, currentContext, ci)
      case ae: AccessExpression =>
        resolvePTAResultAccessExp(ae, typ.get, currentContext, s, ptaresult, global)
      case ie: IndexingExpression =>
        resolvePTAResultIndexingExp(ie, currentContext, s, ptaresult)
      case ce: CastExpression =>
        val slot = VarSlot(ce.varName, isBase = false, isArg = false)
        s.filter { fact => fact.s == slot }.foreach{
          f =>
            ptaresult.addInstance(slot, currentContext, f.v)
        }
      case _=>
    }
  }
  
  def updatePTAResultCallArg(arg: String, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    val slot = VarSlot(arg, isBase = false, isArg = true)
    getRelatedFactsForArg(slot, s).foreach(f => ptaresult.addInstance(f.s, currentContext, f.v))
  }
  
  private def getHeapUnknownFactsExp(exp: Expression, currentContext: Context, ptaresult: PTAResult)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val result: MSet[RFAFact] = msetEmpty
    exp match {
      case _: AccessExpression =>
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base, isBase = true, isArg = false)
        val baseValue = ptaresult.pointsToSet(baseSlot, currentContext)
        baseValue.foreach{
          ins =>
            if(ins.isNull){}
            else if(ins.isUnknown){
              val arraySlot = ArraySlot(ins)
              val arrayValue = ptaresult.pointsToSet(arraySlot, currentContext)
              arrayValue.foreach{
                ins =>
                  if(ins.isUnknown) result += new RFAFact(arraySlot, ins)
              }
            }
        }
      case _ =>
    }
    result.toSet
  }
  
  def getHeapUnknownFacts(rhs: Expression with RHS, currentContext: Context, ptaresult: PTAResult)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    getHeapUnknownFactsExp(rhs, currentContext, ptaresult)
  }

  def processLHS(lhs: Expression with LHS, typ: Option[JawaType], currentContext: Context, ptaresult: PTAResult, global: Global): IMap[PTASlot, Boolean] = {
    val result: MMap[PTASlot, Boolean] = mmapEmpty
    lhs match{
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
        result(slot) = true
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base, isBase = true, isArg = false)
        val baseValue = ptaresult.pointsToSet(baseSlot, currentContext)
        baseValue.foreach { ins =>
          if(ins.isNull) {}
          else{
            if(baseValue.size>1) result(FieldSlot(ins, ae.fieldName)) = false
            else result(FieldSlot(ins, ae.fieldName)) = true
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base, isBase = true, isArg = false)
        val baseValue = ptaresult.pointsToSet(baseSlot, currentContext)
        baseValue.foreach{
          ins =>
            result(ArraySlot(ins)) = false
        }
      case cl: CallLhs =>
        val slot = VarSlot(cl.lhs.varName, isBase = false, isArg = false)
        result(slot) = true
    }
    result.toMap
  }
  
  def processRHS(rhs: Expression with RHS, typ: Option[JawaType], currentContext: Context, ptaResult: PTAResult, global: Global): ISet[Instance] = {
    val result: MSet[Instance] = msetEmpty
    rhs match{
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
        val value: ISet[Instance] = ptaResult.pointsToSet(slot, currentContext)
        result ++= value
      case ce: ConstClassExpression =>
        result += ClassInstance(ce.typExp.typ, currentContext)
      case _: NullExpression =>
        val inst = if(typ.get.isArray) typ.get else typ.get.toUnknown
        val ins = PTAInstance(inst, currentContext, isNull_ = true)
        val value: ISet[Instance] = Set(ins)
        result ++= value
      case le: LiteralExpression =>
        if(le.isString){
          val ins = PTAConcreteStringInstance(le.getString, currentContext)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        } else if(le.isInt && le.getInt == 0){
          val inst = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown
          val ins = PTAInstance(inst, currentContext, isNull_ = true)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        }
      case ne: NewExpression =>
        val ins =
          if(ne.typ == new JawaType("java.lang.String")){
            PTAConcreteStringInstance("", currentContext.copy)
          } else {
            PTAInstance(ne.typ, currentContext.copy, isNull_ = false)
          }
        result += ins
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base, isBase = true, isArg = false)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(baseSlot, currentContext)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else {
            val fieldSlot = FieldSlot(ins, ae.fieldName)
            var fieldValue: ISet[Instance] = ptaResult.pointsToSet(fieldSlot, currentContext)
            if(ins.isUnknown && typ.get.isObject) {
              fieldValue += PTAInstance(typ.get.toUnknown, currentContext, isNull_ = false)
            }
            result ++= fieldValue
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base, isBase = true, isArg = false)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(baseSlot, currentContext)
        baseValue.foreach{
          ins =>
            if(ins.isNull){}
            else if(ins.isUnknown){
              val arraySlot = ArraySlot(ins)
              val arrayValue: MSet[Instance] = msetEmpty
              arrayValue ++= ptaResult.pointsToSet(arraySlot, currentContext)
              val originalType = ins.typ
              val dim = if(originalType.dimensions == 0) 0 else originalType.dimensions - 1
              val newType = JawaType(originalType.baseType, dim)
              val newUnknown =
                if(newType.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
                else PTAInstance(newType.toUnknown, currentContext, isNull_ = false)
              arrayValue += newUnknown
              result ++= arrayValue.toSet
            } else {
              val arraySlot = ArraySlot(ins)
              val arrayValue: ISet[Instance] = ptaResult.pointsToSet(arraySlot, currentContext)
              result ++= arrayValue
            }
        }
      case ce: CastExpression =>
        val castTyp = ce.typ.typ
        val insOpt =
          if(castTyp.jawaName == "java.lang.String"){
            Some(PTAPointStringInstance(currentContext.copy))
          } else if (castTyp.isObject) {
            Some(PTAInstance(castTyp, currentContext.copy, isNull_ = false))
          } else None
        insOpt match {
          case Some(ins) =>
            val slot = VarSlot(ce.varName, isBase = false, isArg = false)
            val value: ISet[Instance] = ptaResult.pointsToSet(slot, currentContext)
            result ++= value.map{
              v =>
                if(v.isUnknown){
                  PTAInstance(ins.typ.toUnknown, v.defSite.copy, isNull_ = false)
                } else {
                  v
                }
            }
          case _ =>
        }
      case _=>
    }
    result.toSet
  }

  def isObjectTypeRegAssignment(a: AssignmentStatement): Boolean = {
    a.kind == "object"
  }
  
  def isStaticFieldRead(a: AssignmentStatement): Boolean = {
    var result = false
    if(isObjectTypeRegAssignment(a)) {
      a.rhs match {
        case ne: NameExpression =>
          result = ne.isStatic
        case _ =>
      }
    }
    result
  }
  
  def isStaticFieldWrite(a: AssignmentStatement): Boolean = {
    var result = false
    if(isObjectTypeRegAssignment(a)) {
      a.lhs match {
        case ne: NameExpression =>
          result = ne.isStatic
        case _ =>
      }
    }
    result
  }
  
  def getNameSlotFromNameExp(ne: NameExpression, typ: Option[JawaType], isBase: Boolean, isArg: Boolean, global: Global): NameSlot = {
    val name = ne.name
    if(ne.isStatic){
      val fqn = new FieldFQN(ne.name, typ.get)
      global.getClassOrResolve(fqn.owner).getField(fqn.fieldName, fqn.typ) match{
        case Some(af) =>
          StaticFieldSlot(af.FQN)
        case None =>
          StaticFieldSlot(fqn)
      }
    }
    else VarSlot(name, isBase, isArg)
  }
}
