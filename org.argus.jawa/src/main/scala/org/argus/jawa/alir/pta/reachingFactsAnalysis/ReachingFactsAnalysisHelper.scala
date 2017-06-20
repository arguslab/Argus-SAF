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
  def getFactMap(s: ISet[RFAFact])(implicit factory: SimHeap): Map[PTASlot, Set[Int]] = {
    s.groupBy(_.slot).mapValues(_.map(_.ins))
  }

  def getHeapFacts(s: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
    s.filter(_.s.isInstanceOf[HeapSlot])
  }

  def getRelatedFactsForArg(slot: VarSlot, s: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
    val bFacts = s.filter(fact=> slot.getId == fact.s.getId).map(fact => RFAFact(slot, fact.ins))
    val rhFacts = getRelatedHeapFactsFrom(bFacts, s)
    bFacts ++ rhFacts
  }

  def getRelatedHeapFactsFrom(fromFacts: ISet[RFAFact], s: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
    val insts = fromFacts.map(f => f.ins)
    getRelatedHeapFacts(insts, s) ++ fromFacts.filter(f => f.slot.isInstanceOf[MapSlot])
  }
  
  def getRelatedHeapFacts(insts: ISet[Int], s: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
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

  def cleanHeap(facts: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
    val root: ISet[RFAFact] = facts.filter { fact => fact.slot.isInstanceOf[NameSlot]}
    root ++ ReachingFactsAnalysisHelper.getRelatedHeapFactsFrom(root, facts)
  }

  def getGlobalFacts(s: ISet[RFAFact])(implicit factory: SimHeap): ISet[RFAFact] = {
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
        Some(PTAInstance(ot, currentContext.copy))
    }
  }
  
  def getReturnFact(rType: JawaType, retVar: String, currentContext: Context)(implicit factory: SimHeap): Option[RFAFact] = {
    getInstanceFromType(rType, currentContext) map(new RFAFact(VarSlot(retVar), _))
  }

  def getUnknownObject(calleeMethod: JawaMethod, s: PTAResult, args: Seq[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact]) = {
    var genFacts: ISet[RFAFact] = isetEmpty
    val killFacts: ISet[RFAFact] = isetEmpty
    val argSlots = args.map(arg=>VarSlot(arg))
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val argValues = s.pointsToSet(after = false, currentContext, argSlot)
      val typ: JawaType = 
        if(!calleeMethod.isStatic && i == 0) calleeMethod.getDeclaringClass.typ
        else if(!calleeMethod.isStatic) calleeMethod.getSignature.getParameterTypes(i - 1)
        else calleeMethod.getSignature.getParameterTypes(i)
      val influencedFields = Set(Constants.ALL_FIELD_FQN(typ))
      argValues.foreach { ins =>
        for(f <- influencedFields) {
          val fs = FieldSlot(ins, f.fieldName)
          val uins = PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext)
          genFacts += new RFAFact(fs, uins)
        }
      }
    }
//    killFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(argValues, s)
    val retTyp = calleeMethod.getReturnType
    retTyp match {
      case ot if ot.isObject =>
        val slot = VarSlot(retVar)
        val value =
          if(retTyp.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
          else PTAInstance(ot.toUnknown, currentContext)
        genFacts += new RFAFact(slot, value)
      case _ =>
    }
    (genFacts, killFacts)
  }

  def getUnknownObject(calleeMethod: JawaMethod, s: ISet[RFAFact], args: Seq[String], retVar: String, currentContext: Context)(implicit factory: SimHeap): (ISet[RFAFact], ISet[RFAFact]) = {
    var genFacts: ISet[RFAFact] = isetEmpty
    val killFacts: ISet[RFAFact] = isetEmpty
    val argSlots = args.map(arg=>VarSlot(arg))
    for(i <- argSlots.indices){
      val argSlot = argSlots(i)
      val argValues = s.filter(f => f.s == argSlot).map(_.v)
      val typ: JawaType =
        if(!calleeMethod.isStatic && i == 0) calleeMethod.getDeclaringClass.typ
        else if(!calleeMethod.isStatic) calleeMethod.getSignature.getParameterTypes(i - 1)
        else calleeMethod.getSignature.getParameterTypes(i)
      val influencedFields = Set(Constants.ALL_FIELD_FQN(typ))
      argValues.foreach { ins =>
        for(f <- influencedFields) {
          val fs = FieldSlot(ins, f.fieldName)
          val uins = PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext)
          genFacts += new RFAFact(fs, uins)
        }
      }
    }
    //    killFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(argValues, s)
    val retTyp = calleeMethod.getReturnType
    retTyp match {
      case ot if ot.isObject =>
        val slot = VarSlot(retVar)
        val value =
          if(retTyp.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
          else PTAInstance(ot.toUnknown, currentContext)
        genFacts += new RFAFact(slot, value)
      case _ =>
    }
    (genFacts, killFacts)
  }

  def getUnknownObjectForClinit(calleeMethod: JawaMethod, currentContext: Context)(implicit factory: SimHeap): ISet[RFAFact] = {
    var result: ISet[RFAFact] = isetEmpty
    val record = calleeMethod.getDeclaringClass
    record.getDeclaredStaticObjectTypeFields.foreach{
      field =>
        result += new RFAFact(StaticFieldSlot(field.FQN.fqn), PTAInstance(field.getType.toUnknown, currentContext))
    }
    result
  }

  def updatePTAResultVar(varName: String, currentContxt: Context, s: ISet[RFAFact], ptaresult: PTAResult, after: Boolean)(implicit factory: SimHeap): Unit = {
    val slot = VarSlot(varName)
    s.filter { fact =>
      fact.s == slot
    }.foreach(f => ptaresult.addInstance(after, currentContxt, slot, f.v))
  }

  def updatePTAResultLHS(lhs: Expression with LHS, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap): Unit = {
    lhs match {
      case _: NameExpression =>
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach { ins =>
          ptaresult.addInstance(after = false, currentContext, baseSlot, ins)
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach { ins =>
          ptaresult.addInstance(after = false, currentContext, baseSlot, ins)
        }
      case _ =>
    }
  }

  private def resolvePTAResultAccessExp(ae: AccessExpression, typ: JawaType, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap) = {
    val baseSlot = VarSlot(ae.base)
    val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map{ f =>
      ptaresult.addInstance(after = false, currentContext, baseSlot, f.v)
      f.v
    }
    baseValue.foreach{ ins =>
      if(ins.isNull){}
      else {
        val fieldSlot = FieldSlot(ins, ae.fieldName)
        s.filter { fact => fact.s == fieldSlot }.foreach(f => ptaresult.addInstance(after = false, currentContext, fieldSlot, f.v))
        s.foreach { fact =>
          fact.s match {
            case slot: FieldSlot if slot.ins == ins && slot.fieldName == Constants.ALL_FIELD && typ.isObject =>
              val uIns = PTAInstance(typ.toUnknown, fact.v.defSite)
              ptaresult.addInstance(after = false, currentContext, fieldSlot, uIns)
            case _ =>
          }
        }
      }
    }
  }

  private def resolvePTAResultIndexingExp(ie: IndexingExpression, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap) = {
    val baseSlot = VarSlot(ie.base)
    val baseValue: ISet[Instance] = s.filter { fact => fact.s.getId == baseSlot.getId }.map{ f =>
      ptaresult.addInstance(after = false, currentContext, baseSlot, f.v)
      f.v
    }
    baseValue.foreach{ ins =>
      if(ins.isNull){}
      else if(ins.isUnknown){
        val arraySlot = ArraySlot(ins)
        val temp = s.filter { fact => fact.s == arraySlot }.map{ f =>
          ptaresult.addInstance(after = false, currentContext, arraySlot, f.v)
          f.v
        }
        if(temp.isEmpty){
          if(!(JavaKnowledge.isJavaPrimitive(ins.typ.baseTyp) && ins.typ.dimensions <= 1)) {
            val uIns = PTAInstance(JawaType(ins.typ.baseType, ins.typ.dimensions - 1), currentContext)
            ptaresult.addInstance(after = false, currentContext, arraySlot, uIns)
          }
        }
      }
      else{
        val arraySlot = ArraySlot(ins)
        s.filter { fact => fact.s == arraySlot }.foreach(f => ptaresult.addInstance(after = false, currentContext, arraySlot, f.v))
      }
    }
  }

  def updatePTAResultRHS(rhs: Expression with RHS, typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap): Unit = {
    updatePTAResultExp(rhs, typ, currentContext, s, ptaresult)
  }

  def updatePTAResultCallJump(cs: CallStatement, callerContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap): Unit = {
    (cs.recvOpt ++ cs.args).foreach(updatePTAResultCallArg(_, callerContext, s, ptaresult))
  }

  def updatePTAResultExp(exp: Expression, typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap): Unit = {
    exp match{
      case be: BinaryExpression =>
        val slotlhs = VarSlot(be.left.varName)
        s.filter { fact => fact.s == slotlhs }.foreach{ f =>
          ptaresult.addInstance(after = false, currentContext, slotlhs, f.v)
        }
        be.right match {
          case Left(r) =>
            val slotrhs = VarSlot(r.varName)
            s.filter { fact => fact.s == slotrhs }.foreach{ f =>
              ptaresult.addInstance(after = false, currentContext, slotrhs, f.v)
            }
          case Right(_) =>
        }
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ)
        slot match {
          case ss: StaticFieldSlot =>
            s.filter { fact => fact.s == ss }.foreach(f => ptaresult.addInstance(after = false, currentContext, ss, f.v))
          case vs: VarSlot =>
            s.filter { fact => fact.s == vs }.foreach(f => ptaresult.addInstance(after = false, currentContext, slot, f.v))
          case _ =>
        }
//      case ce: ConstClassExpression =>
//        val slot = ClassSlot(ce.typExp.typ)
//        val ci = ClassInstance(ce.typExp.typ, currentContext)
//        ptaresult.addInstance(slot, currentContext, ci)
      case ae: AccessExpression =>
        resolvePTAResultAccessExp(ae, typ.get, currentContext, s, ptaresult)
      case ie: IndexingExpression =>
        resolvePTAResultIndexingExp(ie, currentContext, s, ptaresult)
      case ce: CastExpression =>
        val slot = VarSlot(ce.varName)
        s.filter { fact => fact.s == slot }.foreach{ f =>
          ptaresult.addInstance(after = false, currentContext, slot, f.v)
        }
      case _=>
    }
  }

  private def updatePTAResultCallArg(arg: String, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: SimHeap): Unit = {
    val slot = VarSlot(arg)
    getRelatedFactsForArg(slot, s).foreach(f => ptaresult.addInstance(after = false, currentContext, f.s, f.v))
  }
  
  private def getHeapUnknownFactsExp(exp: Expression, currentContext: Context, ptaresult: PTAResult)(implicit factory: SimHeap): ISet[RFAFact] = {
    val result: MSet[RFAFact] = msetEmpty
    exp match {
      case _: AccessExpression =>
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = ptaresult.pointsToSet(after = false, currentContext, baseSlot)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else if(ins.isUnknown){
            val arraySlot = ArraySlot(ins)
            val arrayValue = ptaresult.pointsToSet(after = false, currentContext, arraySlot)
            arrayValue.foreach{ ins =>
              if(ins.isUnknown) result += new RFAFact(arraySlot, ins)
            }
          }
        }
      case _ =>
    }
    result.toSet
  }
  
  def getHeapUnknownFacts(rhs: Expression with RHS, currentContext: Context, ptaresult: PTAResult)(implicit factory: SimHeap): ISet[RFAFact] = {
    getHeapUnknownFactsExp(rhs, currentContext, ptaresult)
  }

  def processLHS(lhs: Expression with LHS, typ: Option[JawaType], currentContext: Context, ptaresult: PTAResult): IMap[PTASlot, Boolean] = {
    val result: MMap[PTASlot, Boolean] = mmapEmpty
    lhs match{
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ)
        result(slot) = true
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue = ptaresult.pointsToSet(after = false, currentContext, baseSlot)
        baseValue.foreach { ins =>
          if(ins.isNull) {}
          else{
            if(baseValue.size>1) result(FieldSlot(ins, ae.fieldName)) = false
            else result(FieldSlot(ins, ae.fieldName)) = true
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue = ptaresult.pointsToSet(after = false, currentContext, baseSlot)
        baseValue.foreach{ ins =>
          result(ArraySlot(ins)) = false
        }
      case cl: CallLhs =>
        val slot = VarSlot(cl.lhs.varName)
        result(slot) = true
    }
    result.toMap
  }
  
  def processRHS(rhs: Expression with RHS, typ: Option[JawaType], currentContext: Context, ptaResult: PTAResult): ISet[Instance] = {
    val result: MSet[Instance] = msetEmpty
    rhs match{
      case ne: NameExpression =>
        val slot = getNameSlotFromNameExp(ne, typ)
        val value: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, slot)
        result ++= value
      case ce: ConstClassExpression =>
        result += ClassInstance(ce.typExp.typ, currentContext)
      case _: NullExpression =>
        val inst = if(typ.get.isArray) typ.get else typ.get.toUnknown
        val ins = PTAInstance(inst, currentContext)
        val value: ISet[Instance] = Set(ins)
        result ++= value
      case le: LiteralExpression =>
        if(le.isString){
          val ins = PTAConcreteStringInstance(le.getString, currentContext)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        } else if(le.isInt && le.getInt == 0){
          val inst = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown
          val ins = PTAInstance(inst, currentContext)
          val value: ISet[Instance] = Set(ins)
          result ++= value
        }
      case ne: NewExpression =>
        val ins =
          if(ne.typ == new JawaType("java.lang.String")){
            PTAConcreteStringInstance("", currentContext.copy)
          } else {
            PTAInstance(ne.typ, currentContext.copy)
          }
        result += ins
      case ae: AccessExpression =>
        val baseSlot = VarSlot(ae.base)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, baseSlot)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else {
            val fieldSlot = FieldSlot(ins, ae.fieldName)
            var fieldValue: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, fieldSlot)
            if(ins.isUnknown && typ.get.isObject) {
              fieldValue += PTAInstance(typ.get.toUnknown, currentContext)
            }
            result ++= fieldValue
          }
        }
      case ie: IndexingExpression =>
        val baseSlot = VarSlot(ie.base)
        val baseValue: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, baseSlot)
        baseValue.foreach{ ins =>
          if(ins.isNull){}
          else if(ins.isUnknown){
            val arraySlot = ArraySlot(ins)
            val arrayValue: MSet[Instance] = msetEmpty
            arrayValue ++= ptaResult.pointsToSet(after = false, currentContext, arraySlot)
            val originalType = ins.typ
            val dim = if(originalType.dimensions == 0) 0 else originalType.dimensions - 1
            val newType = JawaType(originalType.baseType, dim)
            val newUnknown =
              if(newType.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
              else PTAInstance(newType.toUnknown, currentContext)
            arrayValue += newUnknown
            result ++= arrayValue.toSet
          } else {
            val arraySlot = ArraySlot(ins)
            val arrayValue: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, arraySlot)
            result ++= arrayValue
          }
        }
      case ce: CastExpression =>
        val castTyp = ce.typ.typ
        val insOpt =
          if(castTyp.jawaName == "java.lang.String"){
            Some(PTAPointStringInstance(currentContext.copy))
          } else if (castTyp.isObject) {
            Some(PTAInstance(castTyp, currentContext.copy))
          } else None
        insOpt match {
          case Some(ins) =>
            val slot = VarSlot(ce.varName)
            val value: ISet[Instance] = ptaResult.pointsToSet(after = false, currentContext, slot)
            result ++= value.map{ v =>
              if(v.isUnknown){
                PTAInstance(ins.typ.toUnknown, v.defSite.copy)
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
  
  def getNameSlotFromNameExp(ne: NameExpression, typ: Option[JawaType]): NameSlot = {
    val name = ne.name
    if(ne.isStatic){
      val fqn = new FieldFQN(ne.name, typ.get)
      StaticFieldSlot(fqn.fqn)
    }
    else VarSlot(name)
  }
}
