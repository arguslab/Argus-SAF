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

import org.argus.jawa.alir.interprocedural.{Callee, InstanceCallee, StaticCallee, UnknownCallee}
import org.argus.jawa.alir.pta._
import org.argus.jawa.alir.util.CallHandler
import org.argus.jawa.alir.{Context, LibSideEffectProvider}
import org.argus.jawa.core._
import org.argus.jawa.core.util.{ASTUtil, WorklistAlgorithm}
import org.sireum.pilar.ast._
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object ReachingFactsAnalysisHelper {
  final val TITLE = "ReachingFactsAnalysisHelper"
  def getFactMap(s: ISet[RFAFact])(implicit factory: RFAFactFactory): Map[Int, Set[Int]] = {
    s.groupBy(_.slot).mapValues(_.map(_.ins))
  }

  def getHeapFacts(s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    s.filter(_.s.isInstanceOf[HeapSlot])
  }

  def getRelatedFactsForArg(slot: VarSlot, s: ISet[RFAFact])(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val bFacts = s.filter(fact=> slot.getId == fact.s.getId).map(fact => RFAFact(factory.getSlotNum(slot), fact.ins))
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
        worklist.pushAll(facts.map { case RFAFact(_, v) => v }.diff(processed))
      }
    }
    worklist.run(worklist.worklist.pushAll(insts))
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
  
  private def getInstancesOfArg(ce: CallExp, i: Int, callerContext: Context, ptaresult: PTAResult): ISet[Instance] = {
    val value: MSet[Instance] = msetEmpty
    ce.arg match {
      case te: TupleExp =>
        te.exps(i) match{
          case ne: NameExp =>
            val s = VarSlot(ne.name.name, isBase = false, isArg = true)
            value ++= ptaresult.pointsToSet(s, callerContext)
          case _ =>
        }
      case _ =>
    }
    value.toSet
  }

  def getCalleeSet(global: Global, cj: CallJump, sig: Signature, callerContext: Context, ptaresult: PTAResult): ISet[Callee] = {
    val subSig = sig.getSubSignature
    val typ = cj.getValueAnnotation("kind") match {
      case Some(s) => s match {
        case ne: NameExp => ne.name.name
        case _ => ""
      }
      case None => throw new RuntimeException("cannot found annotation 'kind' from: " + cj)
    }
    val calleeSet = msetEmpty[Callee]
    typ match {
      case "virtual" | "interface" | "super" | "direct" =>
        val recvValue: ISet[Instance] = getInstancesOfArg(cj.callExp, 0, callerContext, ptaresult)
        def handleUnknown(typ: JawaType) = {
//          val ps = CallHandler.getUnknownVirtualCalleeMethods(global, typ, subSig)
          try{
            val unknown = global.getClassOrResolve(typ)
            val unknown_base = global.getClassOrResolve(typ.removeUnknown())
            val c2 = global.getClassOrResolve(sig.classTyp)
            val actc = if(c2.isInterface || unknown_base.isChildOf(c2.getType)) unknown else c2
            calleeSet ++= actc.getMethod(subSig).map(m => UnknownCallee(m.getSignature))
          } catch {
            case ie: InterruptedException => throw ie
            case e: Exception =>
          }
        }
        recvValue.foreach{
          ins =>
            if(!ins.isNull)
              if(typ == "super"){
                calleeSet ++= CallHandler.getSuperCalleeMethod(global, sig).map(m => InstanceCallee(m.getSignature, ins))
              } else if(typ == "direct"){
                calleeSet ++= CallHandler.getDirectCalleeMethod(global, sig).map(m => InstanceCallee(m.getSignature, ins))
              } else {
                if(ins.isUnknown){
                  handleUnknown(ins.typ)
                } else {
                  CallHandler.getVirtualCalleeMethod(global, ins.typ, subSig).map(m => InstanceCallee(m.getSignature, ins)) match {
                    case Some(c) => calleeSet += c
                    case None =>
                      handleUnknown(ins.typ)
                  }
                }
              }
        }
        if(recvValue.isEmpty) {
          handleUnknown(sig.getClassType.toUnknown)
        }
      case "static" =>
        calleeSet ++= CallHandler.getStaticCalleeMethod(global, sig).map(m => StaticCallee(m.getSignature))
      case _ => 
    }
    calleeSet.toSet
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

  def getUnknownObject(calleeMethod: JawaMethod, s: PTAResult, args: Seq[String], retVars: Seq[String], currentContext: Context)(implicit factory: RFAFactFactory): (ISet[RFAFact], ISet[RFAFact]) = {
//    val global = calleeMethod.getDeclaringClass.global
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
      val influencedFields = 
        if(LibSideEffectProvider.isDefined)
          LibSideEffectProvider.getInfluencedFields(i, calleeMethod.getSignature)
        else Set(typ.name + ":" + Constants.ALL_FIELD)
      argValues.foreach {
        ins => 
          for(f <- influencedFields) {
            val fs = FieldSlot(ins, f)
            val uins = PTAInstance(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE.toUnknown, currentContext, isNull_ = false)
            genFacts += new RFAFact(fs, uins)
          }
      }
    }
//    killFacts ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(argValues, s)
    val retTyp = calleeMethod.getReturnType
    retTyp match {
      case ot if ot.isObject =>
        retVars.foreach {
          retVar =>
            val slot = VarSlot(retVar, isBase = false, isArg = false)
            val value = 
              if(retTyp.jawaName == "java.lang.String") PTAPointStringInstance(currentContext)
              else PTAInstance(ot.toUnknown, currentContext, isNull_ = false)
            genFacts += new RFAFact(slot, value)
        }
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
  
  def updatePTAResultLHSs(lhss: Seq[Exp], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    lhss.foreach {
      case ne: NameExp =>
      case ae: AccessExp =>
//        val fieldSig = ae.attributeName.name
        val baseSlot = ae.exp match {
          case ne: NameExp => VarSlot(ne.name.name, isBase = true, isArg = false)
          case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
        }
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach {
          ins =>
            ptaresult.addInstance(baseSlot, currentContext, ins)
        }
      case ie: IndexingExp =>
        val baseSlot = ie.exp match {
          case ine: NameExp =>
            VarSlot(ine.name.name, isBase = true, isArg = false)
          case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
        }
        val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map(_.v)
        baseValue.foreach {
          ins =>
            ptaresult.addInstance(baseSlot, currentContext, ins)
        }
      case _ =>
    }
  }
  
  private def resolvePTAResultAccessExp(ae: AccessExp, typ: JawaType, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory) = {
    val fqn = ASTUtil.getFieldFQN(ae, typ)
    val baseSlot = ae.exp match {
      case ne: NameExp => VarSlot(ne.name.name, isBase = true, isArg = false)
      case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
    }
    val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map{
      f => 
        ptaresult.addInstance(baseSlot, currentContext, f.v)
        f.v
    }
    baseValue.foreach{
      ins =>
        if(ins.isNull){} //TODO show null error message.
        else {
          val fName = fqn.fieldName
          val fieldSlot = FieldSlot(ins, fName)
          s.filter { fact => fact.s == fieldSlot }.foreach(f => ptaresult.addInstance(fieldSlot, currentContext, f.v))
          s.foreach {
            fact =>
              fact.s match {
                case slot: FieldSlot if slot.ins == ins && slot.fieldName.contains(Constants.ALL_FIELD) && fqn.typ.isObject =>
                  val definingTypName = slot.fieldName.split(":")(0)
                  val defCls = global.getClassOrResolve(new JawaType(definingTypName))
                  if (defCls.hasField(fName)) {
                    val uIns = PTAInstance(fqn.typ.toUnknown, fact.v.defSite, isNull_ = false)
                    ptaresult.addInstance(fieldSlot, currentContext, uIns)
                  }
                case _ =>
              }
          }
        }
    }
  }
  
  private def resolvePTAResultIndexingExp(ie: IndexingExp, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory) = {
    val baseSlot = ie.exp match {
      case ine: NameExp =>
        VarSlot(ine.name.name, isBase = true, isArg = false)
      case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
    }
    val baseValue = s.filter { fact => fact.s.getId == baseSlot.getId }.map{
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
  
  def updatePTAResultRHSs(rhss: List[Exp], typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory): Unit = {
    rhss.foreach{
      rhs=>
        updatePTAResultExp(rhs, typ, currentContext, s, ptaresult, global)
    }
  }
  
  def updatePTAResultCallJump(cj: CallJump, callerContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    cj.callExp.arg match{
      case te: TupleExp => 
        te.exps foreach(updatePTAResultCallArg(_, callerContext, s, ptaresult))
      case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
    }
  }
  
  def updatePTAResultExp(exp: Exp, typ: Option[JawaType], currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult, global: Global)(implicit factory: RFAFactFactory): Unit = {
    exp match{
      case be: BinaryExp =>
        updatePTAResultExp(be.left, typ, currentContext, s, ptaresult, global)
        updatePTAResultExp(be.right, typ, currentContext, s, ptaresult, global)
      case ne: NameExp =>
        val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
        slot match {
          case cs: ClassSlot => 
            val ci = ClassInstance(typ.get, currentContext)
            ptaresult.addInstance(cs, currentContext, ci)
          case ss: StaticFieldSlot =>
            s.filter { fact => fact.s == ss }.foreach(f => ptaresult.addInstance(ss, currentContext, f.v))
          case vs: VarSlot =>
            s.filter { fact => fact.s == vs }.foreach(f => ptaresult.addInstance(slot, currentContext, f.v))
        }
      case ae: AccessExp =>
        resolvePTAResultAccessExp(ae, typ.get, currentContext, s, ptaresult, global)
      case ie: IndexingExp =>
        resolvePTAResultIndexingExp(ie, currentContext, s, ptaresult)
      case ce: CastExp =>
        ce.exp match{
          case ice: NameExp =>
            val slot = VarSlot(ice.name.name, isBase = false, isArg = false)
            s.filter { fact => fact.s == slot }.foreach{
              f => 
                ptaresult.addInstance(slot, currentContext, f.v)
            }
          case nle: NewListExp =>
            System.err.println(TITLE, "NewListExp: " + nle)
          case _ => throw new RuntimeException("Wrong exp: " + ce.exp)
        }
      case _=>
    }
  }
  
  def updatePTAResultCallArg(exp: Exp, currentContext: Context, s: ISet[RFAFact], ptaresult: PTAResult)(implicit factory: RFAFactFactory): Unit = {
    exp match{
      case ne: NameExp =>
        val slot = VarSlot(ne.name.name, isBase = false, isArg = true)
        getRelatedFactsForArg(slot, s).foreach(f => ptaresult.addInstance(f.s, currentContext, f.v))
      case _ =>
    }
  }
  
  private def getHeapUnknownFactsExp(exp: Exp, currentContext: Context, ptaresult: PTAResult)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val result: MSet[RFAFact] = msetEmpty
    exp match {
      case _: AccessExp =>
      case ie: IndexingExp =>
        val baseSlot = ie.exp match {
          case ine: NameExp =>
            VarSlot(ine.name.name, isBase = true, isArg = false)
          case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
        }
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
  
  def getHeapUnknownFacts(rhss: List[Exp], currentContext: Context, ptaresult: PTAResult)(implicit factory: RFAFactFactory): ISet[RFAFact] = {
    val result: MSet[RFAFact] = msetEmpty
    rhss.foreach{
      rhs=>
        result ++= getHeapUnknownFactsExp(rhs, currentContext, ptaresult)
    }
    result.toSet
  }

  def processLHSs(lhss: List[Exp], typ: Option[JawaType], currentContext: Context, ptaresult: PTAResult, global: Global): IMap[Int, IMap[PTASlot, Boolean]] = {
    val result = mmapEmpty[Int, MMap[PTASlot, Boolean]]
    var i = -1
    lhss.foreach{
      key=>
        i += 1
        key match{
          case ne: NameExp =>
            val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
            result.getOrElseUpdate(i, mmapEmpty)(slot) = true
          case ae: AccessExp =>
            val fieldFQN = ASTUtil.getFieldFQN(ae, typ.get)
            val baseSlot = ae.exp match {
              case ne: NameExp => VarSlot(ne.name.name, isBase = true, isArg = false)
              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
            }
            val baseValue = ptaresult.pointsToSet(baseSlot, currentContext)
            baseValue.foreach{
              ins =>
                if(ins.isNull) {}
                else{
                  val fName = fieldFQN.fieldName
                  if(baseValue.size>1) result.getOrElseUpdate(i, mmapEmpty)(FieldSlot(ins, fName)) = false
                  else result.getOrElseUpdate(i, mmapEmpty)(FieldSlot(ins, fName)) = true
                }
            }
          case ie: IndexingExp =>
            val baseSlot = ie.exp match {
              case ine: NameExp =>
                VarSlot(ine.name.name, isBase = true, isArg = false)
              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
            }
            val baseValue = ptaresult.pointsToSet(baseSlot, currentContext)
            baseValue.foreach{
              ins =>
                result.getOrElseUpdate(i, mmapEmpty)(ArraySlot(ins)) = false
            }
          case _=>
        }
    }
    result.map(x => (x._1, x._2.toMap)).toMap
  }
  
  def processRHSs(rhss: List[Exp], typ: Option[JawaType], currentContext: Context, ptaResult: PTAResult, global: Global): Map[Int, Set[Instance]] = {
    val result = mmapEmpty[Int, Set[Instance]]
    var i = -1
    rhss.foreach{
      rhs=>
        i += 1
        rhs match{
          case ne: NameExp =>
            val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
            val value: ISet[Instance] = ptaResult.pointsToSet(slot, currentContext)
            result(i) = value
          case le: LiteralExp =>
            if(le.typ.name.equals("STRING")){
              val ins = PTAConcreteStringInstance(le.text, currentContext)
              val value: ISet[Instance] = Set(ins)
              result(i) = value
            } else if(le.typ.name.equals("NULL")){
              val inst = if(typ.get.isArray) typ.get else typ.get.toUnknown
              val ins = PTAInstance(inst, currentContext, isNull_ = true)
              val value: ISet[Instance] = Set(ins)
              result(i) = value
            }
          case ne: NewExp =>
            var name: ResourceUri = ""
            var dimensions = 0
            ne.typeSpec match {
              case nt: NamedTypeSpec =>
                dimensions = ne.dims.size + ne.typeFragments.size
                name = nt.name.name
              case _ =>
            }
            val ins =
              if(name == "java.lang.String" && dimensions == 0){
                PTAConcreteStringInstance("", currentContext.copy)
              } else {
                PTAInstance(new JawaType(name, dimensions), currentContext.copy, isNull_ = false)
              }
            val value: ISet[Instance] = Set(ins)
            result(i) = value
          case ae: AccessExp =>
            val fieldFQN = ASTUtil.getFieldFQN(ae, typ.get)
            val baseSlot = ae.exp match {
              case ne: NameExp => getNameSlotFromNameExp(ne, typ, isBase = true, isArg = false, global)
              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
            }
            val baseValue: ISet[Instance] = ptaResult.pointsToSet(baseSlot, currentContext)
            baseValue.foreach{
              ins =>
                if(ins.isNull){}
                else {
                  val fName = fieldFQN.fieldName
                  val fieldSlot = FieldSlot(ins, fName)
                  var fieldValue: ISet[Instance] = ptaResult.pointsToSet(fieldSlot, currentContext)
                  if(ins.isUnknown && fieldFQN.typ.isObject) {
                    fieldValue += PTAInstance(fieldFQN.typ.toUnknown, currentContext, isNull_ = false)
                  }
                  result(i) = fieldValue
                }
            }
          case ie: IndexingExp =>
            val baseSlot = ie.exp match {
              case ine: NameExp =>
                getNameSlotFromNameExp(ine, typ, isBase = true, isArg = false, global)
              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
            }
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
                    if(newType.name == "java.lang.String") PTAPointStringInstance(currentContext)
                    else PTAInstance(newType.toUnknown, currentContext, isNull_ = false)
                  arrayValue += newUnknown
                  result(i) = arrayValue.toSet
                }
                else {
                  val arraySlot = ArraySlot(ins)
                  val arrayValue: ISet[Instance] = ptaResult.pointsToSet(arraySlot, currentContext)
                  result(i) = arrayValue
                }
            }
          case ce: CastExp =>
            val casttyp: JawaType = ASTUtil.getTypeFromTypeSpec(ce.typeSpec)

            val insopt =
              if(casttyp.jawaName == "java.lang.String"){
                Some(PTAPointStringInstance(currentContext.copy))
              } else if (casttyp.isObject) {
                Some(PTAInstance(casttyp, currentContext.copy, isNull_ = false))
              } else None
            insopt match {
              case Some(ins) =>
                ce.exp match{
                  case ne: NameExp =>
                    val slot = getNameSlotFromNameExp(ne, typ, isBase = false, isArg = false, global)
                    val value: ISet[Instance] = ptaResult.pointsToSet(slot, currentContext)
                    result(i) = value.map{
                      v =>
                        if(v.isUnknown){
                          PTAInstance(ins.typ.toUnknown, v.defSite.copy, isNull_ = false)
                        } else {
                          v
                        }
                    }
                  case nle: NewListExp =>
                    System.err.println(TITLE, "NewListExp: " + nle)
                    result(i) = isetEmpty[Instance]// + UnknownInstance(currentContext)
                  case _ => throw new RuntimeException("Wrong exp: " + ce.exp)
                }
              case _ =>
            }
          case _=>
        }
    }
    result.toMap
  }
  
  def isObjectTypeRegAssignment(a: Assignment): Boolean = {
    var res = false
    a match{
      case _: AssignAction =>
        a.getValueAnnotation("kind") match{
          case Some(e) => 
            e match{
              case ne: NameExp => res = ne.name.name == "object"
              case _ =>
            }
          case None => 
        }
      case _ =>
    }
    res
  }
  
  def isStaticFieldRead(a: Assignment): Boolean = {
    var result = false
    if(isObjectTypeRegAssignment(a)) {
      val rhss = PilarAstHelper.getRHSs(a) 
      rhss.foreach {
        case ne: NameExp =>
          if (ne.name.name.startsWith("@@")) {
            result = true
          }
        case _ =>
      }
    }
    result
  }
  
  def isStaticFieldWrite(a: Assignment): Boolean = {
    var result = true
    if(isObjectTypeRegAssignment(a))
    {
      val lhss = PilarAstHelper.getLHSs(a)
      lhss.foreach {
        case ne: NameExp =>
          if (ne.name.name.startsWith("@@")) {
            result = true
          }
        case _ =>
      }
    }
    result
  }
  
  def getNameSlotFromNameExp(ne: NameExp, typ: Option[JawaType], isBase: Boolean, isArg: Boolean, global: Global): NameSlot = {
    val name = ne.name.name
    if(name == Constants.CONST_CLASS) ClassSlot(typ.get)
    else if(name.startsWith("@@")){
      val fqn = new FieldFQN(name.replace("@@", ""), typ.get)
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
