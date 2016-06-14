/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

//package org.sireum.amandroid.alir.taintAnalysis
//
//import org.sireum.jawa._
//import org.sireum.util._
//import org.sireum.jawa.alir.taintAnalysis.TaintFact
//import org.sireum.jawa.alir.controlFlowGraph._
//import org.sireum.jawa.alir.interProcedural._
//import org.sireum.pilar.ast._
//import org.sireum.alir.Slot
//import org.sireum.jawa.alir.reachingFactsAnalysis._
//import org.sireum.jawa.util.StringFormConverter
//import org.sireum.amandroid.alir.reachingFactsAnalysis.AndroidReachingFactsAnalysis
//import org.sireum.jawa.MessageCenter._
//import org.sireum.amandroid.alir.model.AndroidModelCallHandler
//import org.sireum.jawa.alir.taintAnalysis.TaintFact
//import org.sireum.jawa.alir.Context
//import org.sireum.jawa.alir.NullInstance
//
///**
// * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
// * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
// */ 
//class AndroidTaintAnalysisBuilder{
//  final val TITLE = "AndroidTaintAnalysisBuilder"
//  var rfaFacts: AndroidReachingFactsAnalysis.Result = null
//  var cg: InterproceduralControlFlowGraph[AndroidReachingFactsAnalysis.Node] = null
//  
//  def build //
//  (cg: InterproceduralControlFlowGraph[AndroidReachingFactsAnalysis.Node],
//   rfaFacts: AndroidReachingFactsAnalysis.Result,
//   initialFacts: ISet[TaintFact] = isetEmpty,
//   parallel: Boolean,
//   switchAsOrderedMatch: Boolean = false
//   ): AndroidTaintAnalysis.Result = {
//    val gen = new Gen
//    val kill = new Kill
//    val callr = new Callr
//    val initContext = new Context(GlobalConfig.CG_CONTEXT_K)
//    this.rfaFacts = rfaFacts
//    this.cg = cg
//    val initRFAFact = RFAFact(VarSlot("@@RFAiota"), NullInstance(initContext))
//    val iota: ISet[TaintFact] = initialFacts + TaintFact(initRFAFact, "TaintAnalysis")
//    val initial: ISet[TaintFact] = isetEmpty
//    val result = InterProceduralMonotoneDataFlowAnalysisFramework[TaintFact](cg,
//      true, true, false, parallel, gen, kill, callr, iota, initial, switchAsOrderedMatch, None)
//
////    print("TA\n")
////    print(result)
//    result
//  }
//  
//  protected def processLHSs(lhss: List[Exp], s: ISet[TaintFact], currentContext: Context): IMap[Int, (ISet[RFAFact], Boolean)] = {
//    val result = mmapEmpty[Int, (ISet[RFAFact], Boolean)]
//    val node = if(this.cg.cgNormalNodeExists(currentContext)) this.cg.getCGNormalNode(currentContext) else this.cg.getCGReturnNode(currentContext)
//    val rFacts = this.rfaFacts.exitSet(node)
//    var i = -1
//    lhss.foreach{
//      key=>
//        i += 1
//        key match{
//          case ne: NameExp =>
//            val slot = VarSlot(ne.name.name)
//            val resFacts = ReachingFactsAnalysisHelper.getRelatedFacts(slot, rFacts)
//            result(i) = (resFacts, true)
//          case ae: AccessExp =>
//            val fieldSig = ae.attributeName.name
//            val baseSlot = ae.exp match {
//              case ne: NameExp => VarSlot(ne.name.name)
//              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
//            }
//            val baseFacts = rFacts.filter(fact=> baseSlot == fact.s)
//            baseFacts.foreach{
//              case RFAFact(slot, ins) =>
//                Center.findField(ins.getType, fieldSig) match{
//		              case Some(af) =>
//		                val fSlot = FieldSlot(ins, af.getSignature)
//		                val resFacts = ReachingFactsAnalysisHelper.getRelatedFacts(fSlot, rFacts)
//		                if(baseFacts.size>1) result(i) = (resFacts, false)
//		                else result(i) = (resFacts, true)
//		              case None =>
//		                err_msg_detail(TITLE, "Given field may be in other library: " + fieldSig)
//		            }
//            }
//          case ie: IndexingExp =>
//            val baseSlot = ie.exp match {
//              case ine: NameExp =>
//                VarSlot(ine.name.name)
//              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
//            }
//            val baseFacts = rFacts.filter(fact=> baseSlot == fact.s)
//            baseFacts.foreach{
//              case RFAFact(slot, ins) =>
//                val aSlot = ArraySlot(ins)
//                val resFacts = ReachingFactsAnalysisHelper.getRelatedFacts(aSlot, rFacts)
//                result(i) = (resFacts, false)
//            }
//          case _=>
//        }
//    }
//    result.toMap
//  }
//
//  
//  protected def processRHSs(rhss: List[Exp], s: ISet[TaintFact], currentContext: Context): IMap[Int, Set[String]] = {
//    val result = mmapEmpty[Int, Set[String]]
//    var i = -1
//    rhss.foreach{
//      key=>
//        i += 1
//        key match{
//          case ne: NameExp =>
//            val rfacts = this.rfaFacts.entrySet(this.cg.getCGNormalNode(currentContext))
//            val slot = VarSlot(ne.name.name)
//            val facts = ReachingFactsAnalysisHelper.getRelatedFacts(slot, rfacts)
//            val sources = s.filter(tfact => facts.contains(tfact.fact)).map(tfact => tfact.source)
//            result(i) = sources
//          case ae: AccessExp =>
//            val rfacts = this.rfaFacts.entrySet(this.cg.getCGNormalNode(currentContext))
//            val fieldSig = ae.attributeName.name
//            val baseSlot = ae.exp match {
//              case ne: NameExp => VarSlot(ne.name.name)
//              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
//            }
//            val baseFacts = rfacts.filter(fact=> baseSlot == fact.s)
//            baseFacts.foreach{
//              case RFAFact(slot, ins) =>
//                Center.findField(ins.getType, fieldSig) match{
//                  case Some(af) =>
//	                  val fieldSlot = FieldSlot(ins, af.getSignature)
//		                val fieldRFAFacts = ReachingFactsAnalysisHelper.getRelatedFacts(fieldSlot, rfacts)
//		                val sources = s.filter(tfact => fieldRFAFacts.contains(tfact.fact)).map(tfact => tfact.source)
//				            result(i) = sources
//                  case None =>
//                    err_msg_detail(TITLE, "Given field may be in other library: " + fieldSig)
//                }
//            }
//          case ie: IndexingExp =>
//            val rfacts = this.rfaFacts.entrySet(this.cg.getCGNormalNode(currentContext))
//            val baseSlot = ie.exp match {
//              case ine: NameExp =>
//                VarSlot(ine.name.name)
//              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
//            }
//            val baseFacts = rfacts.filter(fact=> baseSlot == fact.s)
//            baseFacts.foreach{
//              case RFAFact(slot, ins) =>
//                val arraySlot = ArraySlot(ins)
//                val arrayRFAFacts = ReachingFactsAnalysisHelper.getRelatedFacts(arraySlot, rfacts)
//                val sources = s.filter(tfact => arrayRFAFacts.contains(tfact.fact)).map(tfact => tfact.source)
//		            result(i) = sources
//            }
//          case ce: CastExp =>
//            val rfacts = this.rfaFacts.entrySet(this.cg.getCGNormalNode(currentContext))
//            ce.exp match{
//              case ice: NameExp =>
//                val slot = VarSlot(ice.name.name)
//		            val facts = ReachingFactsAnalysisHelper.getRelatedFacts(slot, rfacts)
//		            val sources = s.filter(tfact => facts.contains(tfact.fact)).map(tfact => tfact.source)
//		            result(i) = sources
//              case _ => throw new RuntimeException("Wrong exp: " + ce.exp)
//            }
//          case _=>
//        }
//    }
//    result.toMap
//  }
//  
//  protected def getLHSs(a: PilarAstNode): List[Exp] = {
//    var result = List[Exp]()
//
//    def getLHSRec(e: Exp): Unit =
//      e match {
//        case te: TupleExp => te.exps.foreach(getLHSRec)
//        case _             => result ::= e
//      }
//
//    a match {
//      case aa: AssignAction => getLHSRec(aa.lhs)
//      case cj: CallJump =>
//        cj.lhss.foreach{getLHSRec(_)}
//      case _ =>
//    }
//    result
//  }
//  
//  protected def getRHSs(a: PilarAstNode): List[Exp] = {
//    var result = List[Exp]()
//
//    def getRHSRec(e: Exp): Unit =
//      e match {
//        case te: TupleExp => te.exps.foreach(getRHSRec)
//        case _             => result ::= e
//      }
//
//    a match {
//      case aa: AssignAction => getRHSRec(aa.rhs)
//      case cj: CallJump =>
//          getRHSRec(cj.callExp)
//      case _ =>
//    }
//    result
//  }
//  
//  protected def isInterestingAssignment(a: Assignment): Boolean = {
//    var result = false
//    a match{
//      case aa: AssignAction =>
//        aa.rhs match{
//          case ne: NewExp => result = true
//          case ce: CastExp => result = true
//          case _ =>
//        }
//        a.getValueAnnotation("type") match{
//          case Some(e) => 
//            e match{
//              case ne: NameExp => result = (ne.name.name == "object")
//              case _ =>
//            }
//          case None => 
//        }
//      case cj: CallJump => result = true
//      case _ =>
//    }
//    result
//  }
//  
//  def getSourceAndHandleSink(
//      s: ISet[TaintFact],
//      cFacts: ISet[RFAFact],
//      callee: JawaProcedure,
//      callNode: CGCallNode,
//      cj: CallJump,
//      lhssFacts: IMap[Int, (ISet[RFAFact], Boolean)],
//      currentContext: Context): (IMap[Int, ISet[String]], ISet[TaintFact]) = {
//    var sources: IMap[Int, ISet[String]] = imapEmpty
//    var taintset: ISet[TaintFact] = isetEmpty
//    val callees: MSet[JawaProcedure] = msetEmpty
//    val caller = Center.getProcedureWithoutFailing(callNode.getOwner)
//    val jumpLoc = caller.getProcedureBody.location(callNode.getLocIndex).asInstanceOf[JumpLocation]
////    if(callee.getSignature == Center.UNKNOWN_PROCEDURE_SIG){
////      val calleeSignature = cj.getValueAnnotation("signature") match {
////        case Some(s) => s match {
////          case ne: NameExp => ne.name.name
////          case _ => ""
////        }
////        case None => throw new RuntimeException("cannot found annotation 'signature' from: " + cj)
////      }
////      // source and sink APIs can only come from given app's parents.
////      callees ++= Center.getProcedureDeclarations(calleeSignature)
////    } else 
//      callees += callee
////    if(SourceAndSinkCenter.isSource(soundCallee, caller, jumpLoc)){
////      msg_normal("find source: " + soundCallee + "@" + currentContext)
////      lhssFacts.map{
////        case (i, _) => 
////          sources += (i -> (sources.getOrElse(i, isetEmpty) + soundCallee.getSignature))
////      }
////    }
////    if(SourceAndSinkCenter.isSinkProcedure(soundCallee)){
////      msg_normal("find sink: " + soundCallee + "@" + currentContext)
////      val args = cj.callExp.arg match{
////        case te: TupleExp =>
////          te.exps.map{
////            exp =>
////              exp match{
////		            case ne: NameExp => ne.name.name
////		            case _ => exp.toString()
////		          }
////          }.toList
////        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
////      }
////      var argfacts = isetEmpty[RFAFact]
////      args.foreach{
////        arg =>
////          val argslot = VarSlot(arg)
////          argfacts ++= ReachingFactsAnalysisHelper.getRelatedFacts(argslot, cFacts)
////      }
////      val taintFacts = s.filter(taFact => argfacts.contains(taFact.fact))
////      if(!taintFacts.isEmpty){ // means at least one arg got tainted
////        taintFacts.foreach{
////          tFact =>
////            msg_critical("find path: " + tFact.source + " -> " + callee.getSignature)
////        }
////      }
////    }
//    if(isModelCall(callee)){
//      val args = cj.callExp.arg match{
//        case te: TupleExp =>
//          te.exps.map{
//            exp =>
//              exp match{
//		            case ne: NameExp => ne.name.name
//		            case _ => exp.toString()
//		          }
//          }.toList
//        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//      }
//      var argfacts = isetEmpty[RFAFact]
//      args.foreach{
//        arg =>
//          val argslot = VarSlot(arg)
//          argfacts ++= ReachingFactsAnalysisHelper.getRelatedFacts(argslot, cFacts)
//      }
//      val taintFacts = s.filter(taFact => argfacts.contains(taFact.fact))
//      if(!taintFacts.isEmpty){ // means at least one arg got tainted
//        val srcs = taintFacts.map(tf => tf.source)
//        lhssFacts.map{
//	        case (i, _) => 
//	          sources += (i -> (sources.getOrElse(i, isetEmpty) ++ srcs))
//	          srcs.foreach{
//              src =>
//				        argfacts.foreach{
//				          fact =>
//				            taintset += TaintFact(fact, src)
//				        }
//				    }
//        }
//      }
//    }
//    (sources, taintset)
//  }
//
//  class Gen
//      extends InterProceduralMonotonicFunction[TaintFact] {
//    
//    def apply(s: ISet[TaintFact], a: Assignment, currentNode: CGLocNode): ISet[TaintFact] = {
//      var result: ISet[TaintFact] = isetEmpty
//      if(isInterestingAssignment(a)){
//        val lhss = getLHSs(a)
//	      val lhssFacts = processLHSs(lhss, s, currentNode.getContext)
//	      var sources: IMap[Int, ISet[String]] = imapEmpty
//        if(a.isInstanceOf[CallJump]){
//          val cj = a.asInstanceOf[CallJump]
//          val callNode = cg.getCGCallNode(currentNode.getContext).asInstanceOf[CGCallNode]
//          val cFacts = rfaFacts.exitSet(callNode)
//          val calleeSet = callNode.getCalleeSet
//          calleeSet.foreach{
//            callee =>
//              val (srcs, taintset) = getSourceAndHandleSink(s, cFacts, callee.callee, callNode, cj, lhssFacts, currentNode.getContext)
//              sources ++= srcs
//              result ++= taintset
//          }
//        } else {
//		      val rhss = getRHSs(a)
//		      sources ++= processRHSs(rhss, s, currentNode.getContext) 
//        }
//        lhssFacts.foreach{
//	        case(i, (facts, _)) =>
//	          if(sources.contains(i)){
//	            facts.foreach{f => sources(i).foreach{v => result += TaintFact(f, v)}}
//	          }
//	      }
//      }
//      result
//    }
//
//    def apply(s: ISet[TaintFact], e: Exp, currentNode: CGLocNode): ISet[TaintFact] = isetEmpty
//    
//    def apply(s: ISet[TaintFact], a: Action, currentNode: CGLocNode): ISet[TaintFact] = isetEmpty
//  }
//
//  class Kill
//      extends InterProceduralMonotonicFunction[TaintFact] {
//    
//    def apply(s: ISet[TaintFact], a: Assignment, currentNode: CGLocNode): ISet[TaintFact] = {
//      var result = s
//      if(isInterestingAssignment(a)){
//	      val lhss = getLHSs(a)
//	      val rfaFactsWithMark = processLHSs(lhss, s, currentNode.getContext).values.toSet
//	      for (rdf @ TaintFact(fact, _) <- s) {
//	        //if it is a strong definition, we can kill the existing definition
//	        rfaFactsWithMark.foreach{
//	          case (facts, flag) =>
//	            if(facts.contains(fact) && flag) result = result -rdf
//	        }
//	      }
//      }
//      result
//    }
//
//    def apply(s: ISet[TaintFact], e: Exp, currentNode: CGLocNode): ISet[TaintFact] = s
//    def apply(s: ISet[TaintFact], a: Action, currentNode: CGLocNode): ISet[TaintFact] = s
//  }
//  
//  class Callr
//  		extends CallResolver[TaintFact] {
//
//    /**
//     * It returns the facts for each callee entry node and caller return node
//     */
//    def resolveCall(s: ISet[TaintFact], cj: CallJump, callerContext: Context, cg: InterproceduralControlFlowGraph[CGNode]): (IMap[CGNode, ISet[TaintFact]], ISet[TaintFact]) = {
//      val calleeSet = getCalleeSet(s, cj, callerContext)
//      var calleeFactsMap: IMap[CGNode, ISet[TaintFact]] = imapEmpty
//      var returnFacts: ISet[TaintFact] = s
//      calleeSet.foreach{
//        callee =>
//          if(isICCCall(callee)){
//            val args = cj.callExp.arg match{
//              case te: TupleExp =>
//                te.exps.map{
//			            exp =>
//			              exp match{
//					            case ne: NameExp => ne.name.name
//					            case _ => exp.toString()
//					          }
//			          }.toList
//              case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//            }
//            val factsForCallee = getFactsForICCTarget(s, cj, callee, callerContext)
//            calleeFactsMap += (cg.entryNode(callee.getSignature, callerContext) -> mapFactsToICCTarget(factsForCallee, cj, callee.getProcedureBody.procedure))
//          } else { // for normal call
//            val factsForCallee = getFactsForCallee(s, cj, callee, callerContext)
//            returnFacts --= factsForCallee
//            calleeFactsMap += (cg.entryNode(callee.getSignature, callerContext) -> mapFactsToCallee(factsForCallee, cj, callee.getProcedureBody.procedure))
//          }
//      }
//	    (calleeFactsMap, returnFacts)
//    }
//    
//    def getAndMapFactsForCaller(calleeS: ISet[TaintFact], callerNode: CGNode, calleeExitNode: CGVirtualNode): ISet[TaintFact] ={
//      doGetAndMapFactsForCaller(calleeS, callerNode, calleeExitNode)
//    }
//  }
//  
//  private def getCalleeSet(s: ISet[TaintFact], cj: CallJump, callerContext: Context): ISet[JawaProcedure] = {
//    val callNode = cg.getCGCallNode(callerContext)
//    var calleeSet = isetEmpty[JawaProcedure]
//    cg.successors(callNode).foreach{
//      suc =>
//        if(suc.isInstanceOf[CGEntryNode]){
//          calleeSet += Center.getProcedureWithoutFailing(suc.getOwner)
//        }
//    }
//    calleeSet
//  }
//  
//  private def getFactsForICCTarget(s: ISet[TaintFact], cj: CallJump, callee: JawaProcedure, callerContext: Context): ISet[TaintFact] = {
//    var calleeFacts = isetEmpty[TaintFact]
//    val rfacts = this.rfaFacts.entrySet(this.cg.getCGCallNode(callerContext))
//    val globalFacts = ReachingFactsAnalysisHelper.getGlobalFacts(rfacts)
//    calleeFacts ++= s.filter(taFact => globalFacts.contains(taFact.fact))
//    cj.callExp.arg match{
//      case te: TupleExp =>
//        val exp = te.exps(1)
//        if(exp.isInstanceOf[NameExp]){
//          val slot = VarSlot(exp.asInstanceOf[NameExp].name.name)
//          val facts = ReachingFactsAnalysisHelper.getRelatedFacts(slot, rfacts)
//          val taintFacts = s.filter(taFact => facts.contains(taFact.fact))
//          calleeFacts ++= taintFacts
//        }
//        calleeFacts
//      case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//    }
//  }
//  
//  def mapFactsToICCTarget(factsToCallee: ISet[TaintFact], cj: CallJump, calleeProcedure: ProcedureDecl): ISet[TaintFact] = {
//    val varFacts = factsToCallee.filter(f=>f.fact.s.isInstanceOf[VarSlot] && !f.fact.s.asInstanceOf[VarSlot].isGlobal)
//    cj.callExp.arg match{
//      case te: TupleExp =>
//        val argSlot = te.exps(1) match{
//          case ne: NameExp => VarSlot(ne.name.name)
//          case exp => VarSlot(exp.toString())
//        }
//        var paramSlots: List[VarSlot] = List()
//        calleeProcedure.params.foreach{
//          param =>
//            require(param.typeSpec.isDefined)
//            param.typeSpec.get match{
//              case nt: NamedTypeSpec =>
//                val name = nt.name.name
//                if(name=="long" || name=="double")
//                  paramSlots ::= VarSlot(param.name.name)
//              case _ =>
//            }
//            paramSlots ::= VarSlot(param.name.name)
//        }
//        paramSlots = paramSlots.reverse
//        var result = isetEmpty[TaintFact]
//        val paramSlot = paramSlots(0)
//        varFacts.foreach{
//          fact =>
//            if(fact.fact.s == argSlot){
//              val rfafact = RFAFact(paramSlot, fact.fact.v)
//              result += (TaintFact(rfafact, fact.source))
//            }
//        }
//        factsToCallee -- varFacts ++ result
//      case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//    }
//  }
//  
//  private def getFactsForCallee(s: ISet[TaintFact], cj: CallJump, callee: JawaProcedure, callerContext: Context): ISet[TaintFact] = {
//    var calleeFacts = isetEmpty[TaintFact]
//    val rfacts = this.rfaFacts.entrySet(this.cg.getCGCallNode(callerContext))
//    val globalFacts = ReachingFactsAnalysisHelper.getGlobalFacts(rfacts)
//    calleeFacts ++= s.filter(taFact => globalFacts.contains(taFact.fact))
//    cj.callExp.arg match{
//      case te: TupleExp =>
//        for(i <- 0 to te.exps.size -1){
//          val exp = te.exps(i)
//          if(exp.isInstanceOf[NameExp]){
//            val slot = VarSlot(exp.asInstanceOf[NameExp].name.name)
//            val facts = ReachingFactsAnalysisHelper.getRelatedFacts(slot, rfacts)
//            val taintFacts = s.filter(taFact => facts.contains(taFact.fact))
//            calleeFacts ++= taintFacts
//          }
//        }
//        calleeFacts
//      case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//    }
//  }
//  
//  def mapFactsToCallee(factsToCallee: ISet[TaintFact], cj: CallJump, calleeProcedure: ProcedureDecl): ISet[TaintFact] = {
//    val varFacts = factsToCallee.filter(f=>f.fact.s.isInstanceOf[VarSlot] && !f.fact.s.asInstanceOf[VarSlot].isGlobal)
//    cj.callExp.arg match{
//      case te: TupleExp =>
//        val argSlots = te.exps.map{
//          exp =>
//            exp match{
//	            case ne: NameExp => VarSlot(ne.name.name)
//	            case _ => VarSlot(exp.toString())
//	          }
//        }
//        var paramSlots: List[VarSlot] = List()
//        calleeProcedure.params.foreach{
//          param =>
//            require(param.typeSpec.isDefined)
//            param.typeSpec.get match{
//              case nt: NamedTypeSpec =>
//                val name = nt.name.name
//                if(name=="long" || name=="double")
//                  paramSlots ::= VarSlot(param.name.name)
//              case _ =>
//            }
//            paramSlots ::= VarSlot(param.name.name)
//        }
//        paramSlots = paramSlots.reverse
//        var result = isetEmpty[TaintFact]
//        
//        for(i <- 0 to argSlots.size - 1){
//          val argSlot = argSlots(i)
//          if(paramSlots.size < argSlots.size) println("cj-->" + cj + "\ncalleeProcedure-->" +calleeProcedure )
//          val paramSlot = paramSlots(i)
//          varFacts.foreach{
//            fact =>
//              if(fact.fact.s == argSlot){
//	              val rfafact = RFAFact(paramSlot, fact.fact.v)
//	              result += (TaintFact(rfafact, fact.source))
//	            }
//          }
//        }
//        factsToCallee -- varFacts ++ result
//      case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//    }
//  }
//  
//  def doGetAndMapFactsForCaller(calleeS: ISet[TaintFact], callerNode: CGNode, calleeExitNode: CGVirtualNode): ISet[TaintFact] ={
//    var result = isetEmpty[TaintFact]
////    result ++= ReachingFactsAnalysisHelper.getGlobalFacts(calleeS)
////    callerNode match{
////      case crn: CGReturnNode =>
////        val calleeVarFacts = calleeS.filter(_.s.isInstanceOf[VarSlot]).map{f=>(f.s.asInstanceOf[VarSlot], f.v)}.toSet
////        val callee = calleeExitNode.getOwner
////        val calleeProcedure = callee.getProcedureBody.procedure
////        val cj = callee.getProcedureBody.location(crn.getLocIndex).asInstanceOf[JumpLocation].jump.asInstanceOf[CallJump]
////        val lhsSlots: ISeq[VarSlot] = cj.lhss.map{lhs=>VarSlot(lhs.name.name)}
////        var paramSlots: List[VarSlot] = List()
////        calleeProcedure.params.foreach{
////          param =>
////            require(param.typeSpec.isDefined)
////            param.typeSpec.get match{
////              case nt: NamedTypeSpec =>
////                val name = nt.name.name
////                if(name=="[|long|]" || name=="[|double|]")
////                  paramSlots :+= VarSlot(param.name.name)
////              case _ =>
////            }
////            paramSlots :+= VarSlot(param.name.name)
////        }
////        var retSlots: ISet[VarSlot] = isetEmpty
////        calleeProcedure.body match{
////	        case ib: ImplementedBody =>
////	          ib.locations.foreach{
////	            loc=>
////	              if(isReturnJump(loc)){
////	                val rj = loc.asInstanceOf[JumpLocation].jump.asInstanceOf[ReturnJump]
////	                rj.exp match{
////	                  case Some(n) => 
////	                    n match{
////	                      case ne: NameExp => retSlots += VarSlot(ne.name.name)
////	                      case _ =>
////	                    }
////	                  case None =>
////	                }
////	              }
////	          }
////	        case _ =>
////	      }
////	      lhsSlots.foreach{
////	        lhsSlot =>
////		        var values: ISet[Instance] = isetEmpty
////		        retSlots.foreach{
////		          retSlot =>
////		            calleeVarFacts.foreach{
////		              case (s, v) =>
////		                if(s == retSlot){
////		                  values += v
////		                }
////		            }
////		        }
////		        result ++= values.map(v => TaintFact(lhsSlot, v))
////		        result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(values, calleeS)
////	      }
////	      cj.callExp.arg match{
////	        case te: TupleExp =>
////	          val argSlots = te.exps.map{
////	            exp =>
////	              exp match{
////			            case ne: NameExp => VarSlot(ne.name.name)
////			            case _ => VarSlot(exp.toString)
////			          }
////	          }
////	          argSlots.foreach{
////	            argSlot =>
////	              var values: ISet[Instance] = isetEmpty
////		            calleeVarFacts.foreach{
////		              case (s, v) =>
////		                if(paramSlots.contains(s))
////		              	 values += v
////		            }
////	              result ++= values.map(v=>RFAFact(argSlot, v))
////	              result ++= ReachingFactsAnalysisHelper.getRelatedHeapFacts(values, calleeS)
////	          }
////	        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
////	      }
////      case cnn: CGNode =>
////    }
//    result
//  }
//  
//  private def isReturnJump(loc: LocationDecl): Boolean = {
//    loc.isInstanceOf[JumpLocation] && loc.asInstanceOf[JumpLocation].jump.isInstanceOf[ReturnJump]
//  }
//  
//  private def isICCCall(calleeProc: JawaProcedure): Boolean = {
//    calleeProc.getSubSignature == "dummyMain:(Landroid/content/Intent;)V"
//  }
//  
//  private def isModelCall(calleeProc: JawaProcedure): Boolean = {
//    AndroidModelCallHandler.isModelCall(calleeProc)
//  }
//  
//}
//
///**
// * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
// * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
// */ 
//object AndroidTaintAnalysis {
//
//  type Node = AndroidReachingFactsAnalysis.Node
//  type Result = InterProceduralMonotoneDataFlowAnalysisResult[TaintFact]
//   
//  def apply(cg: InterproceduralControlFlowGraph[AndroidReachingFactsAnalysis.Node],
//				   rfaFacts: AndroidReachingFactsAnalysis.Result,
//				   initialFacts: ISet[TaintFact] = isetEmpty,
//				   parallel: Boolean = false,
//				   switchAsOrderedMatch: Boolean = false)
//    = new AndroidTaintAnalysisBuilder().build(cg, rfaFacts, initialFacts, parallel, switchAsOrderedMatch)
//
//}
