/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

//package org.sireum.jawa.alir.taintAnalysis
//
//import org.sireum.jawa.alir.controlFlowGraph.InterproceduralControlFlowGraph
//import org.sireum.util._
//import org.sireum.jawa.alir.interProcedural._
//import org.sireum.pilar.ast._
//import org.sireum.jawa.alir.controlFlowGraph._
//import org.sireum.jawa.PilarAstHelper
//import org.sireum.jawa.alir.Context
//import org.sireum.jawa.alir.dataFlowAnalysis.CallResolver
//import org.sireum.jawa.alir.dataFlowAnalysis.InterProceduralMonotonicFunction
//import org.sireum.jawa.alir.pta.reachingFactsAnalysis.ReachingFactsAnalysisHelper
//import org.sireum.jawa.util.ASTUtil
//import org.sireum.jawa.Global
//import org.sireum.jawa.alir.pta.PTAResult
//import org.sireum.jawa.alir.dataFlowAnalysis.InterProceduralMonotoneDataFlowAnalysisFramework
//import org.sireum.jawa.alir.pta.VarSlot
//import org.sireum.jawa.alir.dataFlowAnalysis.PstProvider
//import org.sireum.jawa.Signature
//import org.sireum.pilar.symbol.ProcedureSymbolTable
//import org.sireum.jawa.util.MyTimer
//import org.sireum.alir.AlirEdge
//import org.sireum.jawa.alir.dataFlowAnalysis.NodeListener
//import org.sireum.jawa.alir.pta.PTASlot
//import org.sireum.jawa.JawaType
//import org.sireum.jawa.alir.pta.FieldSlot
//import org.sireum.jawa.alir.pta.Instance
//
//class IMDFTaintAnalysis(global: Global, ptaresult: PTAResult, ssm: SourceAndSinkManager) {
//  final val TITLE = "IMDFTaintAnalysis"
//  
//  type Node = TaintNode
//  type Edge = AlirEdge[Node]
//  
//  class Tp extends TaintPath[Node, Edge] {
//    var srcN: TaintSource[Node] = null
//    var sinN: TaintSink[Node] = null
//    val path: MList[Edge] = mlistEmpty
//    val typs: MSet[String] = msetEmpty
//    def getSource = srcN
//    def getSink = sinN
//    def getTypes: ISet[String] = this.typs.toSet
//    def getPath: IList[Edge] = {
//      path.map(edge => new Edge(edge.owner, edge.target, edge.source)).toList
//    }
//    def isSame(tp: TaintPath[Node, Edge]): Boolean = getSource.isSame(tp.getSource) && getSink.isSame(tp.getSink)
//    override def toString: String = {
//      val sb = new StringBuilder
//      sb.append("Taint path: ")
//      this.typs foreach (typ => sb.append(typ + " "))
//      sb.append("\n")
//      sb.append(srcN.descriptor + "\n\t-> " + sinN.descriptor + "\n")
//      if(path.size > 1) {
//        path.tail.reverse.foreach{
//          edge =>
//            sb.append(edge.target.getContext + "\n\t-> ")
//        }
//        sb.append(path.head.source.getContext + "\n")
//      } else {
//        sb.append(path.head.target.getContext + "\n\t-> ")
//        sb.append(path.head.source.getContext + "\n")
//      }
//      sb.toString().intern
//    }
//  }
//  
//  class Tar extends TaintAnalysisResult[Node, Edge] {
//    var sourceNodes: ISet[TaintSource[Node]] = isetEmpty
//    var sinkNodes: ISet[TaintSink[Node]] = isetEmpty
//    
//    def getSourceNodes: ISet[TaintSource[Node]] = this.sourceNodes.toSet
//    def getSinkNodes: ISet[TaintSink[Node]] = this.sinkNodes.toSet
//    def getTaintedPaths: ISet[TaintPath[Node, Edge]] = {
//      var tps: ISet[TaintPath[Node, Edge]] = isetEmpty
//      sinkNodes.foreach {
//        sinN =>
//          sourceNodes.foreach {
//            srcN =>
////              val path = iddi.getDependentPath(sinN.getNode, srcN.getNode)
////              if(path != null){
////                val tp = Tp(path)
////                tp.srcN = srcN
////                tp.sinN = sinN
////                
////                if(!tp.typs.isEmpty)
////                  tps += tp
////              }
//          }
//      }
//      tps
//    }
//    override def toString: String = {
//      val sb = new StringBuilder
//      val paths = getTaintedPaths
//      if(!paths.isEmpty){
//        getTaintedPaths.foreach(tp => sb.append(tp.toString) + "\n")
//      }
//      sb.toString.intern()
//    }
//  }
//  
//  def build //
//  (icfg: InterproceduralControlFlowGraph[ICFGNode],
//   initialFacts: ISet[TaintFact] = isetEmpty,
//   timer: Option[MyTimer],
//   switchAsOrderedMatch: Boolean): Unit = {
//    val gen = new Gen
//    val kill = new Kill
//    val callr = new Callr
//    val ppr = new Pstr
//    val initial: ISet[TaintFact] = isetEmpty
//    val iota: ISet[TaintFact] = initialFacts + TaintFact(PrimitiveTaintSlot(VarSlot("@@Taintiota", false, false), new Context), "IOTA")
//    icfg.nodes.foreach {
//      node =>
//        val (srcs, sins) = ssm.getSourceAndSinkNode(node, ptaresult)
//        srcSet ++= srcs.map{src => (src.node, src.asInstanceOf[TagTaintDescriptor])}
//        sinSet ++= sins.map{sin => (sin.node, sin.asInstanceOf[TagTaintDescriptor])}
//    }
//    if(srcSet.isEmpty && sinSet.isEmpty) return
//    val result = InterProceduralMonotoneDataFlowAnalysisFramework[TaintFact](icfg,
//      true, true, false, false, gen, kill, callr, ppr, iota, initial, timer, switchAsOrderedMatch, None)
//    
//  }
//  
//  
//  class Pstr extends PstProvider {
//    def getPst(sig: Signature): ProcedureSymbolTable = {
//      global.getMethod(sig).get.getBody
//    }
//  }
//  
//  private val processed: MSet[InterProceduralMonotoneDataFlowAnalysisFramework.N] = msetEmpty
//  private val srcSet: MMap[InterProceduralMonotoneDataFlowAnalysisFramework.N, TagTaintDescriptor] = mmapEmpty
//  private val sinSet: MMap[InterProceduralMonotoneDataFlowAnalysisFramework.N, TagTaintDescriptor] = mmapEmpty
//  private val sanSet: MMap[InterProceduralMonotoneDataFlowAnalysisFramework.N, ISet[String]] = mmapEmpty // TODO
//  private val tgeSet: MMap[InterProceduralMonotoneDataFlowAnalysisFramework.N, ISet[String]] = mmapEmpty // TODO
//  
//  private val graph: TaintGraph = new TaintGraph
//  
//  private def isObjectAssignment(a: Assignment): Boolean = {
//    var result = false
//    a match{
//      case aa: AssignAction => 
//        aa.rhs match {
//          case ne: NewExp => result = true
//          case ce: CastExp => result = true
//          case _ =>
//            a.getValueAnnotation("kind") match {
//              case Some(e) => 
//                e match{
//                  case ne: NameExp => result = (ne.name.name == "object")
//                  case _ =>
//                }
//              case None => 
//            }
//        }
//      case _ =>
//    }
//    result
//  }
//  
//  private def processPTASlots(slots: ISet[PTASlot], context: Context, isObject: Boolean): IMap[PTASlot, ISet[TaintSlot]] = {
//    val result: MMap[PTASlot, ISet[TaintSlot]] = mmapEmpty
//    if(isObject) {
//      slots.foreach{
//        slot =>
//          val inss = ptaresult.pointsToSet(slot, context)
//          result(slot) = inss.map(InstanceTaintSlot(slot, TaintSlotPosition.LHS, context, _))
//      }
//    } else {
//      slots.map {s => result(s) = Set(PrimitiveTaintSlot(s, TaintSlotPosition.LHS, context))}
//    }
//    result.toMap
//  }
//  
//  private def getPrevTaintSlot(s: ISet[TaintFact], insorslot: Either[Instance, PTASlot]): IMap[TaintSlot, ISet[String]] = {
//    val result: MMap[TaintSlot, MSet[String]] = mmapEmpty
//    insorslot match {
//      case Left(ins) =>
//        s.foreach {
//          fact => 
//            fact.s match {
//              case its: InstanceTaintSlot => 
//                if(its.ins == ins) {
//                  val tags = result.getOrElseUpdate(its, msetEmpty) 
//                  tags += fact.tag
//                }
//              case _ =>
//            }
//        }
//      case Right(slot) =>
//        s.foreach {
//          fact => 
//            fact.s match {
//              case pts: PrimitiveTaintSlot => 
//                if(pts.s.getId == slot.getId) {
//                  val tags = result.getOrElseUpdate(pts, msetEmpty) 
//                  tags += fact.tag
//                }
//              case _ =>
//            }
//        }
//    }
//    result.map(r => (r._1, r._2.toSet)).toMap
//  }
//  
//  private def processRHSs(s: ISet[TaintFact], rhss: IList[Exp], context: Context, typ: Option[JawaType], isObject: Boolean): ISet[(TaintSlot, ISet[String])] = {
//    val pos = TaintSlotPosition.RHS
//    val result: MSet[(TaintSlot, ISet[String])] = msetEmpty
//    rhss foreach {
//      rhs =>
//        rhs match{
//          case ne: NameExp =>
//            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, false, false, global)
//            if(isObject){
//              val value = ptaresult.pointsToSet(slot, context)
//              value.map {
//                ins =>
//                  getPrevTaintSlot(s, Left(ins)) foreach {
//                    case (ptslot, tags) =>
//                      val itslot = InstanceTaintSlot(slot, pos, context, ins)
//                      graph.addTaintEdge(ptslot, itslot)
//                      result += ((itslot, tags))
//                  }
//                    
//              }
//            } else {
//              getPrevTaintSlot(s, Right(slot)) foreach {
//                case (ptslot, tags) =>
//                  val itslot = PrimitiveTaintSlot(slot, pos, context)
//                  graph.addTaintEdge(ptslot, itslot)
//                  result += ((itslot, tags))
//              }
//            }
//          case le: LiteralExp =>
//          case ne: NewExp =>
//          case ae: AccessExp =>
//            val fieldFQN = ASTUtil.getFieldFQN(ae, typ.get)
//            val baseSlot = ae.exp match {
//              case ne: NameExp => ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, true, false, global)
//              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
//            }
//            val baseValue = ptaresult.pointsToSet(baseSlot, context)
//            baseValue.map{
//              ins =>
//                if(ins.isNull){}
//                else {
//                  getPrevTaintSlot(s, Left(ins)) foreach {
//                    case (ptslot, tags) =>
//                      val itslot = InstanceTaintSlot(baseSlot, pos, context, ins)
//                      graph.addTaintEdge(ptslot, itslot)
//                      result += ((itslot, tags))
//                  }
//                  val fName = fieldFQN.fieldName
//                  val fieldSlot = FieldSlot(ins, fName)
//                  if(isObject) {
//                    val fieldValue = ptaresult.pointsToSet(fieldSlot, context)
//                    fieldValue.foreach {
//                      fins => 
//                        getPrevTaintSlot(s, Left(fins)) foreach {
//                          case (ptslot, tags) =>
//                            val itslot = InstanceTaintSlot(fieldSlot, pos, context, fins)
//                            graph.addTaintEdge(ptslot, itslot)
//                            result += ((itslot, tags))
//                        }
//                    }
//                  } else {
//                    getPrevTaintSlot(s, Right(fieldSlot)) foreach {
//                      case (ptslot, tags) =>
//                        val itslot = PrimitiveTaintSlot(fieldSlot, pos, context)
//                        graph.addTaintEdge(ptslot, itslot)
//                        result += ((itslot, tags))
//                    }
//                  }
//                }
//            }
//          case ie: IndexingExp =>
//            val baseSlot = ie.exp match {
//              case ine: NameExp =>
//                ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ine, typ, true, false, global)
//              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
//            }
//            val baseValue = ptaresult.pointsToSet(baseSlot, context)
//            baseValue.map{
//              ins =>
//                if(ins.isNull){}
//                else {
//                  getPrevTaintSlot(s, Left(ins)) foreach {
//                    case (ptslot, tags) =>
//                      val itslot = InstanceTaintSlot(baseSlot, pos, context, ins)
//                      graph.addTaintEdge(ptslot, itslot)
//                      result += ((itslot, tags))
//                  }
//                }
//            }
//          case ce: CastExp =>
//            ce.exp match{
//              case ne: NameExp =>
//                val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, false, false, global)
//                val value: ISet[Instance] = ptaresult.pointsToSet(slot, context)
//                value.foreach {
//                  ins =>
//                    getPrevTaintSlot(s, Left(ins)) foreach {
//                      case (ptslot, tags) =>
//                        val itslot = InstanceTaintSlot(slot, pos, context, ins)
//                        graph.addTaintEdge(ptslot, itslot)
//                        result += ((itslot, tags))
//                    }
//                }
//              case nle: NewListExp =>
//                System.err.println(TITLE, "NewListExp: " + nle)
//              case _ => throw new RuntimeException("Wrong exp: " + ce.exp)
//            }
//          case _ =>
//        }
//    }
//    result.toSet
//  }
//  
//  private def processLHSs(s: ISet[TaintFact], lhss: IList[Exp], rhsslot: ISet[(TaintSlot, ISet[String])], context: Context, typ: Option[JawaType], isObject: Boolean): ISet[(TaintSlot, ISet[String])] = {
//    val pos = TaintSlotPosition.RHS
//    val result: MSet[(TaintSlot, ISet[String])] = msetEmpty
//    if(rhsslot.isEmpty) return result.toSet
//    lhss.foreach{
//      lhs =>
//        lhs match{
//          case ne: NameExp =>
//            val slot = ReachingFactsAnalysisHelper.getNameSlotFromNameExp(ne, typ, false, false, global)
//            if(isObject){
//              val value = ptaresult.pointsToSet(slot, context)
//              value.map {
//                ins =>
//                  val itslot = InstanceTaintSlot(slot, pos, context, ins)
//                  val ta = rhsslot.map{
//                    case (slot, tags) =>
//                      graph.addTaintEdge(slot, itslot)
//                      tags
//                  }.reduce(iunion[String] _)
//                  result += ((itslot,ta))
//              }
//            } else {
//              val itslot = PrimitiveTaintSlot(slot, pos, context)
//              val ta = rhsslot.map{
//                case (slot, tags) =>
//                  graph.addTaintEdge(slot, itslot)
//                  tags
//              }.reduce(iunion[String] _)
//              result += ((itslot,ta))
//            }
//          case ae: AccessExp =>
//            val fieldFQN = ASTUtil.getFieldFQN(ae, typ.get)
//            val baseSlot = ae.exp match {
//              case ne: NameExp => VarSlot(ne.name.name, true, false)
//              case _ => throw new RuntimeException("Wrong exp: " + ae.exp)
//            }
//            val baseValue = ptaresult.pointsToSet(baseSlot, context)
//            baseValue.map{
//              ins =>
//                if(ins.isNull) {}
//                else{
//                  val fName = fieldFQN.fieldName
//                  val fieldSlot = FieldSlot(ins, fName)
//                  if(isObject) {
//                    val fieldValue = ptaresult.pointsToSet(fieldSlot, context)
//                    fieldValue.foreach {
//                      fins => 
//                        val itslot = InstanceTaintSlot(fieldSlot, pos, context, fins)
//                        val ta = rhsslot.map{
//                          case (slot, tags) =>
//                            graph.addTaintEdge(slot, itslot)
//                            tags
//                        }.reduce(iunion[String] _)
//                        result += ((itslot,ta))
//                    }
//                  } else {
//                    val itslot = PrimitiveTaintSlot(fieldSlot, pos, context)
//                    val ta = rhsslot.map{
//                      case (slot, tags) =>
//                        graph.addTaintEdge(slot, itslot)
//                        tags
//                    }.reduce(iunion[String] _)
//                    result += ((itslot,ta))
//                  }
//                }
//            }
//          case ie: IndexingExp =>
//            val baseSlot = ie.exp match {
//              case ine: NameExp =>
//                VarSlot(ine.name.name, true, false)
//              case _ => throw new RuntimeException("Wrong exp: " + ie.exp)
//            }
//            val baseValue = ptaresult.pointsToSet(baseSlot, context)
//            baseValue.map{
//              ins =>
//                val itslot = InstanceTaintSlot(baseSlot, pos, context, ins)
//                val ta = rhsslot.map{
//                  case (slot, tags) =>
//                    graph.addTaintEdge(slot, itslot)
//                    tags
//                }.reduce(iunion[String] _)
//                result += ((itslot,ta))
//            }
//          case _=>
//        }
//    }
//    result.toSet
//  }
//  
//  /**
//   * Gen algorithm:
//   * 1. If current node is source, then it generate a TaintFact with the tags associate with the source.
//   * 2. If current node is an object operation then wherever the instance going get tainted.
//   * 3. If current node is a scala value operation then the left value get tainted.
//   * 4. If a tag generate node found, gen the tag facts.
//   */
//  class Gen
//      extends InterProceduralMonotonicFunction[TaintFact] {
//    
//    def apply(s: ISet[TaintFact], a: Assignment, currentNode: ICFGLocNode): ISet[TaintFact] = {
//      val result: MSet[TaintFact] = msetEmpty
//      val typ = ASTUtil.getType(a)
//      val lhss = PilarAstHelper.getLHSs(a)
//      val rhss = PilarAstHelper.getRHSs(a)
//      val slots: ISet[PTASlot] = ReachingFactsAnalysisHelper.processLHSs(lhss, typ, currentNode.getContext, ptaresult, global).flatMap(_._2).map(_._1).toSet
//      val isObject = isObjectAssignment(a)
//      // Here handle statement source. we consider lhs will be tainted for a statement source.
//      val descOpt = srcSet.get(currentNode)
//      descOpt.foreach {
//        desc =>
//          val taintslots = processPTASlots(slots, currentNode.getContext, isObject)
//          taintslots.foreach {
//            case (ps, tss) =>
//              tss foreach {
//                ts =>
//                  graph.addSource(TaintNode(ts))
//                  result ++= desc.tags.map(TaintFact(ts, _))
//              }
//          }
//      }
//      val rhsslots = processRHSs(s, rhss, currentNode.getContext, typ, isObject)
//      val lhsslots = processLHSs(s, lhss, rhsslots, currentNode.getContext, typ, isObject)
//      (lhsslots ++ rhsslots).foreach {
//        case (slot, tags) =>
//          result ++= tags.map(TaintFact(slot, _))
//      }
//      // TODO: Handle if it's a tag gen node
//      result.toSet
//    }
//
//    def apply(s: ISet[TaintFact], e: Exp, currentNode: ICFGLocNode): ISet[TaintFact] = isetEmpty
//    
//    def apply(s: ISet[TaintFact], a: Action, currentNode: ICFGLocNode): ISet[TaintFact] = isetEmpty
//  }
//
//  /**
//   * Kill algorithm:
//   * 1. Strong update left-hand-side taint get killed.
//   * 2. If a sanitizing node found kill associated tag facts.
//   */
//  class Kill
//      extends InterProceduralMonotonicFunction[TaintFact] {
//    
//    def apply(s: ISet[TaintFact], a: Assignment, currentNode: ICFGLocNode): ISet[TaintFact] = {
//      val typ = ASTUtil.getType(a)
//      var result = s
//      val lhss = PilarAstHelper.getLHSs(a)
//      val slotsWithMark = ReachingFactsAnalysisHelper.processLHSs(lhss, typ, currentNode.getContext, ptaresult, global).values.flatten.toSet
//      for (rdf @ TaintFact(slot, _) <- s) {
//        slot match {
//          case pts: PrimitiveTaintSlot =>
//            //if it is a strong definition, we can kill the existing definition
//            if (slotsWithMark.contains((pts.s, true))) {
//              result = result - rdf
//            }
//          case _ =>
//        }
//        
//      }
//      // TODO: Handle if it's a tag kill node
//      result
//    }
//
//    def apply(s: ISet[TaintFact], e: Exp, currentNode: ICFGLocNode): ISet[TaintFact] = s
//    def apply(s: ISet[TaintFact], a: Action, currentNode: ICFGLocNode): ISet[TaintFact] = s
//  }
//  
//  /**
//   * Call resolver algorithm:
//   * 1. If it's a source, then it generate a TaintFact with the tags associate with the source.
//   * 2. If it's a sink, then if any taint fact reached, generate taint path.
//   * 3. For non-model call, map taint facts from caller to callee.
//   * 4. For model call, mark all RFAfacts which contains tainted instance.
//   * 5. Kill left-hand-side facts.
//   * 6. If model call return scala value, mark the value as tainted if any of the param tainted.
//   * 7. Map facts from callee to caller.
//   */
//  class Callr
//      extends CallResolver[TaintFact] {
//
//    /**
//     * It returns the facts for each callee entry node and caller return node
//     */
//    def resolveCall(s: ISet[TaintFact], cj: CallJump, callerNode: ICFGNode, cg: InterproceduralControlFlowGraph[ICFGNode]): (IMap[ICFGNode, ISet[TaintFact]], ISet[TaintFact]) = {
//      val calleeFactsMap: MMap[ICFGNode, MSet[TaintFact]] = mmapEmpty
//      var returnFacts: ISet[TaintFact] = s
//      val genSet: MSet[TaintFact] = msetEmpty
//      val killSet: MSet[TaintFact] = msetEmpty
//      val typ = ASTUtil.getType(cj)
//      val lhss = PilarAstHelper.getLHSs(cj)
//      val slotsWithMark = ReachingFactsAnalysisHelper.processLHSs(lhss, typ, callerNode.getContext, ptaresult, global).values.flatten.toSet
//      for (rdf @ TaintFact(slot, value) <- s) {
//        slot match {
//          case pts: PrimitiveTaintSlot =>
//            //if it is a strong definition, we can kill the existing definition
//            if (slotsWithMark.contains(pts.s, true)) {
//              killSet += rdf
//            }
//          case _ =>
//        }
//      }
//      val slots: ISet[PTASlot] = slotsWithMark.map(_._1).toSet
//      val isObject = isObjectAssignment(cj)
//      val taintslots = processPTASlots(slots, callerNode.getContext, isObject)
//      val args = cj.callExp.arg match{
//        case te: TupleExp =>
//          te.exps.map{
//            exp =>
//              exp match{
//                case ne: NameExp => ne.name.name
//                case _ => exp.toString()
//              }
//          }.toList
//        case _ => throw new RuntimeException("wrong exp type: " + cj.callExp.arg)
//      }
//      // Handle source case
//      val srcDescOpt = srcSet.get(callerNode)
//      srcDescOpt.foreach {
//        srcdesc =>
//          taintslots.foreach (ts => genSet ++= srcdesc.tags.map(TaintFact(ts, _)))
//      }
//      // Handle sink case
//      val sinDescOpt = sinSet.get(callerNode)
//      sinDescOpt.foreach {
//        sindesc =>
//          val poss = sindesc.positions
//          poss foreach {
//            pos =>
//              try {
//                val arg = args(pos)
//                val argSlot = VarSlot(arg, false, true)
//                val inss = ptaresult.getRelatedInstances(argSlot, callerNode.getContext)
//                s.foreach {
//                  fact =>
//                    fact.s match {
//                      case its: InstanceTaintSlot => if(inss.contains(its.ins)) println("Found path.")
//                      case pts: PrimitiveTaintSlot => if(pts.s.getId == argSlot.getId) println("Found path.")
//                      case _ =>
//                    }
//                }
//              } catch {
//                case ex: Exception => global.reporter.error(TITLE, ex.getMessage)
//              }
//          }
//      }
//      // Handle normal call and model call
//      val succs = cg.successors(callerNode)
//      val callees = callerNode.asInstanceOf[ICFGInvokeNode].getCalleeSet
//      succs foreach {
//        succ =>
//          succ match {
//            case ien: ICFGEntryNode => // Normal call or special call case
//              val entryPTSMap = ptaresult.getPTSMap(ien.getContext)
//              args foreach {
//                arg =>
//                  val argSlot = VarSlot(arg, false, true)
//                  val inss = ptaresult.getRelatedInstances(argSlot, callerNode.getContext)
//                  s.foreach {
//                    fact =>
//                      fact.s match {
//                        case its: InstanceTaintSlot => 
//                          if(inss.contains(its.ins)) {
//                            killSet += fact
//                            entryPTSMap.foreach {
//                              case (slot, entryinss) => if(entryinss.contains(its.ins)) calleeFactsMap.getOrElseUpdate(ien, msetEmpty) += TaintFact(InstanceTaintSlot(its.ins), fact.tag)
//                            }
//                          }
//                        case pts: PrimitiveTaintSlot => 
//                          if(pts.s.getId == argSlot.getId) {
//                            killSet += fact
//                            callees foreach {
//                              callee =>
//                                val params = callee.callee.params
//                                val index = args.indexOf(arg)
//                                if(params.isDefinedAt(index)) {
//                                  val paramSlot = VarSlot(params(index)._1, false, false)
//                                  calleeFactsMap.getOrElseUpdate(ien, msetEmpty) += TaintFact(PrimitiveTaintSlot(paramSlot), fact.tag)
//                                } else global.reporter.error(TITLE, "args does not much params:\n" + callerNode + ":" + args + "\n" + callee.callee.getSignature + ":" + params)
//                            }
//                          }
//                        case _ =>
//                      }
//                  }
//              }
//            case irn: ICFGReturnNode => // Model call case
//              val retPTSMap = ptaresult.getPTSMap(irn.getContext)
//              args foreach {
//                arg =>
//                  val argSlot = VarSlot(arg, false, true)
//                  val inss = ptaresult.getRelatedInstances(argSlot, callerNode.getContext)
//                  s.foreach {
//                    fact =>
//                      fact.s match {
//                        case its: InstanceTaintSlot => 
//                          retPTSMap.foreach {
//                              case (slot, entryinss) => if(entryinss.contains(its.ins)) calleeFactsMap.getOrElseUpdate(ien, msetEmpty) += TaintFact(InstanceTaintSlot(its.ins), fact.tag)
//                            }
//                        case pts: PrimitiveTaintSlot => 
//                          if(pts.s.getId == argSlot.getId) {
//                            killSet += fact
//                            callees foreach {
//                              callee =>
//                                val params = callee.callee.params
//                                val index = args.indexOf(arg)
//                                if(params.isDefinedAt(index)) {
//                                  val paramSlot = VarSlot(params(index)._1, false, false)
//                                  calleeFactsMap.getOrElseUpdate(ien, msetEmpty) += TaintFact(PrimitiveTaintSlot(paramSlot), fact.tag)
//                                } else global.reporter.error(TITLE, "args does not much params:\n" + callerNode + ":" + args + "\n" + callee.callee.getSignature + ":" + params)
//                            }
//                          }
//                        case _ =>
//                      }
//                  }
//              }
//            case _ =>
//          }
//      }
//      returnFacts = returnFacts -- killSet ++ genSet
//      (calleeFactsMap.map(fm => (fm._1, fm._2.toSet)).toMap, returnFacts)
//    }
//    
//    def getAndMapFactsForCaller(calleeS: ISet[TaintFact], callerNode: ICFGNode, calleeExitNode: ICFGVirtualNode): ISet[TaintFact] ={
//      var result = isetEmpty[TaintFact]
//      result
//    }
//  }
//}
//
