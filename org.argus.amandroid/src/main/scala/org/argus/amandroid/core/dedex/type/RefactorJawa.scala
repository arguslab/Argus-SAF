/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
//package org.sireum.jawa.sjc.refactoring
//
//import org.sireum.jawa.DefaultReporter
//import org.sireum.util._
//import org.sireum.alir.AlirLocationNode
//import org.sireum.jawa.sjc.parser._
//import org.sireum.jawa.JawaType
//import org.sireum.alir.AlirVirtualNode
//import org.sireum.jawa.ObjectType
//import org.sireum.jawa.JavaKnowledge
//import org.sireum.jawa.sjc.alir.ControlFlowGraph
//import org.sireum.alir.AlirIntraProceduralGraph
//import org.sireum.jawa.io.Position
//import org.sireum.jawa.PrimitiveType
//import org.sireum.jawa.ExceptionCenter
//
///**
// * @author fgwei
// */
//object RefactorJawa {
//  final val DEBUG = false
//  
//  def apply(code: String): String = {
////    val newcode = 
////      try {
////        resolveCallStatement(code)
////      } catch {
////        case e: Exception => code
////      }
////    var sb: StringBuilder = new StringBuilder
////    val reporter = new DefaultReporter
////    val cuOpt1: Option[CompilationUnit] = JawaParser.parse[CompilationUnit](Left(code), true, reporter)
////    cuOpt1 match {
////      case Some(cu) =>
////        cu.topDecls foreach {
////          c =>
////            val classcode = c.toCode
////            val head = if(c.methods.size > 0) code.substring(0, c.methods(0).firstToken.pos.start - c.methods(0).firstToken.pos.column) else code
////            sb.append(head)
////            c.methods foreach {
////              md =>
////                val pool: AlirIntraProceduralGraph.NodePool = mmapEmpty
////                val cfg = ControlFlowGraph[String](md, "Entry", "Exit", pool, ControlFlowGraph.defaultSiff)
////                try {
////                  val methodcode = resolveNull(md, cfg)
////                  sb.append(methodcode + "\n")
////                } catch {
////                  case e: Exception =>
////                    sb.append(md.toCode + "\n")
////                }
////            }
////        }
////      case None =>
////        println(reporter.problems)
////    }
////    val newcodeafternull = sb.toString.trim
////    sb = new StringBuilder
////    val cuOpt2: Option[CompilationUnit] = JawaParser.parse[CompilationUnit](Left(newcodeafternull), true, reporter)
////    cuOpt2 match {
////      case Some(cu) =>
////        cu.topDecls foreach {
////          c =>
////            val classcode = c.toCode
////            val head = if(c.methods.size > 0) code.substring(0, c.methods(0).firstToken.pos.start - c.methods(0).firstToken.pos.column) else code
////            sb.append(head)
////            c.methods foreach {
////              md =>
////                val pool: AlirIntraProceduralGraph.NodePool = mmapEmpty
////                val cfg = ControlFlowGraph[String](md, "Entry", "Exit", pool, ControlFlowGraph.defaultSiff)
////                try{
////                  val methodcode = resolveLocalVarType(md, cfg)
////                  sb.append(methodcode + "\n")
////                } catch {
////                  case e: Exception =>
////                    if(DEBUG) e.printStackTrace()
////                    sb.append(md.toCode + "\n")
////                }
////            }
////        }
////      case None =>
////        println(reporter.problems)
////    }
////    val finalcode = sb.toString.trim
////    finalcode
//    code
//  }
//  
//  case class NullTask(index: Int, varname: String, pos: Position, code: String)
//  case class Resolved(msg: String) extends Throwable(msg)
//  
//  def resolveNull(md: MethodDeclaration, cfg: ControlFlowGraph[String]): String = {
//    val tasks: MMap[ControlFlowGraph.Node, NullTask] = mmapEmpty
//    val locations: MMap[Int, String] = mmapEmpty // map from index -> location string
//    val sb: StringBuilder = new StringBuilder
//    val code = md.toCode
//    val head: String = code.substring(0, code.indexOf("#") - 1)
//    sb.append(head)
//    val body: ResolvedBody = md.body match {
//      case rb: ResolvedBody => rb
//      case ub: UnresolvedBody => ub.resolve
//    }
//    for(node <- cfg.nodes) {
//      node match {
//        case alun: AlirLocationNode =>
//          val index: Int = alun.locIndex
//          val loc = body.locations(index)
//          val locCode = loc.toCode
//          locations(index) = locCode
//          loc.statement match {
//            case as: AssignmentStatement =>
//              val kind: String = as.kind
//              as.lhs match{
//                case ne: NameExpression =>
//                  ne.varSymbol match {
//                    case Left(v) =>
//                      as.rhs match{
//                        case le: LiteralExpression =>
//                          import org.sireum.jawa.sjc.lexer.Tokens._
//                          le.constant.tokenType match {
//                            case INTEGER_LITERAL =>
//                              if(kind == "int" && le.getInt == 0){ // it is possible as object null
//                                tasks(node) = NullTask(loc.locationIndex, v.varName, v.id.pos, locCode)
//                              }
//                            case _ =>
//                          }
//                        case _ =>
//                      }
//                    case _ =>
//                  }
//                case _ =>
//              }
//            case _ =>
//          }
//        case _ =>
//      }
//    }
//    
//    def handleTask(varname: String, typ: JawaType, task: NullTask): Unit = {
//      if(task.varname == varname) {
//        var newl = task.code
//        if(typ.isInstanceOf[ObjectType]) newl = newl.replace("0I  @kind int", "null  @kind object")
//        locations(task.index) = newl
//        throw Resolved("success")
//      }
//    }
//    
//    for((node, task) <- tasks) {
//      val worklist = mlistEmpty ++ cfg.successors(node)
//      try{
//        val resolved: MSet[ControlFlowGraph.Node] = msetEmpty
//        while(!worklist.isEmpty){
//          val n = worklist.remove(0)
//          resolved += n
//          var skip: Boolean = false
//          n match {
//            case alun: AlirLocationNode => 
//              val index: Int = alun.locIndex
//              val loc = body.locations(index)
//              val locCode = loc.toCode
//              loc.statement match {
//                case cs: CallStatement =>
//                  val paramTypes = cs.signature.getParameterTypes()
//                  val args = cs.argVars
//                  val size = paramTypes.size
//                  for(i <- 1 to size) {
//                    val arg = args(size - i)
//                    val typ = paramTypes(size - i)
//                    handleTask(arg.varName, typ, task)
//                  }
//                  cs.recvVarOpt match {
//                    case Some(recv) =>
//                      val typ = cs.signature.getClassType
//                      handleTask(recv.varName, typ, task)
//                    case None =>
//                  }
//                  cs.lhsOpt match {
//                    case Some(lhs) =>
//                      if(task.varname == lhs.lhs.varName) skip = true
//                    case _ =>
//                  }
//                case as: AssignmentStatement =>
//                  val typOpt: Option[JawaType] = as.typOpt
//                  val kind: String = as.kind
//                  as.rhs match {
//                    case ne: NameExpression =>
//                      ne.varSymbol match {
//                        case Left(v) =>
//                          val varname = v.varName
//                          val typ: JawaType = typOpt match {
//                            case Some(t) => t
//                            case None => 
//                              kind match {
//                                case "object" => JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
//                                case a => PrimitiveType("int")
//                              }
//                          }
//                          handleTask(varname, typ, task)
//                        case _ =>
//                      }
//                    case ee: ExceptionExpression =>
//                    case ie: IndexingExpression =>
//                      ie.indices.reverse.foreach{
//                        indice =>
//                          indice.index match {
//                            case Left(v) =>
//                              val varName = v.varName
//                              handleTask(varName, PrimitiveType("int"), task)
//                            case Right(c) =>
//                          }
//                      }
//                      val varname = ie.base
//                      handleTask(varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, task) /*TODO need to think whether its possible to refer the type*/
//                    case ae: AccessExpression =>
//                      val varname = ae.base
//                      handleTask(varname, typOpt.get, task)
//                    case te: TupleExpression =>
//                    case ce: CastExpression =>
//                      val varname = ce.varName
//                      handleTask(varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, task)
//                    case ne: NewExpression =>
//                      ne.typeFragmentsWithInit.reverse.foreach{
//                        tf =>
//                          tf.varSymbols.reverse.foreach{
//                            v =>
//                              val varname = v._1.varName
//                              handleTask(varname, PrimitiveType("int"), task)
//                          }
//                      }
//                    case le: LiteralExpression =>
//                    case ue: UnaryExpression =>
//                      val varname = ue.unary.varName
//                      handleTask(varname, PrimitiveType(kind), task)
//                    case be: BinaryExpression =>
//                      val rightname = be.right match {
//                        case Left(v) =>
//                          val rightname = v.varName
//                          handleTask(rightname, PrimitiveType(kind), task)
//                        case Right(s) =>
//                      }
//                      val leftname = be.left.varName
//                      handleTask(leftname, PrimitiveType(kind), task)
//                    case ce: CmpExpression =>
//                      val var2name = ce.var2Symbol.varName
//                      val typ = ce.paramType
//                      handleTask(var2name, typ, task)
//                      val var1name = ce.var1Symbol.varName
//                      handleTask(var1name, typ, task)
//                    case ie: InstanceofExpression =>
//                      val varname = ie.varSymbol.varName
//                      handleTask(varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, task)
//                    case ce: ConstClassExpression =>
//                    case le: LengthExpression =>
//                      val varname = le.varSymbol.varName
//                      handleTask(varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, task)
//                    case ne: NullExpression =>
//                    case _ =>  println("resolveLocalVarType rhs problem: " + as.rhs)
//                  }
//                  
//                  as.lhs match {
//                    case ne: NameExpression =>
//                      if(task.varname == ne.name) skip = true
//                    case ie: IndexingExpression =>
//                      ie.indices.reverse.foreach{
//                        indice =>
//                          indice.index match {
//                            case Left(v) =>
//                              val varName = v.varName
//                              handleTask(varName, PrimitiveType("int"), task)
//                            case Right(c) =>
//                          }
//                      }
//                      val varname = ie.base
//                      val dimentions = ie.dimentions
//                      val typ = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
//                      handleTask(varname, typ, task)
//                    case ae: AccessExpression =>
//                      val varname = ae.base
//                      handleTask(varname, typOpt.get, task)
//                    case _ => println("resolveLocalVarType lhs problem: " + as.lhs)
//                  }
//                case ts: ThrowStatement => 
//                  val varname = ts.varSymbol.varName
//                  handleTask(varname, new ObjectType("java.lang.Throwable"), task)
//                case is: IfStatement =>
//                  val left = is.cond.left.varName
//                  is.cond.right match {
//                    case Left(v) =>
//                      handleTask(v.varName, PrimitiveType("int"), task)
//                    case Right(c) =>
//                  }
//                  handleTask(left, PrimitiveType("int"), task)
//                case gs: GotoStatement =>
//                case ss: SwitchStatement =>
//                  val varname = ss.condition.varName
//                  handleTask(varname, PrimitiveType("int"), task)
//                case rs: ReturnStatement =>
//                  rs.varOpt match {
//                    case Some(v) =>
//                      val varname = v.varName
//                      handleTask(varname, md.signature.getReturnType(), task)
//                    case None =>
//                  }
//                case ms: MonitorStatement =>
//                  val varname = ms.varSymbol.varName
//                  handleTask(varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, task)
//                case es: EmptyStatement =>
//                case _ =>
//              }
//            case _ =>
//          }
//          if(!skip){
//            val succs = cfg.successors(n)
//            worklist ++= succs.filter { x => !resolved.contains(x) }
//          }
//        }
//      } catch {
//        case r: Resolved =>
//          // Success
//      }
//    }
//    sb.append("\n")
//    locations.toList.sortBy(_._1) foreach {
//      case (i, loccode) =>
//        sb.append(loccode + "\n")
//    }
//    body.catchClauses foreach {
//      cc =>
//        sb.append(cc.toCode + "\n")
//    }
//    sb.append("}")
//    sb.toString.trim()
//  }
//  
//  def resolveLocalVarType(md: MethodDeclaration, cfg: ControlFlowGraph[String]): String = {
//    val localvars: MMap[String, (JawaType, Boolean)] = mmapEmpty // map from variable -> (typ, isParam)
//    val locations: MMap[Int, String] = mmapEmpty // map from index -> location string
//    val recentvars: MMap[ControlFlowGraph.Node, MMap[String, String]] = mmapEmpty // map from var -> newvar
//    
//    val resolved: MSet[ControlFlowGraph.Node] = msetEmpty
//    
//    def findRecentVarsOrUpdate(node: ControlFlowGraph.Node, varName: String, typ: JawaType): String = {
//      val map = recentvars(node)
//      map.get(varName) match {
//        case Some(n) => n
//        case None =>
//          var newvar = typ.typ.substring(typ.typ.lastIndexOf(".") + 1) + {if(typ.dimensions > 0)"_arr" + typ.dimensions else ""} + "_" + varName
//          if(localvars.contains(newvar) && localvars(newvar)._1 != typ) newvar = "a" + newvar
//          if(!localvars.contains(newvar)) localvars(newvar) = ((typ, false))
//          recentvars(node)(varName) = newvar
//          newvar
//      }
//    }
//    
//    val sb: StringBuilder = new StringBuilder
//    val code = md.toCode
//    var head: String = code.substring(0, code.indexOf("{") + 1)
//    val sig = md.signature
//    val params = md.paramlist 
//    val types = sig.getParameterTypes()
//    
//    for(i <- 1 to params.size) {
//      val param = params(params.size - i)
//      val typ = types(params.size - i)
//      var newvar = typ.typ.substring(typ.typ.lastIndexOf(".") + 1) + {if(typ.dimensions > 0)"_arr" + typ.dimensions else ""} + "_" + param.name
//      if(localvars.contains(newvar) && localvars(newvar)._1 != typ) newvar = "a" + newvar
//      localvars(newvar) = ((typ, true))
//      recentvars.getOrElseUpdate(cfg.entryNode, mmapEmpty)(param.name) = newvar
//      head = updateCode(head, param.paramSymbol.id.pos, newvar)
//    }
//    
//    md.thisParam match {
//      case Some(t) =>
//        val newvar = "this_" + t.name
//        localvars(newvar) = ((md.enclosingTopLevelClass.typ, true))
//        recentvars.getOrElseUpdate(cfg.entryNode, mmapEmpty)(t.name) = newvar
//        head = updateCode(head, t.paramSymbol.id.pos, newvar)
//      case None =>
//    }
//    
//    sb.append(head + "\n")
//    val body: ResolvedBody = md.body match {
//      case rb: ResolvedBody => rb
//      case ub: UnresolvedBody => ub.resolve
//    }
//    for (i <- 0 to body.locations.size - 1) {
//      locations(i) = body.locations(i).toCode
//    }
//    val entry: ControlFlowGraph.Node = cfg.entryNode
//    val worklist: MList[ControlFlowGraph.Node] = mlistEmpty
//    worklist += entry
//    while(!worklist.isEmpty){
//      val n = worklist.remove(0)
//      resolved += n
//      val succs = cfg.successors(n)
//      val preds = cfg.predecessors(n)
//      val recmap = recentvars.getOrElseUpdate(n, mmapEmpty)
//      preds foreach {
//        pred => 
//          val premap = recentvars.getOrElse(pred, mmapEmpty)
//          recmap ++= premap
//      }
//      worklist ++= succs.filter { x => !resolved.contains(x) }
//      n match {
//        case alun: AlirLocationNode => 
//          val index: Int = alun.locIndex
//          val loc = body.locations(index)
//          var locCode = loc.toCode
//          loc.statement match {
//            case cs: CallStatement =>
//              val paramTypes = cs.signature.getParameterTypes()
//              val args = cs.argVars
//              val size = paramTypes.size
//              for(i <- 1 to size) {
//                val arg = args(size - i)
//                val typ = paramTypes(size - i)
//                val newarg = findRecentVarsOrUpdate(n, arg.varName, typ)
//                locCode = updateCode(locCode, arg.id.pos, newarg)
//              }
//              cs.recvVarOpt match {
//                case Some(recv) =>
//                  val newarg = findRecentVarsOrUpdate(n, recv.varName, cs.signature.getClassType)
//                  locCode = updateCode(locCode, recv.id.pos, newarg)
//                case None =>
//              }
//              cs.lhsOpt match {
//                case Some(lhs) =>
//                  val retType = cs.signature.getReturnType() match {
//                    case ot: ObjectType =>
//                      if(JavaKnowledge.isJavaPrimitive(ot.typ)) ot
//                      else ObjectType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, ot.dimensions)
//                    case a => a
//                  }
//                  var newvar = retType.typ.substring(retType.typ.lastIndexOf(".") + 1) + {if(retType.dimensions > 0)"_arr" + retType.dimensions else ""} + "_" + lhs.lhs.varName
//                  if(localvars.contains(newvar) && localvars(newvar)._1 != retType) newvar = "a" + newvar
//                  if(!localvars.contains(newvar)) localvars(newvar) = ((retType, false))
//                  recentvars(n)(lhs.lhs.varName) = newvar
//                  locCode = updateCode(locCode, lhs.lhs.id.pos, newvar)
////                  updateEvidence(lhs.lhs.id.pos) = newvar
//                case None =>
//              }
//            case as: AssignmentStatement =>
//              val typOpt: Option[JawaType] = as.typOpt
//              val kind: String = as.kind
//              var rhsType: JawaType = null
//              as.rhs match {
//                case ne: NameExpression =>
//                  ne.varSymbol match {
//                    case Left(v) =>
//                      val varname = v.varName
//                      val typ: JawaType = typOpt match {
//                        case Some(t) => t
//                        case None => 
//                          kind match {
//                            case "object" => JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
//                            case a => PrimitiveType("int")
//                          }
//                      }
//                      val newarg = findRecentVarsOrUpdate(n, varname, typ)
//                      locCode = updateCode(locCode, v.id.pos, newarg)
//                      rhsType = localvars(newarg)._1
//                    case Right(f) =>
//                      rhsType = typOpt.get
//                  }
//                case ee: ExceptionExpression =>
//                  rhsType = new ObjectType("java.lang.Throwable")/*TODO*/
//                case ie: IndexingExpression =>
//                  ie.indices.reverse.foreach{
//                    indice =>
//                      indice.index match {
//                        case Left(v) =>
//                          val varName = v.varName
//                          val newarg = findRecentVarsOrUpdate(n, varName, PrimitiveType("int"))
//                          locCode = updateCode(locCode, v.id.pos, newarg)
//                        case Right(c) =>
//                      }
//                  }
//                  val varname = ie.base
//                  val newarg = findRecentVarsOrUpdate(n, varname, ObjectType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, 1))
//                  locCode = updateCode(locCode, ie.varSymbol.id.pos, newarg)
//                  val dimentions = ie.dimentions
//                  val typ = localvars(newarg)._1
//                  val d = if(typ.dimensions - dimentions < 0) 0 else typ.dimensions - dimentions // for safe
//                  rhsType = JawaType.generateType(typ.typ, d)
//                case ae: AccessExpression =>
//                  val varname = ae.base
//                  val newarg = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, ae.varSymbol.id.pos, newarg)
//                  rhsType = typOpt.get
//                case te: TupleExpression =>
//                  rhsType =
//                    as.lhs match {
//                      case ne: NameExpression =>
//                        ne.varSymbol match {
//                          case Left(v) =>
//                            val newv = findRecentVarsOrUpdate(n, v.varName, ObjectType("int", 1))
//                            val (typ, _) = localvars(newv)
//                            typ
//                          case Right(v) =>
//                            println("resolveLocalVarType TupleExpression NameExpression problem: " + as.lhs)
//                            ObjectType("char", 1)
//                        }
//                      case _ =>
//                        println("resolveLocalVarType TupleExpression problem: " + as.lhs)
//                        ObjectType("char", 1)
//                    }
//                case ce: CastExpression =>
//                  val varname = ce.varName
//                  val newarg = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, ce.varSym.id.pos, newarg)
//                  rhsType = ce.typ.typ
//                case ne: NewExpression =>
//                  ne.typeFragmentsWithInit.reverse.foreach{
//                    tf =>
//                      tf.varSymbols.reverse.foreach{
//                        v =>
//                          val varname = v._1.varName
//                          val newarg = findRecentVarsOrUpdate(n, varname, PrimitiveType("int"))
//                          locCode = updateCode(locCode, v._1.id.pos, newarg)
//                      }
//                  }
//                  rhsType = ne.typ
//                case le: LiteralExpression =>
//                  import org.sireum.jawa.sjc.lexer.Tokens._
//                  le.constant.tokenType match {
//                    case STRING_LITERAL =>
//                      rhsType = new ObjectType("java.lang.String")
//                    case FLOATING_POINT_LITERAL =>
//                      rhsType = PrimitiveType(kind)
//                    case INTEGER_LITERAL =>
//                      rhsType = PrimitiveType(kind)
//                    case CHARACTER_LITERAL =>
//                      rhsType = PrimitiveType(kind)
//                  }
//                case ue: UnaryExpression =>
//                  val varname = ue.unary.varName
//                  rhsType = PrimitiveType(kind)
//                  val newarg = findRecentVarsOrUpdate(n, varname, rhsType)
//                  locCode = updateCode(locCode, ue.unary.id.pos, newarg)
//                case be: BinaryExpression =>
//                  rhsType = PrimitiveType(kind)
//                  val rightname = be.right match {
//                    case Left(v) =>
//                      val rightname = v.varName
//                      val newright = findRecentVarsOrUpdate(n, rightname, rhsType)
//                      locCode = updateCode(locCode, v.id.pos, newright)
//                    case Right(s) =>
//                  }
//                  val leftname = be.left.varName
//                  val newleft = findRecentVarsOrUpdate(n, leftname, rhsType)
//                  locCode = updateCode(locCode, be.left.id.pos, newleft)
//                case ce: CmpExpression =>
//                  val var2name = ce.var2Symbol.varName
//                  val typ = ce.paramType
//                  val newvar2name = findRecentVarsOrUpdate(n, var2name, typ)
//                  locCode = updateCode(locCode, ce.var2Symbol.id.pos, newvar2name)
//                  val var1name = ce.var1Symbol.varName
//                  val newvar1name = findRecentVarsOrUpdate(n, var1name, typ)
//                  locCode = updateCode(locCode, ce.var1Symbol.id.pos, newvar1name)
//                  rhsType = PrimitiveType("boolean")
//                case ie: InstanceofExpression =>
//                  val varname = ie.varSymbol.varName
//                  val newarg = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, ie.varSymbol.id.pos, newarg)
//                  rhsType = PrimitiveType("boolean")
//                case ce: ConstClassExpression =>
//                  rhsType = new ObjectType("java.lang.Class")
//                case le: LengthExpression =>
//                  val varname = le.varSymbol.varName
//                  val newarg = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, le.varSymbol.id.pos, newarg)
//                  rhsType = PrimitiveType("int")
//                case ne: NullExpression =>
//                  rhsType = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
//                case _ =>  println("resolveLocalVarType rhs problem: " + as.rhs)
//              }
//              rhsType = rhsType match {
//                case ot: ObjectType =>
//                  if(JavaKnowledge.isJavaPrimitive(ot.typ)) ot
//                  else ObjectType(JavaKnowledge.JAVA_TOPLEVEL_OBJECT, ot.dimensions)
//                case a => a
//              }
//              as.lhs match {
//                case ne: NameExpression =>
//                  ne.varSymbol match {
//                    case Left(v) =>
//                      var newvar = rhsType.typ.substring(rhsType.typ.lastIndexOf(".") + 1) + {if(rhsType.dimensions > 0)"_arr" + rhsType.dimensions else ""} + "_" + ne.name
//                      if(localvars.contains(newvar) && localvars(newvar)._1 != rhsType) newvar = "a" + newvar
//                      if(!localvars.contains(newvar)) localvars(newvar) = ((rhsType, false))
//                      recentvars(n)(ne.name) = newvar
//                      locCode = updateCode(locCode, v.id.pos, newvar)
//                    case Right(f) =>
//                  }
//                case ie: IndexingExpression =>
//                  ie.indices.reverse.foreach{
//                    indice =>
//                      indice.index match {
//                        case Left(v) =>
//                          val varName = v.varName
//                          val newarg = findRecentVarsOrUpdate(n, varName, PrimitiveType("int"))
//                          locCode = updateCode(locCode, v.id.pos, newarg)
//                        case Right(c) =>
//                      }
//                  }
//                  val varname = ie.base
//                  val dimentions = ie.dimentions
//                  val typ = JawaType.generateType(rhsType.typ, rhsType.dimensions + dimentions)
//                  val newarg = findRecentVarsOrUpdate(n, varname, typ)
//                  locCode = updateCode(locCode, ie.varSymbol.id.pos, newarg)
//                case ae: AccessExpression =>
//                  val varname = ae.base
//                  val newarg = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, ae.varSymbol.id.pos, newarg)
//                case _ => System.err.println("resolveLocalVarType lhs problem: " + as.lhs)
//              }
//            case ts: ThrowStatement => 
//              val varname = ts.varSymbol.varName
//              val newarg = findRecentVarsOrUpdate(n, varname, ExceptionCenter.EXCEPTION)
//              locCode = updateCode(locCode, ts.varSymbol.id.pos, newarg)
//            case is: IfStatement =>
//              val left = is.cond.left.varName
//              is.cond.right match {
//                case Left(v) =>
//                  val newright = findRecentVarsOrUpdate(n, v.varName, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                  locCode = updateCode(locCode, v.id.pos, newright)
//                case Right(c) =>
//                  if(recentvars(n).contains(left)){
//                    val tmpleft = findRecentVarsOrUpdate(n, left, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//                    val (typ, _) = localvars(tmpleft)
//                    JavaKnowledge.isJavaPrimitive(typ) match {
//                      case true =>
//                      case false =>
//                        locCode = updateCode(locCode, c.pos, "null")
//                    }
//                  }
//              }
//              val newleft = findRecentVarsOrUpdate(n, left, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//              locCode = updateCode(locCode, is.cond.left.id.pos, newleft)
//            case gs: GotoStatement =>
//            case ss: SwitchStatement =>
//              val varname = ss.condition.varName
//              val newvar = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//              locCode = updateCode(locCode, ss.condition.id.pos, newvar)
//            case rs: ReturnStatement =>
//              rs.varOpt match {
//                case Some(v) =>
//                  val varname = v.varName
//                  val newvar = findRecentVarsOrUpdate(n, varname, sig.getReturnType())
//                  locCode = updateCode(locCode, v.id.pos, newvar)
//                case None =>
//              }
//            case ms: MonitorStatement =>
//              val varname = ms.varSymbol.varName
//              val newvar = findRecentVarsOrUpdate(n, varname, JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE)
//              locCode = updateCode(locCode, ms.varSymbol.id.pos, newvar)
//            case es: EmptyStatement =>
//            case _ =>
//          }
//          locations(index) = locCode
//        case _ =>
//      }
//    }
//    
//    localvars foreach {
//      case (v, (typ, isParam)) =>
//        if(!isParam)
//          sb.append("      " + typ.jawaName.replace(typ.typ, "`" + typ.typ + "`") + " " + v + ";\n")
//    }
//    sb.append("\n")
//    locations.toList.sortBy(_._1) foreach {
//      case (i, loccode) =>
//        sb.append(loccode + "\n")
//    }
//    body.catchClauses foreach {
//      cc =>
//        sb.append(cc.toCode + "\n")
//    }
//    sb.append("}")
//    sb.toString().trim()
//  }
//  
//  private def updateCode(loccode: String, pos: Position, newtext: String): String = {
//    val sb: StringBuffer = new StringBuffer
//    sb.append(loccode)
//    val start = pos.column
//    val end = pos.column + pos.end - pos.start + 1
//    sb.replace(start, end, newtext)
//    sb.toString().intern()
//  }
//  
////  def resolveCallStatement(code: String): String = {
////    val sb: StringBuilder = new StringBuilder
////    val reporter = new DefaultReporter
////    val cuOpt: Option[CompilationUnit] = JawaParser.parse[CompilationUnit](Left(code), true, reporter)
////    cuOpt match {
////      case Some(cu) =>
////        cu.topDecls.foreach{
////          c =>
////            val classCode = c.toCode
////            val head = if(c.methods.size > 0) code.substring(0, c.methods(0).firstToken.pos.start - c.methods(0).firstToken.pos.column) else code
////            sb.append(head)
////            c.methods foreach {
////              m =>
////                val methodcode = RemoveTempAndDoubleLongVars(m)
////                sb.append(methodcode + "\n")
////            }
////        }
////      case None =>
////        System.err.println(reporter.problems.toString())
////        sb.append(code + "\n")
////    }
////    sb.toString().trim()
////  }
//  
////  private def RemoveTempAndDoubleLongVars(md: MethodDeclaration): String = {
////    val sb: StringBuilder = new StringBuilder
////    val ccChange: MMap[String, String] = mmapEmpty
////    val body: ResolvedBody = md.body match {
////      case rb: ResolvedBody =>
////        rb
////      case ub: UnresolvedBody =>
////        ub.resolve
////    }
////    val code = md.toCode
////    val head: String = 
////      if(code.indexOf("#") != -1) code.substring(0, code.indexOf("#") - 1)
////      else code.substring(0, code.indexOf("}") - 1)
////    sb.append(head + "\n")
////    var skip: Int = 0
////    body.locations foreach {
////      location =>
////        var linecode = location.toCode
////        if(skip == 0){
////          location.statement match {
////            case cs: CallStatement =>
////              val typs = cs.signature.getParameterTypes()
////              val args = cs.argClause.varSymbols.map(_._1)
////              var j = args.size - 1
////              for(x <- 1 to typs.size) {
////                val i = typs.size - x
////                val typ = typs(i)
////                typ.name match {
////                  case "double" | "long" =>
////                    val v1pos = args(j-1).id.pos
////                    val v2pos = args(j).id.pos
////                    val pos = Position.range(v1pos.source, v1pos.start, v2pos.end - v1pos.start + 1, v1pos.line, v1pos.column)
////                    linecode = updateCode(linecode, pos, args(j-1).varName)
////                    j -= 1
////                  case _ =>
////                }
////                j -= 1
////              }
////              cs.signature.getReturnType().name match {
////                case "void" =>
////                  linecode = linecode.replaceAll("temp:=  ", "")
////                case _ =>
//////                  val nextLoc: org.sireum.jawa.sjc.parser.Location = body.locations(location.locationIndex + 1)
//////                  val nextStat: Statement = nextLoc.statement
//////                  nextStat match {
//////                    case as: AssignmentStatement =>
//////                      if(as.rhs.isInstanceOf[NameExpression] && as.rhs.asInstanceOf[NameExpression].name == "temp") {
//////                        val varName = as.lhs.asInstanceOf[NameExpression].varSymbol.left.get.varName
//////                        linecode = linecode.replaceFirst("temp:=", varName + ":=")
//////                        val to = location.locationUri
//////                        val from = nextLoc.locationUri
//////                        ccChange(from) = to
//////                        skip = 1
//////                      } else {
//////                        linecode = linecode.replaceAll("temp:=  ", "")
//////                      }
//////                    case _ =>
//////                      linecode = linecode.replaceAll("temp:=  ", "")
//////                  }
////              }
////            case _ =>
////          }
////          sb.append(linecode + "\n")
////        } else {
////          skip -= 1
////        }
////    }
////    body.catchClauses foreach {
////      cc =>
////        var cctmp = cc.toCode
////        ccChange.foreach {
////          case (f, t) =>
////            cctmp = cctmp.replaceAll(f, t)
////        }
////        sb.append(cctmp + "\n")
////    }
////    sb.append("}")
////    sb.toString().trim()
////  }
//}
