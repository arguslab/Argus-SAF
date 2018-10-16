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

import org.argus.jawa.flow.JawaAlirInfoProvider
import org.argus.jawa.flow.cfg.{CFGLocationNode, CFGNode, CFGVirtualNode}
import org.argus.jawa.flow.dfa._
import org.argus.jawa.flow.rda._
import org.argus.jawa.core.ast._
import org.argus.jawa.core.compiler.parser._
import org.argus.jawa.core.io.{NoPosition, Position}
import org.argus.jawa.core._
import org.argus.jawa.core.elements.{JavaKnowledge, JawaType}
import org.argus.jawa.core.util._

/**
 * @author fgwei
 */
object LocalTypeResolver {
  type N = CFGNode
  type TypeFact = (VarSlot, VarType)
  type LOC = (String, Int)
  type Result = MonotoneDataFlowAnalysisResult[N, TypeFact]

  object CertainLevel extends Enumeration {
    val NOT_SURE, PROBABLY, CERTAIN, IS = Value
  }

  class VarType {
    val types: MSet[(JawaType, CertainLevel.Value)] = msetEmpty
    def addType(typ: JawaType, l: CertainLevel.Value): VarType = {
      types += ((typ, l))
      this
    }
    def addType(typ: (JawaType, CertainLevel.Value)): VarType = {
      types += typ
      this
    }
    def getTypes: ISet[(JawaType, CertainLevel.Value)] = types.toSet

    private def resolvePrimitives(typs: ISet[JawaType]): JawaType = {
      if(typs.contains(JavaKnowledge.DOUBLE)) return JavaKnowledge.DOUBLE
      if(typs.contains(JavaKnowledge.LONG)) return JavaKnowledge.LONG
      if(typs.contains(JavaKnowledge.FLOAT)) return JavaKnowledge.FLOAT
      if(typs.contains(JavaKnowledge.INT)) return JavaKnowledge.INT
      if(typs.contains(JavaKnowledge.SHORT)) return JavaKnowledge.SHORT
      if(typs.contains(JavaKnowledge.CHAR)) return JavaKnowledge.CHAR
      if(typs.contains(JavaKnowledge.BYTE)) return JavaKnowledge.BYTE
      JavaKnowledge.BOOLEAN
    }
    private def resolveType(global: Global, typs: ISet[JawaType]): Option[JawaType] = {
      if(typs.isEmpty) None
      else {
        val prims = typs.filter(_.isPrimitive)
        val objs = typs.filter(_.isObject)
        if(objs.nonEmpty) {
          if(objs.size == 1) return objs.headOption
          var dimensions = 0
          val baseTypes = objs map { obj =>
            if(obj.dimensions > dimensions) {
              dimensions = obj.dimensions
            }
            new JawaType(obj.baseType)
          }
          baseTypes.find{ t =>
            val clazz = global.getClassOrResolve(t)
            val allParentsIncluding = clazz.getAllParents.map(_.getType) + clazz.getType
            objs.diff(allParentsIncluding).isEmpty
          } match {
            case Some(t) => Some(JawaType.addDimensions(t, dimensions))
            case None => Some(JawaType.addDimensions(JavaKnowledge.OBJECT, dimensions))
          }
        } else if(prims.nonEmpty) {
          if(prims.size == 1) return prims.headOption
          Some(resolvePrimitives(typs))
        } else None
      }
    }
    private var typ_cache: Option[JawaType] = None
    def getJawaType(global: Global): JawaType = {
      typ_cache match {
        case Some(t) => t
        case None =>
          val rt = resolveType(global, getTypes.filter(_._2 == CertainLevel.IS).map(_._1)) match {
            case Some(typ) => typ
            case None =>
              resolveType(global, getTypes.filter(_._2 == CertainLevel.CERTAIN).map(_._1)) match {
                case Some(typ) => typ
                case None =>
                  resolveType(global, getTypes.filter(_._2 == CertainLevel.PROBABLY).map(_._1)) match {
                    case Some(typ) => typ
                    case None =>
                      resolveType(global, getTypes.filter(_._2 == CertainLevel.NOT_SURE).map(_._1)) match {
                        case Some(typ) => typ
                        case None => throw new LocalTypeResolveException(NoPosition, "Should not be here.")
                      }
                  }
              }
          }
          typ_cache = Some(rt)
          rt
      }
    }

    def merge(typ: VarType): VarType = {
      types ++= typ.types
      this
    }
    def clear(): Unit = this.types.clear()

    override def toString: String = {
      types.toString()
    }
  }

  def apply(global: Global, md: MethodDeclaration): (IMap[Int, IMap[VarSlot, VarType]], IMap[Int, IMap[VarSlot, VarType]]) = build(global, md)

  def build(global: Global, md: MethodDeclaration): (IMap[Int, IMap[VarSlot, VarType]], IMap[Int, IMap[VarSlot, VarType]]) = {
    val cfg = JawaAlirInfoProvider.buildCfg(md, global)
    val ip = new IntraIngredientProvider[TypeFact](md, cfg)
    val def_types: MMap[Int, MMap[VarSlot, VarType]] = mmapEmpty
    val use_types: MMap[Int, MMap[VarSlot, VarType]] = mmapEmpty
    val defPoints: MMap[Position, VarType] = mmapEmpty
    val gen = new Gen(md, def_types, use_types, defPoints)
    val kill = new Kill()
    val sig = md.signature
    val iota: ISet[TypeFact] = {
      val result = msetEmpty[TypeFact]
      result += ((VarSlot("@@TypeIOTA"), new VarType))
      md.thisParam.foreach { thisP =>
        val slot = VarSlot(thisP.name)
        val typ = new VarType().addType(sig.getClassType, CertainLevel.CERTAIN)
        defPoints(thisP.pos) = typ
        result += ((slot, typ))
      }
      md.paramList.indices foreach { i =>
        sig.getParameterTypes.lift(i) match {
          case Some(paramType) =>
            val slot = VarSlot(md.param(i).name)
            val typ = new VarType().addType(paramType, CertainLevel.CERTAIN)
            defPoints(md.param(i).pos) = typ
            result += ((slot, typ))
          case None => throw new LocalTypeResolveException(md.param(i).paramSymbol.id.pos, "Parameter number mismatched with signature: " + sig)
        }
      }
      def_types.getOrElseUpdate(-1, mmapEmpty) ++= result
      result.toSet
    }
    val initial: ISet[TypeFact] = isetEmpty
    MonotoneDataFlowAnalysisFramework[N, TypeFact, LOC](cfg, forward = true, lub = true, ip, gen, kill, None, iota, initial)
    (def_types.map{case (k, v) => k -> v.toMap}.toMap, use_types.map{case (k, v) => k -> v.toMap}.toMap)
  }

  protected class Gen(md: MethodDeclaration, def_types: MMap[Int, MMap[VarSlot, VarType]], use_types: MMap[Int, MMap[VarSlot, VarType]], defPoints: MMap[Position, VarType])
    extends MonotonicFunction[N, TypeFact] {

    def apply(s: ISet[TypeFact], e: Statement, currentNode: N): ISet[TypeFact] = {
      val locIndex: Int = currentNode match {
        case ln: CFGLocationNode => ln.locIndex
        case _: CFGVirtualNode => throw new LocalTypeResolveException(e.pos, "Gen should not handle virtual node: " + e.toCode)
      }
      val (defs, uses) = getDefaultVarType(md, e, defPoints)
      uses.foreach { case (slot, typ) =>
        s.find{ case (os, _) =>
          os == slot
        } match {
          case Some((_, t)) =>
            t.merge(typ)
            use_types.getOrElseUpdate(locIndex, mmapEmpty)(slot) = t
          case None =>
            throw new LocalTypeResolveException(e.pos, "All use site should have defined before: " + e.toCode)
        }
      }
      val result = msetEmpty[TypeFact]
      defs match {
        case Some((defSlot, defType)) =>
          e match {
            case as: AssignmentStatement =>
              as.rhs match {
                case ie: IndexingExpression =>
                  use_types.getOrElse(locIndex, mmapEmpty).get(VarSlot(ie.base)) match {
                    case Some(typ) =>
                      typ.getTypes.foreach { case (ietyp, c) =>
                        defType.addType(JawaType.addDimensions(ietyp, -1 * ie.dimensions), c)
                      }
                    case None =>
                      throw new LocalTypeResolveException(e.pos, "Should never go here: " + e.toCode)
                  }
                  result += ((defSlot, defType))
                case vne: VariableNameExpression =>
                  use_types.getOrElse(locIndex, mmapEmpty).get(VarSlot(vne.varSymbol.varName)) match {
                    case Some(typ) =>
                      result += ((defSlot, typ))
                    case None =>
                      throw new LocalTypeResolveException(e.pos, "Should never go here: " + e.toCode)
                  }
                case _: StaticFieldAccessExpression =>
                  result += ((defSlot, defType))
                case _: TupleExpression =>
                  s.find{case (slot, _) => slot == defSlot} match {
                    case Some((_, typ)) =>
                      result += ((defSlot, typ.merge(defType)))
                    case None => throw new LocalTypeResolveException(e.pos, "TupleExpression lhs should defined before: " + e.toCode)
                  }
                case ue: UnaryExpression =>
                  use_types.getOrElse(locIndex, mmapEmpty).get(VarSlot(ue.unary.varName)) match {
                    case Some(typ) =>
                      result += ((defSlot, typ))
                    case None =>
                      throw new LocalTypeResolveException(e.pos, "Should never go here: " + e.toCode)
                  }
                case _ =>
                  result += ((defSlot, defType))
              }
            case _ =>
              result += ((defSlot, defType))
          }
        case None =>
      }
      result.foreach { case (slot, typ) =>
        def_types.getOrElseUpdate(locIndex, mmapEmpty)(slot) = typ
      }
      result.toSet
    }
  }

  protected class Kill()
    extends MonotonicFunction[N, TypeFact] {
    def apply(s: ISet[TypeFact], e: Statement, currentNode: N): ISet[TypeFact] = {
      e match {
        case a: Assignment =>
          var r = s
          a.getLhs match {
            case Some(lhs) =>
              lhs match {
                case ne: VariableNameExpression =>
                  a.getRhs match {
                    case _: TupleExpression =>
                    case _ =>
                      r = r.filter{case (slot, _) => slot != VarSlot(ne.varSymbol.varName)}
                  }
                case _ =>
              }
            case None =>
          }
          r
        case _ => s
      }
    }
  }

  private def getDefaultVarType(md: MethodDeclaration, statement: Statement, defPoints: MMap[Position, VarType]): (Option[TypeFact], ISet[TypeFact]) = {
    var defs: Option[TypeFact] = None
    val uses: MSet[TypeFact] = msetEmpty
    statement match {
      case as: AssignmentStatement =>
        val (rhsTyp, level): (JawaType, CertainLevel.Value) = as.rhs match {
          case ae: AccessExpression =>
            uses += ((VarSlot(ae.base), new VarType().addType(JavaKnowledge.OBJECT, CertainLevel.NOT_SURE)))
            val typ = ae.typ
            (typ, CertainLevel.IS)
          case be: BinaryExpression =>
            val (typ, c) = getTypeFromKind(as.kind)
            uses += ((VarSlot(be.left.varName), new VarType().addType(typ, c)))
            be.right match {
              // In binary expression the second operand will be implicitly casted.
              case Left(v) => uses += ((VarSlot(v.varName), new VarType().addType(typ, CertainLevel.NOT_SURE)))
              case Right(_) =>
            }
            (typ, c)
          case ce: CastExpression =>
            uses += ((VarSlot(ce.varName), new VarType().addType(getTypeFromCast(as.kind))))
            (ce.typ.typ, CertainLevel.IS)
          case ce: CmpExpression =>
            uses += ((VarSlot(ce.var1Symbol.varName), new VarType().addType(ce.paramType, CertainLevel.CERTAIN)))
            uses += ((VarSlot(ce.var2Symbol.varName), new VarType().addType(ce.paramType, CertainLevel.CERTAIN)))
            (JavaKnowledge.INT, CertainLevel.IS)
          case _: ConstClassExpression =>
            (JavaKnowledge.CLASS, CertainLevel.IS)
          case e: ExceptionExpression =>
            (e.typ, CertainLevel.IS)
          case ie: IndexingExpression =>
            val (typ, level) = getTypeFromKind(as.kind)
            uses += ((VarSlot(ie.base), new VarType().addType(JawaType.addDimensions(typ, ie.dimensions), level)))
            ie.indices foreach { i =>
              i.index match {
                case Left(v) =>
                  uses += ((VarSlot(v.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.CERTAIN)))
                case Right(_) =>
              }
            }
            (typ, level)
          case ie: InstanceOfExpression =>
            uses += ((VarSlot(ie.varSymbol.varName), new VarType().addType(ie.typExp.typ, CertainLevel.PROBABLY)))
            (JavaKnowledge.BOOLEAN, CertainLevel.IS)
          case le: LengthExpression =>
            uses += ((VarSlot(le.varSymbol.varName), new VarType().addType(JawaType.addDimensions(JavaKnowledge.OBJECT, 1), CertainLevel.NOT_SURE)))
            (JavaKnowledge.INT, CertainLevel.IS)
          case le: LiteralExpression =>
            if(le.isString) {
              (JavaKnowledge.STRING, CertainLevel.IS)
            } else if(le.isLong) {
              (JavaKnowledge.LONG, CertainLevel.PROBABLY)
            } else if(le.isDouble) {
              (JavaKnowledge.DOUBLE, CertainLevel.PROBABLY)
            } else if(le.isInt) {
              if(le.getInt == 0) {
                (JavaKnowledge.INT, CertainLevel.NOT_SURE)
              } else {
                (JavaKnowledge.INT, CertainLevel.PROBABLY)
              }
            } else if(le.isLong) {
              (JavaKnowledge.LONG, CertainLevel.PROBABLY)
            } else if(le.isFloat) {
              (JavaKnowledge.FLOAT, CertainLevel.PROBABLY)
            } else {
              throw new LocalTypeResolveException(statement.pos, "LiteralExpression is not expected: " + statement.toCode)
            }
          case vne: VariableNameExpression =>
            val typ = getTypeFromKind(as.kind)
            uses += ((VarSlot(vne.varSymbol.varName), new VarType().addType(typ)))
            typ
          case sfae: StaticFieldAccessExpression =>
            val typ = sfae.typ
            (typ, CertainLevel.IS)
          case ne: NewExpression =>
            (ne.typ, CertainLevel.IS)
          case nae: NewArrayExpression =>
            nae.varSymbols.foreach { vs =>
              uses += ((VarSlot(vs.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.IS)))
            }
            (nae.typ, CertainLevel.IS)
          case _: NullExpression =>
            (JavaKnowledge.OBJECT, CertainLevel.PROBABLY)
          case te: TupleExpression =>
            val typ = te.constants.find{ con =>
              con.isLong
            } match {
              case Some(_) => JavaKnowledge.LONG
              case None => JavaKnowledge.INT
            }
            (JawaType.addDimensions(typ, 1), CertainLevel.PROBABLY)
          case ue: UnaryExpression =>
            val typ = getTypeFromKind(as.kind)
            uses += ((VarSlot(ue.unary.varName), new VarType().addType(typ)))
            typ
          case _ => throw new LocalTypeResolveException(statement.pos, "Unexpected RHS expression: " + statement.toCode)
        }
        as.lhs match {
          case ae: AccessExpression =>
            uses += ((VarSlot(ae.base), new VarType().addType(JavaKnowledge.OBJECT, CertainLevel.NOT_SURE)))
          case ie: IndexingExpression =>
            uses += ((VarSlot(ie.base), new VarType().addType(JawaType.addDimensions(rhsTyp, ie.dimensions), level)))
            ie.indices foreach { i =>
              i.index match {
                case Left(v) =>
                  uses += ((VarSlot(v.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.CERTAIN)))
                case Right(_) =>
              }
            }
          case vne: VariableNameExpression =>
            defs = Some((VarSlot(vne.name), defPoints.getOrElseUpdate(vne.varSymbol.pos, new VarType().addType(rhsTyp, level))))
          case _: StaticFieldAccessExpression =>
          case _ => throw new LocalTypeResolveException(statement.pos, "Unexpected LHS expression: " + statement.toCode)
        }
      case cs: CallStatement =>
        val sig = cs.signature
        cs.lhsOpt match {
          case Some(lhs) =>
            defs = Some((VarSlot(lhs.name), defPoints.getOrElseUpdate(lhs.pos, new VarType().addType(sig.getReturnType, CertainLevel.IS))))
          case None =>
        }
        cs.recvVarOpt match {
          case Some(recv) =>
            uses += ((VarSlot(recv.varName), new VarType().addType(sig.getClassType, CertainLevel.CERTAIN)))
          case None =>
        }
        for(i <- cs.argVars.indices) {
          val arg = cs.argVar(i)
          val typ = sig.getParameterTypes.lift(i).getOrElse(JavaKnowledge.OBJECT)
          uses += ((VarSlot(arg.varName), new VarType().addType(typ, CertainLevel.CERTAIN)))
        }
      case _: EmptyStatement =>
      case _: GotoStatement =>
      case is: IfStatement =>
        is.cond.right match {
          case Left(v) =>
            uses += ((VarSlot(is.cond.left.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.NOT_SURE)))
            uses += ((VarSlot(v.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.NOT_SURE)))
          case Right(_) =>
            is.cond.op.text match {
              case "==" | "!=" =>
                uses += ((VarSlot(is.cond.left.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.NOT_SURE)))
              case _ =>
                uses += ((VarSlot(is.cond.left.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.PROBABLY)))
            }
        }
      case ms: MonitorStatement =>
        uses += ((VarSlot(ms.varSymbol.varName), new VarType().addType(JavaKnowledge.OBJECT, CertainLevel.NOT_SURE)))
      case rs: ReturnStatement =>
        rs.varOpt.foreach { v =>
          uses += ((VarSlot(v.varName), new VarType().addType(md.signature.getReturnType, CertainLevel.CERTAIN)))
        }
      case ss: SwitchStatement =>
        uses += ((VarSlot(ss.condition.varName), new VarType().addType(JavaKnowledge.INT, CertainLevel.PROBABLY)))
      case ts: ThrowStatement =>
        uses += ((VarSlot(ts.varSymbol.varName), new VarType().addType(ExceptionCenter.THROWABLE, CertainLevel.NOT_SURE)))
    }
    (defs, uses.toSet)
  }

  private def getTypeFromKind(kind: String): (JawaType, CertainLevel.Value) = {
    kind match {
      case "wide" => (JavaKnowledge.LONG, CertainLevel.PROBABLY)
      case "object" => (JavaKnowledge.OBJECT, CertainLevel.NOT_SURE)
      case "boolean" => (JavaKnowledge.BOOLEAN, CertainLevel.CERTAIN)
      case "byte" => (JavaKnowledge.BYTE, CertainLevel.CERTAIN)
      case "char" => (JavaKnowledge.CHAR, CertainLevel.CERTAIN)
      case "short" => (JavaKnowledge.SHORT, CertainLevel.CERTAIN)
      case "long" => (JavaKnowledge.LONG, CertainLevel.CERTAIN)
      case "float" => (JavaKnowledge.FLOAT, CertainLevel.CERTAIN)
      case "double" => (JavaKnowledge.DOUBLE, CertainLevel.CERTAIN)
      case _ => (JavaKnowledge.INT, CertainLevel.PROBABLY)
    }
  }

  private def getTypeFromCast(kind: String): (JawaType, CertainLevel.Value) = {
    kind match {
      case "i2l" | "i2f" | "i2d" | "i2b" | "i2c" | "i2s" => (JavaKnowledge.INT, CertainLevel.CERTAIN)
      case "l2i" | "l2f" | "l2d" => (JavaKnowledge.LONG, CertainLevel.CERTAIN)
      case "f2i" | "f2l" | "f2d" => (JavaKnowledge.FLOAT, CertainLevel.CERTAIN)
      case "d2i" | "d2l" | "d2f" => (JavaKnowledge.DOUBLE, CertainLevel.CERTAIN)
      case _ => (JavaKnowledge.OBJECT, CertainLevel.NOT_SURE)
    }
  }
}

class LocalTypeResolveException(pos: Position, msg: String) extends JawaParserException(pos, msg)