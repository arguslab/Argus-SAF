/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.ast._
import org.argus.jawa.core.elements._
import org.argus.jawa.core.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
object PointsCollector {
  
  def collectMethodPoint(ownerSig: Signature, md: MethodDeclaration): Point with Method = {
    val methodSig = md.signature
    val types = methodSig.getParameterTypes
    val thisTyp = methodSig.getClassType

    var thisPEntry: PointThisEntry = null
    var thisPExit: PointThisExit = null
    val paramPsEntry: MMap[Int, PointParamEntry] = mmapEmpty
    val paramPsExit: MMap[Int, PointParamExit] = mmapEmpty
    md.thisParam.foreach{ t =>
      thisPEntry = PointThisEntry(t.name, thisTyp, ownerSig)
      thisPExit = PointThisExit(t.name, thisTyp, ownerSig)
    }
    var j = 0 // control type traversal
    md.paramList.foreach { param =>
      if (param.isObject) {
        paramPsEntry += (j -> PointParamEntry(param.name, types(j), j, ownerSig))
        paramPsExit += (j -> PointParamExit(param.name, types(j), j, ownerSig))
      }
      j += 1
    }
    
    var retP: Option[PointMethodRet] = None
    if(methodSig.isReturnObject){
      retP = Some(PointMethodRet(methodSig))
    }

    val accessTyp = md.accessModifier
    if(AccessFlag.isStatic(AccessFlag.getAccessFlags(accessTyp))){
      PointStaticMethod(methodSig, accessTyp, paramPsEntry.toMap, paramPsExit.toMap, retP, ownerSig)
    } else {
      if(thisPEntry == null) throw new RuntimeException("Virtual method " + methodSig + " does not have 'this' param.")
      PointMethod(methodSig, accessTyp, thisPEntry, thisPExit, paramPsEntry.toMap, paramPsExit.toMap, retP, ownerSig)
    }
  }
  
  def points(ownerSig: Signature, md: MethodDeclaration): Set[Point] = {
    val points: MSet[Point] = msetEmpty
    var locUri: String = ""
    var locIndex = 0

    val procPoint = collectMethodPoint(ownerSig, md)
    points += procPoint
    
    def processLHS(e: Expression with LHS): Point with Left = {
      e match {
        case vne: VariableNameExpression =>
          PointL(vne.name, locUri, locIndex, ownerSig)
        case sfae: StaticFieldAccessExpression =>
          val fqn = new FieldFQN(sfae.name, sfae.typ)
          PointStaticFieldL(fqn, locUri, locIndex, ownerSig)
        case ie: IndexingExpression =>
          val dimensions = ie.dimensions
          PointMyArrayL(ie.base, dimensions, locUri, locIndex, ownerSig)
        case ae: AccessExpression =>
          val baseName = ae.base
          val pBase = PointBaseL(baseName, locUri, locIndex, ownerSig)
          val fqn = new FieldFQN(ae.fieldSym.FQN, ae.typ)
          val pfl = PointFieldL(pBase, fqn, locUri, locIndex, ownerSig)
          pBase.setFieldPoint(pfl)
          pfl
        case _ =>
          throw new RuntimeException(s"Unknown left hand side $e")
      }
    }
    
    def processRHS(e: Expression with RHS): Point with Right = {
      e match {
        case ae: AccessExpression =>
          val baseName = ae.base
          val pBase = PointBaseR(baseName, locUri, locIndex, ownerSig)
          val fqn = new FieldFQN(ae.fieldSym.FQN, ae.typ)
          val pfr = PointFieldR(pBase, fqn, locUri, locIndex, ownerSig)
          pBase.setFieldPoint(pfr)
          pfr
//        case be: BinaryExpression =>
//        case cr: CallRhs =>
        case ce: CastExpression =>
          val name = ce.varName
          PointCastR(ce.typ.typ, name, locUri, locIndex, ownerSig)
//        case ce: CmpExpression =>
        case ce: ConstClassExpression =>
          PointClassO(new JawaType("java.lang.Class"), ce.typExp.typ, locUri, locIndex, ownerSig)
        case ee: ExceptionExpression =>
          PointExceptionR(ee.typ.toUnknown, locUri, locIndex, ownerSig)
        case ie: IndexingExpression =>
          val dimensions = ie.dimensions
          PointMyArrayR(ie.base, dimensions, locUri, locIndex, ownerSig)
        case ie: InstanceOfExpression =>
          PointInstanceOfR(ie.varSymbol.varName, ie.typExp.typ, locUri, locIndex, ownerSig)
        case le: LengthExpression =>
          PointLengthR(le.varSymbol.varName, locUri, locIndex, ownerSig)
        case le: LiteralExpression =>
          PointStringO(new JawaType("java.lang.String"), le.getString , locUri, locIndex, ownerSig)
        case vne: VariableNameExpression =>
          PointR(vne.name, locUri, locIndex, ownerSig)
        case sfae: StaticFieldAccessExpression =>
          val fqn = new FieldFQN(sfae.name, sfae.typ)
          PointStaticFieldR(fqn, locUri, locIndex, ownerSig)
        case ne: Expression with New =>
          PointO(ne.typ, locUri, locIndex, ownerSig)
        case _: NullExpression =>
          PointO(JavaKnowledge.OBJECT, locUri, locIndex, ownerSig)
//        case te: TupleExpression =>
//        case _: UnaryExpression =>
        case _ => throw new RuntimeException("Unexpected rhs expression: " + e)
      }
    }
      
    val visitor = Visitor.build({
      case l: Location =>
        locUri = l.locationUri
        locIndex = l.locationIndex
        true
      case as: AssignmentStatement =>
        var pl: Option[Point with Left] = None
        var pr: Option[Point with Right] = None
        
        as.getRhs match {
          case ae: AccessExpression =>
            if(as.kind == "object"){
              pl = Some(processLHS(as.lhs))
              pr = Some(processRHS(ae))
            }
          case _: BinaryExpression =>
          case _: CallRhs =>
          case ce: CastExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ce))
          case _: CmpExpression =>
          case ce: ConstClassExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ce))
          case ee: ExceptionExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ee))
          case ie: IndexingExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ie))
          case ie: InstanceOfExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ie))
          case le: LengthExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(le))
          case le: LiteralExpression =>
            if(le.isString){
              pl = Some(processLHS(as.lhs))
              pr = Some(processRHS(le))
            }
          case vne: VariableNameExpression =>
            if(as.kind == "object"){
              pl = Some(processLHS(as.lhs))
              pr = Some(processRHS(vne))
            }
          case sfae: StaticFieldAccessExpression =>
            if(sfae.typ.isObject){
              pl = Some(processLHS(as.lhs))
              pr = Some(processRHS(sfae))
            }
          case ne: Expression with RHS with New =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ne))
          case ne: NullExpression =>
            pl = Some(processLHS(as.lhs))
            pr = Some(processRHS(ne))
          case _: TupleExpression =>
          case _: UnaryExpression =>
        }
        if(pl.isDefined && pr.isDefined){
          val assignmentPoint: PointAsmt = PointAsmt(pl.get, pr.get, locUri, locIndex, ownerSig)
          points += assignmentPoint
        }
        false
      case cs: CallStatement =>
        var recvPCall: Option[PointRecvCall] = None
        var recvPReturn: Option[PointRecvReturn] = None
        val argPsCall: MMap[Int, PointArgCall] = mmapEmpty
        val argPsReturn: MMap[Int, PointArgReturn] = mmapEmpty
        var i = 0
        cs.recvOpt.foreach { recv =>
          recvPCall = Some(PointRecvCall(recv, i, locUri, locIndex, ownerSig))
          recvPReturn = Some(PointRecvReturn(recv, i, locUri, locIndex, ownerSig))
          i += 1
        }
        cs.args.foreach { arg =>
          argPsCall += (i -> PointArgCall(arg, i, locUri, locIndex, ownerSig))
          argPsReturn += (i -> PointArgReturn(arg, i, locUri, locIndex, ownerSig))
          i += 1
        }
        val pi: Point with Right with Invoke = 
          if(cs.isStatic){
            PointStaticI(cs.signature, cs.kind, cs.signature.getReturnType, argPsCall.toMap, argPsReturn.toMap, locUri, locIndex, ownerSig)
          } else {
            val p = PointI(cs.signature, cs.kind, cs.signature.getReturnType, recvPCall.get, recvPReturn.get, argPsCall.toMap, argPsReturn.toMap, locUri, locIndex, ownerSig)
            recvPCall.get.setContainer(p)
            recvPReturn.get.setContainer(p)
            p
          }
        argPsCall foreach {case (_, p) => p.setContainer(pi)}
        argPsReturn foreach {case (_, p) => p.setContainer(pi)}
        val pl = cs.lhsOpt.map{lhs => processLHS(lhs)}
        val callPoint: PointCall = PointCall(pl, pi, locUri, locIndex, ownerSig)
        points += callPoint
        false
      case rj: ReturnStatement =>
        if(rj.kind == "object"){
          val p = PointRet(rj.varOpt.get.varName, procPoint, locUri, locIndex, ownerSig)
          points += p
        }
        false
    }) 
    
    val locationDecls = md.resolvedBody.locations
    val size = locationDecls.size
    for (i <- 0 until size) {
      val l = locationDecls(i)
      visitor(l)
    }
    points.toSet
  }
}

/**
 * Set of program points corresponding to assignment expression. 
 */
final case class PointAsmt(lhs: Point with Left, rhs: Point with Right, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to call expression
 */
final case class PointCall(lhsOpt: Option[Point with Left], rhs: Point with Right with Invoke, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to object creating expressions. 
 * An object creating program point abstracts all the objects created
 * at that particular program point.
 */
final case class PointO(obj: JawaType, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to array object creating expressions. 
 * An array object creating program point abstracts all the objects created
 * at that particular program point.
 */
//final case class PointArrayO(obj: ObjectType, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj with Array

/**
 * Set of program points corresponding to string object creating expressions. 
 * An string object creating program point abstracts all the objects created
 * at that particular program point.
 */
final case class PointStringO(obj: JawaType, text: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to l-value. 
 */
final case class PointL(varname: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left

/**
 * Set of program points corresponding to r-value. 
 */
final case class PointR(varname: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to const class value. 
 */
final case class PointClassO(obj: JawaType, classtyp: JawaType, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to cast.
 */
final case class PointCastR(casttyp: JawaType, varname: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to length. 
 */
final case class PointLengthR(varname: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to instanceOf.
 */
final case class PointInstanceOfR(varname: String, typ: JawaType, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to exception.
 */
final case class PointExceptionR(typ: JawaType, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to l-value field access expressions. 
 */
final case class PointFieldL(baseP: PointBaseL, fqn: FieldFQN, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Field

/**
 * Set of program points corresponding to R-value field access expressions. 
 */
final case class PointFieldR(baseP: PointBaseR, fqn: FieldFQN, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Field

/**
 * Set of program points corresponding to l-value array variable. 
 */
final case class PointMyArrayL(arrayname: String, dimensions: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with MyArray

/**
 * Set of program points corresponding to R-value array variable. 
 */
final case class PointMyArrayR(arrayname: String, dimensions: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with MyArray

/**
 * Set of program points corresponding to l-value static field variable. 
 */
final case class PointStaticFieldL(staticFieldFQN: FieldFQN, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Static_Field

/**
 * Set of program points corresponding to R-value static field variable. 
 */
final case class PointStaticFieldR(staticFieldFQN: FieldFQN, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Static_Field

/**
 * Set of program points corresponding to l-value static field array variable. 
 */
final case class PointStaticFieldMyArrayL(staticFieldFQN: FieldFQN, dimensions: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Static_Field with MyArray

/**
 * Set of program points corresponding to R-value static field array variable. 
 */
final case class PointStaticFieldMyArrayR(staticFieldFQN: FieldFQN, dimensions: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Static_Field with MyArray

/**
 * Set of program points corresponding to base part of field access expressions in the LHS. 
 */
final case class PointBaseL(baseName: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Base

/**
 * Set of program points corresponding to base part of field access expressions in the RHS. 
 */
final case class PointBaseR(baseName: String, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Base

/**
 * Set of program points corresponding to method recv variable.
 * pi represents an element in this set.
 */
final case class PointRecvCall(argName: String, index: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Call

/**
 * Set of program points corresponding to method arg variable.
 * pi represents an element in this set.
 */
final case class PointArgCall(argName: String, index: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Call

/**
 * Set of program points corresponding to method recv variable.
 * pi represents an element in this set.
 */
final case class PointRecvReturn(argName: String, index: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Return

/**
 * Set of program points corresponding to method arg variable.
 * pi represents an element in this set.
 */
final case class PointArgReturn(argName: String, index: Int, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Return

/**
 * Set of program points corresponding to method invocation expressions.
 * pi represents an element in this set.
 */
final case class PointI(sig: Signature, invokeTyp: String, retTyp: JawaType, recvPCall: PointRecvCall, recvPReturn: PointRecvReturn, argPsCall: IMap[Int, PointArgCall], argPsReturn: IMap[Int, PointArgReturn], locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Invoke with Virtual

/**
 * Set of program points corresponding to static method invocation expressions.
 * pi represents an element in this set.
 */
final case class PointStaticI(sig: Signature, invokeTyp: String, retTyp: JawaType, argPsCall: IMap[Int, PointArgCall], argPsReturn: IMap[Int, PointArgReturn], locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Invoke

/**
 * Set of program points corresponding to this variable .
 */
final case class PointThisEntry(paramName: String, paramTyp: JawaType, ownerSig: Signature) extends Point with Param with Entry {
  def index: Int = -1
}

/**
 * Set of program points corresponding to params.
 */
final case class PointParamEntry(paramName: String, paramTyp: JawaType, index: Int, ownerSig: Signature) extends Point with Param with Entry

/**
 * Set of program points corresponding to this variable .
 */
final case class PointThisExit(paramName: String, paramTyp: JawaType, ownerSig: Signature) extends Point with Param with Exit {
  def index: Int = -1
}

/**
 * Set of program points corresponding to params.
 */
final case class PointParamExit(paramName: String, paramTyp: JawaType, index: Int, ownerSig: Signature) extends Point with Param with Exit

/**
 * Set of program points corresponding to return variable.
 */
final case class PointRet(retname: String, procPoint: Point with Method, locUri: String, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to return variable (fake one).
 */
final case class PointMethodRet(ownerSig: Signature) extends Point

/**
 * Set of program points corresponding to methods. 
 */
final case class PointMethod(methodSig: Signature, accessTyp: String, thisPEntry: PointThisEntry, thisPExit: PointThisExit, paramPsEntry: IMap[Int, PointParamEntry], paramPsExit: IMap[Int, PointParamExit], retVar: Option[PointMethodRet], ownerSig: Signature) extends Point with Method with Dynamic

/**
 * Set of program points corresponding to static methods. 
 */
final case class PointStaticMethod(methodSig: Signature, accessTyp: String, paramPsEntry: IMap[Int, PointParamEntry], paramPsExit: IMap[Int, PointParamExit], retVar: Option[PointMethodRet], ownerSig: Signature) extends Point with Method
