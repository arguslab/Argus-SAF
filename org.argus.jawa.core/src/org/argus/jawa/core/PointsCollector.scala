/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core

import org.argus.jawa.core.util.ASTUtil
import org.sireum.pilar.symbol.ProcedureSymbolTable
import org.sireum.util._
import org.sireum.pilar.ast._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */ 
class PointsCollector {
  
  def collectMethodPoint(ownerSig: Signature, pst: ProcedureSymbolTable): Point with Method = {
    val methodSig = ASTUtil.getSignature(pst.procedure).get
    
    val types = methodSig.getParameterTypes
    val thisTyp = methodSig.getClassType
    
    val accessTyp = pst.procedure.getValueAnnotation("AccessFlag") match{
      case Some(acc) =>
        acc match {
          case ne: NameExp =>
            ne.name.name
          case _ => ""
        }
      case None => ""
    }

    var thisPEntry: PointThisEntry = null
    var thisPExit: PointThisExit = null
    val paramPsEntry: MMap[Int, PointParamEntry] = mmapEmpty
    val paramPsExit: MMap[Int, PointParamExit] = mmapEmpty
    var j = 0 // control type traversal
    pst.procedure.params.foreach(
      param => {
        if(is("this", param.annotations)){
          thisPEntry = PointThisEntry(param.name.name, thisTyp, ownerSig)
          thisPExit = PointThisExit(param.name.name, thisTyp, ownerSig)
          j -= 1
        } else if(is("object", param.annotations)){
          paramPsEntry += (j -> PointParamEntry(param.name.name, types(j), j, ownerSig))
          paramPsExit += (j -> PointParamExit(param.name.name, types(j), j, ownerSig))
        }
        j += 1
      }
    )
    
    var retP: Option[PointMethodRet] = None
    if(methodSig.isReturnObject){
      retP = Some(PointMethodRet(methodSig))
    }
    
    if(AccessFlag.isStatic(AccessFlag.getAccessFlags(accessTyp))){
      PointStaticMethod(methodSig, accessTyp, paramPsEntry.toMap, paramPsExit.toMap, retP, ownerSig)
    } else {
      if(thisPEntry == null) throw new RuntimeException("Virtual method " + methodSig + " does not have 'this' param.")
      PointMethod(methodSig, accessTyp, thisPEntry, thisPExit, paramPsEntry.toMap, paramPsExit.toMap, retP, ownerSig)
    }
  }
  
  /**
   * Resolve native method node collect
   */
//  def resolveNativeMethod(pst: ProcedureSymbolTable, pMethod: PointMethod) = {
//    val thisP = PointThis("native", pst.procedureUri)
//    pMethod.setThisParam(thisP)
//  }
  
  /**
   * get type from annotations, if it is an object type return true else false
   */
  def is(typ: String, annots: ISeq[Annotation]): Boolean = {
    annots.exists{
      annot =>
        annot.params.exists{
          param =>{
            param match {
              case ExpAnnotationParam(_, NameExp(name)) =>
                name.name.equals(typ)
              case _ => false
            }
          }
        }
    }
  }
  
  def points(ownerSig: Signature, pst: ProcedureSymbolTable): Set[Point] = {
    val points: MSet[Point] = msetEmpty
    var loc: ResourceUri = ""
    var locIndex = 0

    val procPoint = collectMethodPoint(ownerSig, pst)
    points += procPoint
    
    def getLocUri(l: LocationDecl) =
      if (l.name.isEmpty)
        ""
      else
        l.name.get.uri
          
    def isStaticField(name: String): Boolean = {
      name.startsWith("@@")
    }
    
    def processLHS(e: Exp, typ: Option[JawaType]): Point with Left = {
      e match {
        case n: NameExp =>
          if(isStaticField(n.name.name)){
            val fqn = new FieldFQN(n.name.name.replace("@@", ""), typ.get)
            PointStaticFieldL(fqn, loc, locIndex, ownerSig)
          } else {
            PointL(n.name.name, loc, locIndex, ownerSig)
          }
        case ie: IndexingExp =>
          ie.exp match {
            case n: NameExp =>
              val dimensions = ie.indices.size
              if(isStaticField(n.name.name)){
                val fqn = new FieldFQN(n.name.name.replace("@@", ""), typ.get)
                PointStaticFieldArrayL(fqn, dimensions, loc, locIndex, ownerSig)
              } else {
                PointArrayL(n.name.name, dimensions, loc, locIndex, ownerSig)
              }
            case _ => null
          }
        case ae: AccessExp =>
          val baseName = ae.exp match {
            case ne: NameExp => ne.name.name
            case _ => ""
          }
          val pBase = PointBaseL(baseName, loc, locIndex, ownerSig)
          val fqn = new FieldFQN(ae.attributeName.name, typ.get)
          val pfl = PointFieldL(pBase, fqn, loc, locIndex, ownerSig)
          pBase.setFieldPoint(pfl)
          pfl
        case _ => null
      }
    }
    
    def processRHS(e: Exp, typ: Option[JawaType]): Point with Right = {
      e match {
        case n: NameExp =>
          if(n.name.name == Constants.CONST_CLASS){
            PointClassO(new JawaType("java.lang.Class"), typ.get, loc, locIndex, ownerSig)
          } else if (n.name.name == Constants.LENGTH) {
            val varname: String = e.getValueAnnotation("variable") match {
              case Some(NameExp(name)) =>
                name.name
              case _ => ""
            }
            PointLengthR(varname, loc, locIndex, ownerSig)
          } else if (n.name.name == Constants.INSTANCEOF) {
            val varname: String = e.getValueAnnotation("variable") match {
              case Some(NameExp(name)) =>
                name.name
              case _ => ""
            }
            val typ: JawaType = ASTUtil.getType(e).get
            PointInstanceOfR(varname, typ, loc, locIndex, ownerSig)
          } else if (n.name.name == Constants.EXCEPTION) {
            PointExceptionR(typ.get.toUnknown, loc, locIndex, ownerSig)
          } else if(isStaticField(n.name.name)){
            val fqn = new FieldFQN(n.name.name.replace("@@", ""), typ.get)
            PointStaticFieldR(fqn, loc, locIndex, ownerSig)
          } else {
            PointR(n.name.name, loc, locIndex, ownerSig)
          }
        case ie: IndexingExp =>
          val dimensions = ie.indices.size
          ie.exp match {
            case n: NameExp =>
              if(isStaticField(n.name.name)){
                val fqn = new FieldFQN(n.name.name.replace("@@", ""), typ.get)
                PointStaticFieldArrayR(fqn, dimensions, loc, locIndex, ownerSig)
              } else {
                PointArrayR(n.name.name, dimensions, loc, locIndex, ownerSig)
              }
            case _ => null
          }
        case ae: AccessExp =>
          val baseName = ae.exp match {
            case ne: NameExp => ne.name.name
            case _ => ""
          }
          val pBase = PointBaseR(baseName, loc, locIndex, ownerSig)
          val fqn = new FieldFQN(ae.attributeName.name, typ.get)
          val pfr = PointFieldR(pBase, fqn, loc, locIndex, ownerSig)
          pBase.setFieldPoint(pfr)
          pfr
        case ce: CastExp =>
          val name = ce.exp match {
            case ne: NameExp => ne.name.name
            case _ => ""
          }
          val typ = ASTUtil.getTypeFromTypeSpec(ce.typeSpec)
          PointCastR(typ, name, loc, locIndex, ownerSig)
        case _ => null
      }
    }
      
    val visitor = Visitor.build({
      case ld: LocationDecl => 
        loc = getLocUri(ld)
        locIndex = ld.index
        true
      case t: Transformation =>
        true
      case as: AssignAction =>
        var pl: Point with Left = null
        var pr: Point with Right = null
        val typ: Option[JawaType] = ASTUtil.getType(as)
        
        as.rhs match {
          case le: LiteralExp =>
            if(le.typ.name.equals("STRING")){
              pl = processLHS(as.lhs, typ)
              pr = PointStringO(new JawaType("java.lang.String"), le.text , loc, locIndex, ownerSig)
            }
            if(le.typ.name.equals("null")) {
              pl = processLHS(as.lhs, typ)
              pr = PointO(JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE, loc, locIndex, ownerSig)
            }
          case n: NewExp =>
            pl = processLHS(as.lhs, typ)
            var name: ResourceUri = ""
            var dimensions = 0
            n.typeSpec match {
              case nt: NamedTypeSpec => 
                dimensions = n.dims.size + n.typeFragments.size
                name = nt.name.name
              case _ =>
            }
            pr = PointO(new JawaType(name, dimensions), loc, locIndex, ownerSig)
          case n: NameExp =>
            if(is("object", as.annotations)){
              pl = processLHS(as.lhs, typ)
              pr = processRHS(n, typ)
            }
          case ae: AccessExp =>
            if(is("object", as.annotations)){
              pl = processLHS(as.lhs, typ)
              pr = processRHS(ae, typ)
            }
          case ie: IndexingExp =>
            pl = processLHS(as.lhs, typ)
            pr = processRHS(ie, typ)
          case ce: CastExp =>
            pl = processLHS(as.lhs, typ)
            pr = processRHS(ce, typ)
          case _ =>
        }
        if(pl != null && pr != null){
          val assignmentPoint: PointAsmt = PointAsmt(pl, pr, loc, locIndex, ownerSig)
          points += assignmentPoint
        }
        false
      case t: CallJump if t.jump.isEmpty =>
        var pl: Option[PointL] = None
        val sig = ASTUtil.getSignature(t).get
        val invokeTyp = ASTUtil.getKind(t)
        val retTyp = sig.getReturnType
        
        var recvPCall: PointRecvCall = null
        var recvPReturn: PointRecvReturn = null
        val argPsCall: MMap[Int, PointArgCall] = mmapEmpty
        val argPsReturn: MMap[Int, PointArgReturn] = mmapEmpty

        t.callExp.arg match {
          case te: TupleExp =>
            val exps = te.exps
            var i = 0
            exps foreach {
              exp =>
                require(exp.isInstanceOf[NameExp])
                val ne = exp.asInstanceOf[NameExp]
                if (i == 0 && !invokeTyp.contains("static")) {
                  recvPCall = PointRecvCall(ne.name.name, i, loc, locIndex, ownerSig)
                  recvPReturn = PointRecvReturn(ne.name.name, i, loc, locIndex, ownerSig)
                } else {
                  argPsCall += (i -> PointArgCall(ne.name.name, i, loc, locIndex, ownerSig))
                  argPsReturn += (i -> PointArgReturn(ne.name.name, i, loc, locIndex, ownerSig))
                }
                i += 1
            }
          case _ =>
        }
        val pi: Point with Right with Invoke = 
          if(invokeTyp.contains("static")){
            PointStaticI(sig, invokeTyp, retTyp, argPsCall.toMap, argPsReturn.toMap, loc, locIndex, ownerSig)
          } else {
            if(recvPCall == null) throw new RuntimeException("Dynamic method invokation does not have 'recv' param.")
            val p = PointI(sig, invokeTyp, retTyp, recvPCall, recvPReturn, argPsCall.toMap, argPsReturn.toMap, loc, locIndex, ownerSig)
            recvPCall.setContainer(p)
            recvPReturn.setContainer(p)
            p
          }
        argPsCall foreach {case (_, p) => p.setContainer(pi)}
        argPsReturn foreach {case (_, p) => p.setContainer(pi)}
//        points += pi
        require(t.lhss.size<=1)
        if(t.lhss.size == 1){
          pl = Some(PointL(t.lhss.head.name.name, loc, locIndex, ownerSig))
        }
        val callPoint: PointCall = PointCall(pl, pi, loc, locIndex, ownerSig)
        points += callPoint
        false
      case rj: ReturnJump =>
        if(is("object", rj.annotations)){
          rj.exp match {
            case Some(ne) =>
              ne match {
                case exp: NameExp =>
                  val p = PointRet(exp.name.name, procPoint, loc, locIndex, ownerSig)
                  points += p
                case _ =>
              }
            case None =>
          }
        }
        false
    }) 
    
    val locationDecls = pst.locations
    val size = locationDecls.size
    for (i <- 0 until size) {
      val l = locationDecls(i)
      visitor(l)
    }
//    println("points---> " + points)
    points.toSet
  }
}

/**
 * Set of program points corresponding to assignment expression. 
 */
final case class PointAsmt(lhs: Point with Left, rhs: Point with Right, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to call expression
 */
final case class PointCall(lhsOpt: Option[Point with Left], rhs: Point with Right, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to object creating expressions. 
 * An object creating program point abstracts all the objects created
 * at that particular program point.
 */
final case class PointO(obj: JawaType, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to array object creating expressions. 
 * An array object creating program point abstracts all the objects created
 * at that particular program point.
 */
//final case class PointArrayO(obj: ObjectType, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj with Array

/**
 * Set of program points corresponding to string object creating expressions. 
 * An string object creating program point abstracts all the objects created
 * at that particular program point.
 */
final case class PointStringO(obj: JawaType, text: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to l-value. 
 */
final case class PointL(varname: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left

/**
 * Set of program points corresponding to r-value. 
 */
final case class PointR(varname: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to const class value. 
 */
final case class PointClassO(obj: JawaType, classtyp: JawaType, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with NewObj

/**
 * Set of program points corresponding to const class value. 
 */
final case class PointCastR(casttyp: JawaType, varname: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to length. 
 */
final case class PointLengthR(varname: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to length. 
 */
final case class PointInstanceOfR(varname: String, typ: JawaType, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to length. 
 */
final case class PointExceptionR(typ: JawaType, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right

/**
 * Set of program points corresponding to l-value field access expressions. 
 */
final case class PointFieldL(baseP: PointBaseL, fqn: FieldFQN, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Field

/**
 * Set of program points corresponding to R-value field access expressions. 
 */
final case class PointFieldR(baseP: PointBaseR, fqn: FieldFQN, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Field

/**
 * Set of program points corresponding to l-value array variable. 
 */
final case class PointArrayL(arrayname: String, dimensions: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Array

/**
 * Set of program points corresponding to R-value array variable. 
 */
final case class PointArrayR(arrayname: String, dimensions: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Array

/**
 * Set of program points corresponding to l-value static field variable. 
 */
final case class PointStaticFieldL(staticFieldFQN: FieldFQN, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Static_Field

/**
 * Set of program points corresponding to R-value static field variable. 
 */
final case class PointStaticFieldR(staticFieldFQN: FieldFQN, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Static_Field

/**
 * Set of program points corresponding to l-value static field array variable. 
 */
final case class PointStaticFieldArrayL(staticFieldFQN: FieldFQN, dimensions: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Static_Field with Array

/**
 * Set of program points corresponding to R-value static field array variable. 
 */
final case class PointStaticFieldArrayR(staticFieldFQN: FieldFQN, dimensions: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Static_Field with Array

/**
 * Set of program points corresponding to base part of field access expressions in the LHS. 
 */
final case class PointBaseL(baseName: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Left with Base

/**
 * Set of program points corresponding to base part of field access expressions in the RHS. 
 */
final case class PointBaseR(baseName: String, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Base

/**
 * Set of program points corresponding to method recv variable.
 * pi represents an element in this set.
 */
final case class PointRecvCall(argName: String, index: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Call

/**
 * Set of program points corresponding to method arg variable.
 * pi represents an element in this set.
 */
final case class PointArgCall(argName: String, index: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Call

/**
 * Set of program points corresponding to method recv variable.
 * pi represents an element in this set.
 */
final case class PointRecvReturn(argName: String, index: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Return

/**
 * Set of program points corresponding to method arg variable.
 * pi represents an element in this set.
 */
final case class PointArgReturn(argName: String, index: Int, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Arg with Return

/**
 * Set of program points corresponding to method invocation expressions.
 * pi represents an element in this set.
 */
final case class PointI(sig: Signature, invokeTyp: String, retTyp: JawaType, recvPCall: PointRecvCall, recvPReturn: PointRecvReturn, argPsCall: IMap[Int, PointArgCall], argPsReturn: IMap[Int, PointArgReturn], loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Invoke with Dynamic

/**
 * Set of program points corresponding to static method invocation expressions.
 * pi represents an element in this set.
 */
final case class PointStaticI(sig: Signature, invokeTyp: String, retTyp: JawaType, argPsCall: IMap[Int, PointArgCall], argPsReturn: IMap[Int, PointArgReturn], loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc with Right with Invoke

/**
 * Set of program points corresponding to this variable .
 */
final case class PointThisEntry(paramName: String, paramTyp: JawaType, ownerSig: Signature) extends Point with Param with Entry {
  def index = -1
}

/**
 * Set of program points corresponding to params.
 */
final case class PointParamEntry(paramName: String, paramTyp: JawaType, index: Int, ownerSig: Signature) extends Point with Param with Entry

/**
 * Set of program points corresponding to this variable .
 */
final case class PointThisExit(paramName: String, paramTyp: JawaType, ownerSig: Signature) extends Point with Param with Exit {
  def index = -1
}

/**
 * Set of program points corresponding to params.
 */
final case class PointParamExit(paramName: String, paramTyp: JawaType, index: Int, ownerSig: Signature) extends Point with Param with Exit

/**
 * Set of program points corresponding to return variable.
 */
final case class PointRet(retname: String, procPoint: Point with Method, loc: ResourceUri, locIndex: Int, ownerSig: Signature) extends Point with Loc

/**
 * Set of program points corresponding to return variable (fake one).
 */
final case class PointMethodRet(ownerSig: Signature) extends Point

/**
 * Set of program points corresponding to methods. 
 */
final case class PointMethod(methodSig: Signature, accessTyp: String, thisPEntry: PointThisEntry, thisPExit: PointThisExit, paramPsEntry: IMap[Int, PointParamEntry], paramPsExit: IMap[Int, PointParamExit], retVar: Option[PointMethodRet], ownerSig: Signature) extends Point with Method with Virtual

/**
 * Set of program points corresponding to static methods. 
 */
final case class PointStaticMethod(methodSig: Signature, accessTyp: String, paramPsEntry: IMap[Int, PointParamEntry], paramPsExit: IMap[Int, PointParamExit], retVar: Option[PointMethodRet], ownerSig: Signature) extends Point with Method 
