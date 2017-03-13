/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.core.dedex

import org.argus.jawa.core.{JavaKnowledge, JawaType, Signature}
import org.sireum.util._

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
object DedexTypeResolver {
  
  final case class Position(base: Long, pos: Int)
  
  sealed trait DedexType
  case class DedexJawaType(typ: JawaType) extends DedexType

  case class DedexUndeterminedType(defsite: Position, defaultType: JawaType, objectable: Boolean) extends DedexType {
    def possible(position: Position, typ: JawaType, isLeft: Boolean): DedexUndeterminedType = {
      typs += ((position, typ, isLeft))
      this
    }
    val typs: MSet[(Position, JawaType, Boolean)] = msetEmpty
    val typHolders: MSet[Position] = msetEmpty
    val mergepos: MSet[Long] = msetEmpty
  }
}

trait DedexTypeResolver { self: DexInstructionToPilarParser =>
  import DedexTypeResolver._
  
  /**
   * Key of the method invocation result value in the register map
   */
  final def REGMAP_RESULT_KEY = -1
  
  protected[dedex] val regMap: MMap[Int, DedexType] = mmapEmpty
  protected[dedex] val localvars: MMap[String, (JawaType, Boolean)] = mmapEmpty // map from variable -> (typ, isParam)
  def getLocalVars: IMap[String, (JawaType, Boolean)] = localvars.toMap
  protected[dedex] val positionTypMap: MMap[Position, JawaType] = mmapEmpty // stores types resolved from first pass
  protected[dedex] val undeterminedMap: MMap[Position, DedexUndeterminedType] = mmapEmpty
  /**
   * Sets the register map. This is used to initialize/restore the map e.g. after branching.
   * @param regMap The register map to set.
   */
  def setRegisterMap(regMap: IMap[Int, DedexType]): Unit = {
    this.regMap.clear()
    this.regMap ++= regMap
  }
  
  def setLocalVars(localvars: IMap[String, (JawaType, Boolean)]) = {
    this.localvars.clear()
    this.localvars ++= localvars
  }
  
  /**
   * Returns the current register map. This maps register numbers to types in the registers.
   * @return the current register map
   */
  def getRegisterMap: IMap[Int, DedexType] = regMap.toMap
  
  implicit class UndeterminedType(typ: JawaType) {
    def undetermined(pos: Position, objectable: Boolean): DedexUndeterminedType = {
      undeterminedMap.getOrElseUpdate(pos, DedexUndeterminedType(pos, typ, objectable))
    }
  }
  
  protected[dedex] def genRegName(reg: Int, typ: DedexType): String = {
    genVarName("v" + reg, typ)
  }
  
  protected[dedex] def genVarName(v: String, typ: DedexType): String = {
    typ match {
      case jt: DedexJawaType =>
        var newvar = jt.typ.baseTyp.substring(jt.typ.baseTyp.lastIndexOf(".") + 1) + {if(jt.typ.dimensions > 0)"_arr" + jt.typ.dimensions else ""} + "_" + v
        while(localvars.contains(newvar) && localvars(newvar)._1 != jt.typ) newvar = "a_" + newvar
        if(!localvars.contains(newvar)) localvars(newvar) = (jt.typ, false)
        newvar
      case _ => v
    }
    
  }
  
  protected[dedex] def resolveRegType(position: Position, reg: Int, defaultTyp: JawaType, isLeft: Boolean, isHolder: Boolean = false): DedexType = {
    if(secondPass) {
      DedexJawaType(this.positionTypMap.getOrElseUpdate(position, defaultTyp))
    } else {
      val typ = this.regMap.getOrElseUpdate(reg, DedexJawaType(defaultTyp))
      val theDefaultTyp = this.positionTypMap.getOrElseUpdate(position, defaultTyp)
      typ match {
        case ut: DedexUndeterminedType =>
          if(isHolder) {
            ut.typHolders += position
            ut
          } else if (!ut.objectable && theDefaultTyp.isObject) {
            if(isLeft)
              this.regMap(reg) = DedexJawaType(theDefaultTyp)
            this.positionTypMap(position) = theDefaultTyp
            DedexJawaType(theDefaultTyp)
          } else if (ut.typs.exists(_._2.isPrimitive) && theDefaultTyp.isObject) {
            if(isLeft)
              this.regMap(reg) = DedexJawaType(theDefaultTyp)
            this.positionTypMap(position) = theDefaultTyp
            DedexJawaType(theDefaultTyp)
          } else {
            ut.possible(position, theDefaultTyp, isLeft)
          }
        case jt: DedexJawaType =>
          var result = jt.typ
          if(isLeft) {
            result = theDefaultTyp
            this.regMap(reg) = DedexJawaType(result)
          }
          this.positionTypMap(position) = result
          DedexJawaType(result)
      }
    }
  }
  
  protected[dedex] def resolveUndeterminedForMove(ut: DedexUndeterminedType): JawaType = {
    var result: JawaType = ut.defaultType
    val primitiveTyps: MSet[(Position, JawaType)] = msetEmpty
    val arrayTyps: MSet[(Position, JawaType)] = msetEmpty
    val objectTyps: MSet[(Position, JawaType)] = msetEmpty
    ut.typs foreach {
      case (position, typ, _) =>
        if(typ.isArray) arrayTyps += ((position, typ))
        else if(typ.isObject) objectTyps += ((position, typ))
        else primitiveTyps += ((position, typ))
    }
    if(ut.objectable) {
      if(arrayTyps.isEmpty) {
        val otyplist = objectTyps.toList
        var res = otyplist.head._2
        otyplist.tail foreach {
          case (position, typ) =>
            val oldSig = JavaKnowledge.formatTypeToSignature(res)
            val newSig = JavaKnowledge.formatTypeToSignature(typ)
            if(oldSig != newSig) {
              try {
                var ancestorSig = dexOffsetResolver.findCommonAncestor(oldSig, newSig)
                if(ancestorSig != null) {
                  ancestorSig = "L" + ancestorSig + ";"
                  res = JavaKnowledge.formatSignatureToType(ancestorSig)
                }
              } catch {
                case e: Exception =>
                  res = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
              }
            }
        }
        otyplist foreach {
          case (position, typ) =>
            this.positionTypMap(position) = res
        }
        result = res
      } else {
        if(arrayTyps.size == 1) result = arrayTyps.head._2
        arrayTyps foreach{case (position, _ ) => this.positionTypMap(position) = result}
      }
      ut.typHolders.foreach(this.positionTypMap(_) = result)
    } else {
      if(primitiveTyps.size == 1) result = primitiveTyps.head._2
      primitiveTyps foreach{case (position, _ ) => this.positionTypMap(position) = result}
    }
    result
  }
  
  protected[dedex] def resolveUndeterminedForConst(ut: DedexUndeterminedType): IList[JawaType] = {
    val result: MSet[JawaType] = msetEmpty
//    val rightTyps: MList[(Position, JawaType)] = mlistEmpty
//    val leftTyps: MList[(Position, JawaType)] = mlistEmpty
    if(ut.typs.isEmpty) {
      result += ut.defaultType
    } else {
      val primitiveTyps: MSet[(Position, JawaType)] = msetEmpty
      val objectable: MSet[Position] = msetEmpty
      ut.typs foreach {
        case (position, typ, _) =>
          if(typ.isArray || typ.isObject) objectable += position
          else primitiveTyps += ((position, typ))
      }
      primitiveTyps foreach {
        case (position, typ) =>
          result += typ
          this.positionTypMap(position) = typ
      }
      if(objectable.nonEmpty) {
        val typ = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
        result += typ
        objectable.foreach {
          position =>
            this.positionTypMap(position) = typ
        }
        ut.typHolders.foreach(this.positionTypMap(_) = typ)
      }
//      arrayTyps foreach {
//        case (position, typ) =>
//          result += typ
//          this.positionTypMap(position) = typ
//          ut.typHolders.foreach(this.positionTypMap(_) = typ)
//      }
//      if(!objectTyps.isEmpty) {
//        val otyplist = objectTyps.toList
//        var res = otyplist.head._2
//        otyplist.tail foreach {
//          case (position, typ) =>
//            val oldSig = JavaKnowledge.formatTypeToSignature(res)
//            val newSig = JavaKnowledge.formatTypeToSignature(typ)
//            if(oldSig != newSig) {
//              try {
//                var ancestorSig = dexOffsetResolver.findCommonAncestor(oldSig, newSig)
//                if(ancestorSig != null) {
//                  ancestorSig = "L" + ancestorSig + ";"
//                  res = JavaKnowledge.formatSignatureToType(ancestorSig)
//                }
//              } catch {
//                case e: Exception =>
//                  res = JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
//              }
//            }
//        }
//        otyplist foreach {
//          case (position, typ) =>
//            this.positionTypMap(position) = res
//        }
//        ut.typHolders.foreach(this.positionTypMap(_) = res)
//        result += res
//      }
    }
    result.toList
  }

  protected[dedex] def getArgNames(args: IList[(Position, Int)], isStatic: Boolean, signature: Signature): IList[String] = {
    var recvarg: Option[(Position, Int)] = None
    val othargs: MList[(Position, Int, JawaType)] = mlistEmpty
    val ptyps = signature.getParameterTypes
    var j = 0
    var nextpass = false
    for(i <- args.indices) {
      val (position, arg) = args(i)
      if(!isStatic && i == 0) {
        recvarg = Some((position, arg))
      } else {
        val ptyp =
          if(ptyps.isDefinedAt(j)) ptyps(j)
          else JavaKnowledge.JAVA_TOPLEVEL_OBJECT_TYPE
        ptyp match {
          case pt if pt.jawaName == "long" || pt.jawaName == "double" =>
            if(!nextpass) {
              othargs += ((position, arg, ptyp))
              nextpass = true
            } else {
              nextpass = false
              j += 1
            }
          case _ =>
            othargs += ((position, arg, ptyp))
            j += 1
        }
      }
    }
    val res: MList[String] = mlistEmpty
    res ++= recvarg map{case (position, arg) => genRegName(arg, resolveRegType(position, arg, signature.getClassType, isLeft = false))}
    res ++= othargs.map{case (position, arg, typ) => genRegName(arg, resolveRegType(position, arg, typ, isLeft = false))}
    res.toList
  }
  
}
