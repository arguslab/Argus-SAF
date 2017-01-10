/*
 * Copyright (c) 2016. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.sourcefile

import org.sireum.pilar.symbol.SymbolTable
import org.sireum.pilar.symbol.SymbolTableProducer
import org.sireum.util._
import org.argus.jawa.core._
import org.argus.jawa.core.util.ASTUtil

/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
class MySTVisitor {
  private val classes: MMap[JawaType, MyClass] = mmapEmpty
  def getClasses: IMap[JawaType, MyClass] = classes.toMap
  
  /**
   * resolve all the classes, fields and procedures from symbol table producer which are provided from symbol table model
   */
  def resolveFromST(st: SymbolTable, level: ResolveLevel.Value): Unit = {
    val stp = st.asInstanceOf[SymbolTableProducer]
    resolveClasses(stp, level)
    resolveGlobalVars(stp, level)
    resolveMethods(stp, level)
  }
  
  /**
   * collect class info from symbol table
   */
  def resolveClasses(stp: SymbolTableProducer, level: ResolveLevel.Value) = {
    val classes = stp.tables.recordTable.map{
      case (uri, rd) =>
        val typ: JawaType = JavaKnowledge.getTypeFromJawaName(rd.name.name)
        val accessFlag: Int = AccessFlag.getAccessFlags(ASTUtil.getAccessFlag(rd))
        var superType: Option[JawaType] = None
        val interfaces: MList[JawaType] = mlistEmpty
        rd.extendsClauses.foreach {
          ec =>
            val isInterface: Boolean = ASTUtil.getKind(ec) == "interface"
            if(isInterface){
              interfaces += JavaKnowledge.getTypeFromJawaName(ec.name.name)
            } else {
              if(superType.isDefined) throw InheritanceError(ec.name.name + " should be interface")
              superType = Some(JavaKnowledge.getTypeFromJawaName(ec.name.name))
            }
        }
        var outerType: Option[JawaType] = None
        if(JavaKnowledge.isInnerClass(typ)) outerType = Some(JavaKnowledge.getOuterTypeFrom(typ))
        
        val myclass = MyClass(accessFlag, typ, superType, interfaces.toList, outerType)
        this.classes(typ) = myclass
        
        rd.attributes.foreach{
          field =>
            val fieldType: JawaType = ASTUtil.getTypeFromTypeSpec(field.typeSpec.get)
            val FQN: FieldFQN = new FieldFQN(field.name.name, fieldType)
            val accessFlag: Int = AccessFlag.getAccessFlags(ASTUtil.getAccessFlag(field))
            val f = MyField(accessFlag, FQN)
            myclass.addField(f)
        }
        myclass
    }.toSet
    classes.foreach{
      c =>
        c.addField(createClassField(c))
    }
  }
  
  private def createClassField(rec: MyClass): MyField = {
    MyField(AccessFlag.getAccessFlags("FINAL_STATIC"), FieldFQN(rec.typ, "class", new JawaType("java.lang.Class")))
  }
  
  /**
   * collect global variables info from the symbol table
   */
  def resolveGlobalVars(stp: SymbolTableProducer, level: ResolveLevel.Value) = {
    stp.tables.globalVarTable.foreach{
      case (uri, gvd) =>
        require(gvd.typeSpec.isDefined)
        val globalVarType: JawaType = ASTUtil.getTypeFromTypeSpec(gvd.typeSpec.get)
        val FQN = new FieldFQN(gvd.name.name.replaceAll("@@", ""), globalVarType) // e.g. @@java.lang.Enum.serialVersionUID
        val accessFlag = AccessFlag.getAccessFlags(ASTUtil.getAccessFlag(gvd))
        val f = MyField(accessFlag, FQN)
        val ownerType = FQN.owner
        val owner = this.classes(ownerType)
        owner.addField(f)
    }
  }
  
  /**
   * collect method info from symbol table
   */
  def resolveMethods(stp: SymbolTableProducer, level: ResolveLevel.Value) = {
    val ms = resolveMethodOnly(stp, level)
    ms foreach {
      m =>
        val ownerType = m.signature.getClassType
        val c: MyClass = this.classes(ownerType)
        c.addMethod(m)
    }
  }
  
  def resolveMethodOnly(stp: SymbolTableProducer, level: ResolveLevel.Value): ISet[MyMethod] = {
    val col = stp.tables.procedureAbsTable
    col.map{
      case (uri, pd) =>
        val signature = ASTUtil.getSignature(pd).get
        val accessFlag = AccessFlag.getAccessFlags(ASTUtil.getAccessFlag(pd))
        val paramNames = pd.params.map{_.name.name}.toList
        val m: MyMethod = MyMethod(accessFlag, signature, paramNames)
        
        if(level >= ResolveLevel.BODY){
            m.setBody(stp.procedureSymbolTableProducer(uri).asInstanceOf[MethodBody])
//          if(pd.body.isInstanceOf[ImplementedBody]){
//            val body = pd.body.asInstanceOf[ImplementedBody]
//            val catchclauses = body.catchClauses
//            catchclauses.foreach{
//              catchclause =>
//                require(catchclause.typeSpec.isDefined)
//                require(catchclause.typeSpec.get.isInstanceOf[NamedTypeSpec])
//                val excName = catchclause.typeSpec.get.asInstanceOf[NamedTypeSpec].name.name
//                proc.addExceptionHandler(excName, catchclause.fromTarget.name, catchclause.toTarget.name, catchclause.jump.target.name)
//            }
//          }
        }
        m
    }.toSet
  }
}
