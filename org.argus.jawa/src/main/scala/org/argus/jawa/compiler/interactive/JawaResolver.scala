/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.compiler.interactive

import org.argus.jawa.compiler.lexer.Token
import org.argus.jawa.compiler.parser._
import org.argus.jawa.core.{JavaKnowledge, JawaType, Reporter}
import org.argus.jawa.core.io.{NoPosition, SourceFile}
import org.sireum.util._

/**
 * this object collects info from the symbol table and builds Global, JawaClass, and JawaMethod
 *
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 */
trait JawaResolver extends JavaKnowledge {self: Global =>
  
//  private val DEBUG: Boolean = false
//  private final val TITLE: String = "JawaResolver"
  
  import scala.reflect.runtime.{ universe => ru }
  
  def parseCode[T <: ParsableAstNode : ru.TypeTag](source: SourceFile, resolveBody: Boolean): Option[T] = {
    val paopt = JawaParser.parse[T](Right(source), resolveBody, reporter) 
    paopt
  }
  
  private def parseBodyTokens(bodyTokens: IList[Token]): Option[ResolvedBody] = {
    val paopt = JawaParser.parse[org.argus.jawa.compiler.parser.Body](bodyTokens, resolveBody = true, reporter)
    paopt map{pa => pa.asInstanceOf[ResolvedBody]}
  }
  
  /**
   * resolve the given method's body to BODY level. 
   */
  def resolveMethodBody(md: MethodDeclaration): MethodDeclaration = {
    parseBodyTokens(md.body.tokens) foreach {
      body => md.body = body
    }
    if(reporter.hasErrors) reporter.error(NoPosition, "Fail to resolve method body for " + md.signature)
    md
  }
  
  def getClassTypes(file: SourceFile, reporter: Reporter): ISet[JawaType] = {
    val cuOpt = JawaParser.parse[CompilationUnit](Right(file), resolveBody = false, reporter)
    cuOpt match {
      case Some(cu) => cu.topDecls.map(_.typ).toSet
      case None => isetEmpty
    }
  }
  
  /**
   * resolve the given classes to desired level. 
   */
//  def resolveClassFromSource(source: SourceFile, desiredLevel: ResolveLevel.Value): ISet[JawaClass] = {
//    val resolveBody: Boolean = desiredLevel match {
//      case ResolveLevel.BODY => true
//      case _ => false
//    }
//    val cu = parseCode[CompilationUnit](source, resolveBody).get
//    val tpes = getClassTypes(source, reporter)
//    tpes foreach{removeClass(_)}
//    resolveClasses(cu.topDecls, desiredLevel, true)
//    tpes map{tpe => getClass(tpe).get}
//  }
//	
//	/**
//	 * collect class info from symbol table
//	 */
//	def resolveClasses(cids: IList[ClassOrInterfaceDeclaration], level: ResolveLevel.Value, par: Boolean) = {
//	  if(DEBUG) println("Doing " + TITLE + ". Resolve classes parallel: " + par)
//	  val col: GenIterable[ClassOrInterfaceDeclaration] = if(par) cids.par else cids
//	  val classes = col.map{
//	    cid =>
//	      val classType: ObjectType = cid.typ
//        getClass(classType) match {
//          case Some(c) => c
//          case None =>
//            val recAccessFlag = cid.accessModifier        // It can be PUBLIC ... or empty (which means no access flag class)
//            val clazz: JawaClass = new JawaClass(this, classType, recAccessFlag)
//            cid.parents foreach {
//              p =>
//                getClass(p) match {
//                  case Some(pc) =>
//                    if(pc.isInterface) clazz.addInterface(pc)
//                    else clazz.setSuperClass(pc)
//                  case None =>
//                    val up: JawaClass = JawaClass(this, p, 0)
//                    clazz.addUnknownParent(up)
//                }
//            }
//            if(isInnerClass(clazz.getType)){
//              val outer = getOuterTypeFrom(clazz.getType)
//              getClass(outer) match {
//                case Some(o) => clazz.setOuterClass(o)
//                case None =>
//                  val oc: JawaClass = JawaClass(this, outer, 0)
//                  clazz.setOuterClass(oc)
//              }
//            }
//            clazz.setAST(cid)
//            resolveFields(clazz, cid.fields, par)
//            resolveMethods(clazz, cid.methods, level, par)
//            clazz.setResolvingLevel(level)
//            clazz
//        }
//	  }.toSet
////	  resolveClassesRelationWholeProgram
//	  // now we generate a special Jawa Method for each class; this proc would represent the const-class operation
//	  classes.foreach{
//	    clazz =>
//	      createClassField(clazz)
//	  }
//	}
//	
//	private def createClassField(rec: JawaClass): JawaField = {
//	  JawaField(rec, "class", new ObjectType("java.lang.Class"), AccessFlag.getAccessFlags("FINAL_STATIC"))
//	}
//	
//	/**
//	 * collect global variables info from the symbol table
//	 */
//	def resolveFields(declaringClass: JawaClass, fieldDecls: IList[Field with Declaration], par: Boolean) = {
//	  if(DEBUG) println("Doing " + TITLE + ". Resolve field parallel: " + par)
//	  val col: GenIterable[Field with Declaration] = if(par) fieldDecls.par else fieldDecls
//	  col.foreach{
//	    fieldDecl =>
//	      val fieldName: String = fieldDecl.fieldName // e.g. serialVersionUID
//	      val accessFlags: Int = AccessFlag.getAccessFlags(fieldDecl.accessModifier)
//	      val fieldType: JawaType = fieldDecl.typ.typ	      
//	      JawaField(declaringClass, fieldName, fieldType, accessFlags)
//	  }
//	}
//	
//	/**
//	 * collect method info from symbol table
//	 */
//	def resolveMethods(declaringClass: JawaClass, mds: IList[MethodDeclaration], level: ResolveLevel.Value, par: Boolean) = {
//	  if(DEBUG) println("Doing " + TITLE + ". Resolve methods parallel: " + par)
//	  val col: GenIterable[MethodDeclaration] = if(par) mds.par else mds
//	  col.foreach{
//	    md =>
//	      val methodName: String = md.name
//	      val accessFlags: Int = AccessFlag.getAccessFlags(md.accessModifier)
//        val thisOpt: Option[String] = md.paramClause.thisParam.map(_.name)
//        val params: ISeq[(String, JawaType)] = md.paramlist.map{p => (p.name, p.typ.typ)}
//        val returnType: JawaType = md.returnType.typ
//	      val method: JawaMethod = JawaMethod(declaringClass, methodName, thisOpt, params, returnType, accessFlags)
//	      method.setResolvingLevel(level)
//        method.setAST(md)
//	      if(level >= ResolveLevel.BODY){
//	      	if(md.body.isInstanceOf[ResolvedBody]){
//		        val body = md.body.asInstanceOf[ResolvedBody]
//		        val catchclauses = body.catchClauses
//		        catchclauses.foreach{
//		          catchclause =>
//		            val excName = catchclause.typ.typ.name
//			          method.addExceptionHandler(excName, catchclause.from, catchclause.to, catchclause.goto.text)
//		        }
//		      }
//	      }
//	  }
//	}
  
}
