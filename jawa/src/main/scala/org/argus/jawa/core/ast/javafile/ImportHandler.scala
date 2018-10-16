/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

///*
// * Copyright (c) 2017. Fengguo Wei and others.
// * All rights reserved. This program and the accompanying materials
// * are made available under the terms of the Eclipse Public License v1.0
// * which accompanies this distribution, and is available at
// * http://www.eclipse.org/legal/epl-v10.html
// *
// * Detailed contributors are listed in the CONTRIBUTOR.md
// */
//
//package org.argus.jawa.core.ast.javafile
//
//import com.github.javaparser.ast.`type`._
//import com.github.javaparser.ast.expr.NameExpr
//import com.github.javaparser.ast.{ImportDeclaration, NodeList}
//import org.argus.jawa.core._
//import org.argus.jawa.core.io.RangePosition
//import org.argus.jawa.core.util._
//
//class ImportHandler(j2j: Java2Jawa, imports: NodeList[ImportDeclaration]) {
//  import j2j._
//  private val types: MSet[JawaType] = msetEmpty
//  private val pkgs: MSet[String] = msetEmpty
//  private val staticContainer: MSet[JawaType] = msetEmpty
//  private val staticFields: MSet[JawaField] = msetEmpty
//  private val staticMethods: MSet[JawaMethod] = msetEmpty
//
//  def processImports(): Unit = {
//    imports.forEach { imp =>
//      if (!imp.isStatic) {
//        if (imp.isAsterisk) {
//          pkgs += imp.getNameAsString
//        } else {
//          types ++= global.containsClassCanonical(imp.getNameAsString)
//        }
//      }
//    }
//  }
//
//  // Do this separately to prevent cycle in global resolve class
//  def resolveStaticImports(): Unit = {
//    imports.forEach{ imp =>
//      if(imp.isStatic) {
//        if(imp.isAsterisk) {
//          staticContainer ++= global.containsClassCanonical(imp.getNameAsString)
//        } else {
//          global.containsClassCanonical(imp.getNameAsString) match {
//            case Some(typ) => types += typ
//            case None =>
//              val idx = imp.getNameAsString.lastIndexOf(".")
//              if(idx > 0) {
//                val name = imp.getNameAsString.substring(0, idx)
//                val part = imp.getNameAsString.substring(idx + 1)
//                global.containsClassCanonical(name) match {
//                  case Some(typ) =>
//                    val clazz = global.getClassOrResolve(typ)
//                    staticMethods ++= clazz.getMethodsByName(part).filter(m => m.isStatic)
//                    staticFields ++= clazz.getStaticFields.filter(f => f.name == part && f.isStatic)
//                  case None =>
//                    throw Java2JawaException(imp.toRange, s"Cannot resolve static import $imp")
//                }
//              }
//          }
//        }
//      }
//    }
//  }
//
//  def getStaticField(name: NameExpr): Option[JawaField] = {
//    val fieldName = name.getNameAsString
//    staticFields.foreach { f =>
//      if(f.getName == fieldName) {
//        return Some(f)
//      }
//    }
//    staticContainer.foreach { sc =>
//      val clazz = global.getClassOrResolve(sc)
//      clazz.getStaticFields.foreach { sf =>
//        if(sf.getName == fieldName) {
//          return Some(sf)
//        }
//      }
//    }
//    None
//  }
//
//  def getStaticMethod(name: String, argTypes: IList[JawaType]): Option[JawaMethod] = {
//    staticMethods.foreach { m =>
//      if(m.matches(name, argTypes)) {
//        return Some(m)
//      }
//    }
//    staticContainer.foreach { sc =>
//      val clazz = global.getClassOrResolve(sc)
//      clazz.getStaticMethods.foreach { m =>
//        if(m.matches(name, argTypes)) {
//          return Some(m)
//        }
//      }
//    }
//    None
//  }
//
//  private val typeMap: MMap[String, JawaType] = mmapEmpty
//
//  protected[javafile] def findTypeOpt(name: String): Option[JawaType] = {
//    typeMap.get(name) match {
//      case t @ Some(_) => t
//      case None =>
//        var typOpt: Option[JawaType] = None
//        // Check whether itself is FQN
//        val firstTry = new JawaType(name)
//        if(global.containsClass(firstTry)) {
//          typOpt = Some(firstTry)
//        }
//        typOpt match {
//          case None =>
//            // check current package
//            if(packageName.nonEmpty) {
//              val checkCurrent = new JawaType(s"$packageName.$name")
//              if(global.containsClass(checkCurrent)) {
//                typOpt = Some(checkCurrent)
//              }
//            }
//          case _ =>
//        }
//        typOpt match {
//          case None =>
//            // check inner type
//            topDecls.foreach { decl =>
//              val newname = name.replaceAll("\\.", "&")
//              val finalname = s"${decl.typ.jawaName}$$$newname"
//              val finaltype = new JawaType(finalname)
//              if(global.containsClass(finaltype)) {
//                typOpt = Some(finaltype)
//              }
//            }
//          case _ =>
//        }
//        typOpt match {
//          case None =>
//            // Check imports
//            if(name.contains(".")) {
//              val idx = name.indexOf(".")
//              val basename = name.substring(0, idx)
//              val innername = name.substring(idx + 1)
//              types.foreach { typ =>
//                if(typ.canonicalName.endsWith(s".$basename")) {
//                  val finalname = s"${typ.jawaName}$$${innername.replaceAll("\\.", "&")}"
//                  val finaltype = new JawaType(finalname)
//                  if(global.containsClass(finaltype)) {
//                    typOpt = Some(finaltype)
//                  }
//                }
//              }
//            } else {
//              types.foreach { typ =>
//                if(typ.canonicalName.endsWith(s".$name")) {
//                  typOpt = Some(typ)
//                }
//              }
//            }
//          case _ =>
//        }
//        typOpt match {
//          case None =>
//            pkgs.foreach { pkg =>
//              val finalname = s"$pkg.$name"
//              typOpt = global.containsClassCanonical(finalname)
//            }
//          case _ =>
//        }
//        typOpt match {
//          case None =>
//            // java.lang.* is implicit applied
//            val typ = new JawaType(s"java.lang.$name")
//            if(global.containsClass(typ)) {
//              typOpt = Some(typ)
//            }
//          case _ =>
//        }
//        typOpt match {
//          case Some(t) => typeMap(name) = t
//          case None =>
//            val dotIndex = name.lastIndexOf('.')
//            if(dotIndex >= 0) {
//              val innerName = new StringBuilder(name).replace(dotIndex, dotIndex + 1, "$").toString()
//              typOpt = findTypeOpt(innerName)
//            }
//        }
//        typOpt
//    }
//  }
//
//  protected[javafile] def findType(name: String, pos: RangePosition): JawaType = {
//    findTypeOpt(name) match {
//      case Some(typ) => typ
//      case None =>
//        global.reporter.error(pos, s"Could not resolve type: $name")
//        val hackType = new JawaType(name)
//        typeMap(name) = hackType
//        hackType
//    }
//  }
//
//  // Does not handle IntersectionType and UnionType
//  protected[javafile] def findType(javaType: Type): JawaType = {
//    var typStr: String = null
//    var dimension: Int = 0
//    javaType match {
//      case at: ArrayType =>
//        typStr = findType(at.getElementType).jawaName
//        dimension = at.getArrayLevel
//      case cit: ClassOrInterfaceType =>
//        typStr = findType(cit.getNameAsString, cit.getName.toRange).jawaName
//      case pt: PrimitiveType =>
//        pt.getType match {
//          case PrimitiveType.Primitive.BOOLEAN => typStr = "boolean"
//          case PrimitiveType.Primitive.BYTE => typStr = "byte"
//          case PrimitiveType.Primitive.CHAR => typStr = "char"
//          case PrimitiveType.Primitive.DOUBLE => typStr = "double"
//          case PrimitiveType.Primitive.FLOAT => typStr = "float"
//          case PrimitiveType.Primitive.INT => typStr = "int"
//          case PrimitiveType.Primitive.LONG => typStr = "long"
//          case PrimitiveType.Primitive.SHORT => typStr = "short"
//          case _ =>
//            global.reporter.error(javaType.toRange.pos, s"Unknown primitive type: $pt")
//            typStr = "int"
//        }
//      case _: VoidType =>
//        typStr = "void"
//      case _ =>
//        throw Java2JawaException(javaType.toRange, s"${javaType.getClass} is not handled by jawa: $javaType, please contact author: fgwei521@gmail.com")
//    }
//    new JawaType(typStr, dimension)
//  }
//
//  // Handle all types.
//  protected[javafile] def findTypes(javaType: Type): IList[JawaType] = {
//    val jawaTypes: MList[JawaType] = mlistEmpty
//    javaType match {
//      case at: ArrayType =>
//        jawaTypes += findType(at)
//      case cit: ClassOrInterfaceType =>
//        jawaTypes += findType(cit)
//      case it: IntersectionType =>
//        it.getElements.forEach{ elem =>
//          jawaTypes ++= findTypes(elem)
//        }
//      case ut: UnionType =>
//        ut.getElements.forEach{ elem =>
//          jawaTypes ++= findTypes(elem)
//        }
//      case pt: PrimitiveType =>
//        jawaTypes += findType(pt)
//      case _: VoidType =>
//        jawaTypes += findType(javaType)
//      case _ =>
//        throw Java2JawaException(javaType.toRange, s"${javaType.getClass} is not handled by jawa: $javaType, please contact author: fgwei521@gmail.com")
//    }
//    jawaTypes.toList
//  }
//}
