/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.codegen

import java.util

import org.argus.jawa.core.elements.JawaType
import org.stringtemplate.v4.{ST, STGroupString}

object JawaModelProvider {
  val jawaModel =
    """
group JawaModelGenerator;

delimiters "$", "$"

RecordDecl(recName, annotations, extends, attributes, globals, procedures) ::= <<
record `$recName$` $annotations ; separator=" "$$if(extends)$ extends $extends ; separator=", "$$endif$ {
  $attributes ; separator="\n"$
}
$globals ; separator="\n"$
$procedures ; separator="\n"$
>>

ExtendsAndImplements(recName, annotations) ::= <<
`$recName$` $annotations ; separator=" "$
>>

Type(baseTyp, dimensions) ::= <<
`$baseTyp$`$dimensions ; separator=""$
>>

AttributeDecl(attrTyp, attrName, annotations) ::= <<
$attrTyp$ `$attrName$` $annotations ; separator=" "$;
>>

GlobalDecl(globalTyp, globalName, annotations) ::= <<
global $globalTyp$ `$globalName$` $annotations ; separator=" "$;
>>

ProcedureDecl(retTyp, procedureName, params, annotations, localVars, body, catchClauses) ::= <<
procedure $retTyp$ `$procedureName$`($params ; separator=", "$) $annotations ; separator=" "$ {
  $localVars$

  $body$
  $catchClauses$
}
>>

Param(paramTyp, paramName, annotations) ::= <<
$paramTyp$ $paramName$ $annotations ; separator=" "$
>>

LocalVars(locals) ::= <<
  $locals ; separator="\n"$
>>

LocalVar(typ, name) ::= <<
$typ$ $name$;
>>

ParamVar(typ, name, annotations) ::= <<
$typ$ $name$ $annotations ; separator=" "$
>>

Annotation(flag, value) ::= <<
@$flag$ $value$
>>

Body(codeFragments) ::= <<
$codeFragments ; separator="\n"$
>>

CodeFragment(label, codes) ::= <<
#$label$.
$codes ; separator="\n"$
>>

Code(num, code) ::= <<
#L$num$. $code$;
>>

Label(num) ::= <<
Label$num$
>>

IfStmt(cond, label) ::= <<
if $cond$ then goto $label$
>>

GotoStmt(label) ::= <<
goto $label$
>>

ReturnStmt(variable) ::= <<
return $variable$
>>

AssignmentStmt(lhs, rhs, annotations) ::= <<
$lhs$:= $rhs$ $annotations ; separator=" "$
>>

CondExp(lhs, rhs) ::= <<
$lhs$ == $rhs$
>>

NewExp(name) ::= <<
new $name$
>>

InvokeStmtWithReturn(funcName, params, annotations) ::= <<
call temp:= `$funcName$`($params ; separator=", "$) $annotations ; separator=" "$
>>

InvokeStmtWithoutReturn(funcName, params, annotations) ::= <<
call `$funcName$`($params ; separator=", "$) $annotations ; separator=" "$
>>

FieldAccessExp(base, field, typ) ::= <<
$base$.`$field$` @kind ^$typ$
>>

FilledNewArray(baseTyp, args) ::= <<
temp:= new $baseTyp$[$args ; separator=", "$]
>>

CatchClauses(catches) ::= <<
$catches ; separator="\n"$
>>

Catch(catchTyp, fromLoc, toLoc, targetLoc) ::= <<
catch $catchTyp$ @[$fromLoc$..$toLoc$] goto $targetLoc$;
>>
"""

  def generateAnnotation(flag: String, value: String, template: STGroupString): ST = {
    val annot = template.getInstanceOf("Annotation")
    annot.add("flag", flag)
    annot.add("value", value)
  }

  def generateType(typ: JawaType, template: STGroupString): ST = {
    val typTemplate = template.getInstanceOf("Type")
    typTemplate.add("baseTyp", typ.baseTyp)
    val dimensions: util.ArrayList[String] = new util.ArrayList[String]
    for(_ <- 0 until typ.dimensions) dimensions.add("[]")
    typTemplate.add("dimensions", dimensions)
    typTemplate
  }
}