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

object PilarModelProvider {
  val pilarModel =
"""
group PilarModelGenerator;

delimiters "$", "$"

RecordDecl(recName, annotations, extends, attributes, globals, procedures) ::= <<
record `$recName$` $annotations ; separator=" "$$if(extends)$ extends $extends ; separator=", "$$endif$ {
  $attributes ; separator="\n"$
}
$globals ; separator="\n"$
$procedures ; separator="\n"$
>>

ExtendsAndImpliments(recName, annotations) ::= <<
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
`$typ$` $name$;
>>

ParamVar(typ, name, annotations) ::= <<
`$typ$` $name$ $annotations ; separator=" "$
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
#L$num$. $code$
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
new `$name$`
>>

InvokeStmtWithReturn(funcName, params, annotations) ::= <<
call temp:= `$funcName$`($params ; separator=", "$) $annotations ; separator=" "$
>>

InvokeStmtWithoutReturn(funcName, params, annotations) ::= <<
call `$funcName$`($params ; separator=", "$) $annotations ; separator=" "$
>>

FieldAccessExp(base, field) ::= <<
$base$.`$field$`
>>

FilledNewArray(baseTyp, args) ::= <<
temp:= new $baseTyp$[$args ; separator=", "$]
>>

CatchClauses(catchs) ::= <<
$catchs ; separator="\n"$
>>

Catch(catchTyp, fromLoc, toLoc, targetLoc) ::= <<
catch $catchTyp$ @[$fromLoc$..$toLoc$] goto $targetLoc$;
>>
"""
}