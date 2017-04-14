/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.pilarCodeGenerator

object JawaCodeModelProvider {
  def getJawaCodeModel: String =
"""
group JawaCodeGenerator;

delimiters "$", "$"

ProcedureDecl(retTyp, procedureName, params, localVars, annotations, body) ::= <<
procedure `$retTyp$` `$procedureName$`($params ; separator=", "$) $annotations ; separator=" "$ {
  $localVars$
	
  $body$
}
>>

LocalVars(locals) ::= <<
  `int` RandomCoinToss;
  `int` head;
  `int` x;
  $locals ; separator="\n"$
>>

LocalVar(typ, name) ::= <<
`$typ$` $name$;
>>

ParamVar(typ, name, annotations) ::= <<
`$typ$` $name$ $annotations ; separator=" "$
>>

annotationWithExp(flag, exps) ::= <<
@$flag$ $exps ; separator=", "$
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
"""
}