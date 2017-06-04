grammar Safsu;


summaryFile : summary* EOF;

summary
  : signature ':' suRule* ';'
  ;

signature
  : UID
  ;

suRule
  : lhs '=' rhs
  ;

lhs
  : arg
  | field
  | global
  | ret
  ;

rhs
  : arg
  | field
  | global
  | type
  ;

arg
  : 'arg' ':' Digits             // arg1
  ;

field
  : arg ('.' ID)+            // arg1.f1.f2
  ;

global
  : '@@' ID ('.' ID)*             // @@com.my.Class.GlobalVariable
  ;

type
  : ID ('.' ID)* ('@' location)?    // com.my.Object@L123
  ;

ret
  : 'ret'
  ;

location
  : ID
  ;

UID: '`' ( ~( '\n' | '\r' | '\t' | '\u000C' | '`' ) )* '`';

ID: LETTER ( LETTER | DIGIT )*;

Digits : DIGIT+ ;

fragment
DIGIT : '0'..'9' ;

fragment
LETTER
  : '\u0041'..'\u005a'       // A-Z
  | '\u005f'                 // _
  | '\u0061'..'\u007a'       // a-z
  ;

WS
  : [ \r\t\u000C\n]+ -> channel(HIDDEN)
  ;

COMMENT
  : '/*' .*? '*/'    -> channel(2)
  ;

LINE_COMMENT
  : '//' ~[\r\n]*    -> channel(2)
  ;