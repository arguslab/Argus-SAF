// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.summary/src/main/java/org/argus/summary/grammar/safsu.g4 by ANTLR 4.7
package org.argus.summary.grammar;
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link safsuParser}.
 */
public interface safsuListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link safsuParser#summaryFile}.
	 * @param ctx the parse tree
	 */
	void enterSummaryFile(safsuParser.SummaryFileContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#summaryFile}.
	 * @param ctx the parse tree
	 */
	void exitSummaryFile(safsuParser.SummaryFileContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#summary}.
	 * @param ctx the parse tree
	 */
	void enterSummary(safsuParser.SummaryContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#summary}.
	 * @param ctx the parse tree
	 */
	void exitSummary(safsuParser.SummaryContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#signature}.
	 * @param ctx the parse tree
	 */
	void enterSignature(safsuParser.SignatureContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#signature}.
	 * @param ctx the parse tree
	 */
	void exitSignature(safsuParser.SignatureContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#suRule}.
	 * @param ctx the parse tree
	 */
	void enterSuRule(safsuParser.SuRuleContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#suRule}.
	 * @param ctx the parse tree
	 */
	void exitSuRule(safsuParser.SuRuleContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#lhs}.
	 * @param ctx the parse tree
	 */
	void enterLhs(safsuParser.LhsContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#lhs}.
	 * @param ctx the parse tree
	 */
	void exitLhs(safsuParser.LhsContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#rhs}.
	 * @param ctx the parse tree
	 */
	void enterRhs(safsuParser.RhsContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#rhs}.
	 * @param ctx the parse tree
	 */
	void exitRhs(safsuParser.RhsContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#arg}.
	 * @param ctx the parse tree
	 */
	void enterArg(safsuParser.ArgContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#arg}.
	 * @param ctx the parse tree
	 */
	void exitArg(safsuParser.ArgContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#field}.
	 * @param ctx the parse tree
	 */
	void enterField(safsuParser.FieldContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#field}.
	 * @param ctx the parse tree
	 */
	void exitField(safsuParser.FieldContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#global}.
	 * @param ctx the parse tree
	 */
	void enterGlobal(safsuParser.GlobalContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#global}.
	 * @param ctx the parse tree
	 */
	void exitGlobal(safsuParser.GlobalContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#type}.
	 * @param ctx the parse tree
	 */
	void enterType(safsuParser.TypeContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#type}.
	 * @param ctx the parse tree
	 */
	void exitType(safsuParser.TypeContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#ret}.
	 * @param ctx the parse tree
	 */
	void enterRet(safsuParser.RetContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#ret}.
	 * @param ctx the parse tree
	 */
	void exitRet(safsuParser.RetContext ctx);
	/**
	 * Enter a parse tree produced by {@link safsuParser#location}.
	 * @param ctx the parse tree
	 */
	void enterLocation(safsuParser.LocationContext ctx);
	/**
	 * Exit a parse tree produced by {@link safsuParser#location}.
	 * @param ctx the parse tree
	 */
	void exitLocation(safsuParser.LocationContext ctx);
}