// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.summary/src/main/java/org/argus/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.summary.grammar;
import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by
 * {@link SafsuParser}.
 */
public interface SafsuListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by {@link SafsuParser#summaryFile}.
	 * @param ctx the parse tree
	 */
	void enterSummaryFile(SafsuParser.SummaryFileContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#summaryFile}.
	 * @param ctx the parse tree
	 */
	void exitSummaryFile(SafsuParser.SummaryFileContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#summary}.
	 * @param ctx the parse tree
	 */
	void enterSummary(SafsuParser.SummaryContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#summary}.
	 * @param ctx the parse tree
	 */
	void exitSummary(SafsuParser.SummaryContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#signature}.
	 * @param ctx the parse tree
	 */
	void enterSignature(SafsuParser.SignatureContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#signature}.
	 * @param ctx the parse tree
	 */
	void exitSignature(SafsuParser.SignatureContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#suRule}.
	 * @param ctx the parse tree
	 */
	void enterSuRule(SafsuParser.SuRuleContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#suRule}.
	 * @param ctx the parse tree
	 */
	void exitSuRule(SafsuParser.SuRuleContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#lhs}.
	 * @param ctx the parse tree
	 */
	void enterLhs(SafsuParser.LhsContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#lhs}.
	 * @param ctx the parse tree
	 */
	void exitLhs(SafsuParser.LhsContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#rhs}.
	 * @param ctx the parse tree
	 */
	void enterRhs(SafsuParser.RhsContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#rhs}.
	 * @param ctx the parse tree
	 */
	void exitRhs(SafsuParser.RhsContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#arg}.
	 * @param ctx the parse tree
	 */
	void enterArg(SafsuParser.ArgContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#arg}.
	 * @param ctx the parse tree
	 */
	void exitArg(SafsuParser.ArgContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#field}.
	 * @param ctx the parse tree
	 */
	void enterField(SafsuParser.FieldContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#field}.
	 * @param ctx the parse tree
	 */
	void exitField(SafsuParser.FieldContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#global}.
	 * @param ctx the parse tree
	 */
	void enterGlobal(SafsuParser.GlobalContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#global}.
	 * @param ctx the parse tree
	 */
	void exitGlobal(SafsuParser.GlobalContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#type}.
	 * @param ctx the parse tree
	 */
	void enterType(SafsuParser.TypeContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#type}.
	 * @param ctx the parse tree
	 */
	void exitType(SafsuParser.TypeContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#ret}.
	 * @param ctx the parse tree
	 */
	void enterRet(SafsuParser.RetContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#ret}.
	 * @param ctx the parse tree
	 */
	void exitRet(SafsuParser.RetContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#location}.
	 * @param ctx the parse tree
	 */
	void enterLocation(SafsuParser.LocationContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#location}.
	 * @param ctx the parse tree
	 */
	void exitLocation(SafsuParser.LocationContext ctx);
}