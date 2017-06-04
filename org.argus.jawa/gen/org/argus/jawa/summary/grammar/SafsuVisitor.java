// Generated from /Users/fgwei/IdeaProjects/Argus-SAF/org.argus.jawa/src/main/java/org/argus/jawa/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.jawa.summary.grammar;
import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced
 * by {@link SafsuParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for
 * operations with no return type.
 */
public interface SafsuVisitor<T> extends ParseTreeVisitor<T> {
	/**
	 * Visit a parse tree produced by {@link SafsuParser#summaryFile}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummaryFile(SafsuParser.SummaryFileContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#summary}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSummary(SafsuParser.SummaryContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#signature}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSignature(SafsuParser.SignatureContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#suRule}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitSuRule(SafsuParser.SuRuleContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#lhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLhs(SafsuParser.LhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#rhs}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRhs(SafsuParser.RhsContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#arg}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitArg(SafsuParser.ArgContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#field}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitField(SafsuParser.FieldContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#global}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitGlobal(SafsuParser.GlobalContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#type}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitType(SafsuParser.TypeContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#ret}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitRet(SafsuParser.RetContext ctx);
	/**
	 * Visit a parse tree produced by {@link SafsuParser#location}.
	 * @param ctx the parse tree
	 * @return the visitor result
	 */
	T visitLocation(SafsuParser.LocationContext ctx);
}