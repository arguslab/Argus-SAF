/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

// Generated from /Users/fengguow/IdeaProjects/Argus-SAF/jawa/src/main/java/org/argus/jawa/flow/summary/grammar/Safsu.g4 by ANTLR 4.7
package org.argus.jawa.flow.summary.grammar;
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
	 * Enter a parse tree produced by {@link SafsuParser#defaultType}.
	 * @param ctx the parse tree
	 */
	void enterDefaultType(SafsuParser.DefaultTypeContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#defaultType}.
	 * @param ctx the parse tree
	 */
	void exitDefaultType(SafsuParser.DefaultTypeContext ctx);
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
	 * Enter a parse tree produced by {@link SafsuParser#clearRule}.
	 * @param ctx the parse tree
	 */
	void enterClearRule(SafsuParser.ClearRuleContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#clearRule}.
	 * @param ctx the parse tree
	 */
	void exitClearRule(SafsuParser.ClearRuleContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#binaryRule}.
	 * @param ctx the parse tree
	 */
	void enterBinaryRule(SafsuParser.BinaryRuleContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#binaryRule}.
	 * @param ctx the parse tree
	 */
	void exitBinaryRule(SafsuParser.BinaryRuleContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#ops}.
	 * @param ctx the parse tree
	 */
	void enterOps(SafsuParser.OpsContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#ops}.
	 * @param ctx the parse tree
	 */
	void exitOps(SafsuParser.OpsContext ctx);
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
	 * Enter a parse tree produced by {@link SafsuParser#suThis}.
	 * @param ctx the parse tree
	 */
	void enterSuThis(SafsuParser.SuThisContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#suThis}.
	 * @param ctx the parse tree
	 */
	void exitSuThis(SafsuParser.SuThisContext ctx);
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
	 * Enter a parse tree produced by {@link SafsuParser#heap}.
	 * @param ctx the parse tree
	 */
	void enterHeap(SafsuParser.HeapContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#heap}.
	 * @param ctx the parse tree
	 */
	void exitHeap(SafsuParser.HeapContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#heapAccess}.
	 * @param ctx the parse tree
	 */
	void enterHeapAccess(SafsuParser.HeapAccessContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#heapAccess}.
	 * @param ctx the parse tree
	 */
	void exitHeapAccess(SafsuParser.HeapAccessContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#fieldAccess}.
	 * @param ctx the parse tree
	 */
	void enterFieldAccess(SafsuParser.FieldAccessContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#fieldAccess}.
	 * @param ctx the parse tree
	 */
	void exitFieldAccess(SafsuParser.FieldAccessContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#arrayAccess}.
	 * @param ctx the parse tree
	 */
	void enterArrayAccess(SafsuParser.ArrayAccessContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#arrayAccess}.
	 * @param ctx the parse tree
	 */
	void exitArrayAccess(SafsuParser.ArrayAccessContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#instance}.
	 * @param ctx the parse tree
	 */
	void enterInstance(SafsuParser.InstanceContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#instance}.
	 * @param ctx the parse tree
	 */
	void exitInstance(SafsuParser.InstanceContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#classOf}.
	 * @param ctx the parse tree
	 */
	void enterClassOf(SafsuParser.ClassOfContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#classOf}.
	 * @param ctx the parse tree
	 */
	void exitClassOf(SafsuParser.ClassOfContext ctx);
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
	 * Enter a parse tree produced by {@link SafsuParser#javaType}.
	 * @param ctx the parse tree
	 */
	void enterJavaType(SafsuParser.JavaTypeContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#javaType}.
	 * @param ctx the parse tree
	 */
	void exitJavaType(SafsuParser.JavaTypeContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#innerType}.
	 * @param ctx the parse tree
	 */
	void enterInnerType(SafsuParser.InnerTypeContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#innerType}.
	 * @param ctx the parse tree
	 */
	void exitInnerType(SafsuParser.InnerTypeContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#unknown}.
	 * @param ctx the parse tree
	 */
	void enterUnknown(SafsuParser.UnknownContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#unknown}.
	 * @param ctx the parse tree
	 */
	void exitUnknown(SafsuParser.UnknownContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#stringLit}.
	 * @param ctx the parse tree
	 */
	void enterStringLit(SafsuParser.StringLitContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#stringLit}.
	 * @param ctx the parse tree
	 */
	void exitStringLit(SafsuParser.StringLitContext ctx);
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
	/**
	 * Enter a parse tree produced by {@link SafsuParser#virtualLocation}.
	 * @param ctx the parse tree
	 */
	void enterVirtualLocation(SafsuParser.VirtualLocationContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#virtualLocation}.
	 * @param ctx the parse tree
	 */
	void exitVirtualLocation(SafsuParser.VirtualLocationContext ctx);
	/**
	 * Enter a parse tree produced by {@link SafsuParser#concreteLocation}.
	 * @param ctx the parse tree
	 */
	void enterConcreteLocation(SafsuParser.ConcreteLocationContext ctx);
	/**
	 * Exit a parse tree produced by {@link SafsuParser#concreteLocation}.
	 * @param ctx the parse tree
	 */
	void exitConcreteLocation(SafsuParser.ConcreteLocationContext ctx);
}