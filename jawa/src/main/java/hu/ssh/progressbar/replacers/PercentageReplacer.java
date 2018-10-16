/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package hu.ssh.progressbar.replacers;

import hu.ssh.progressbar.progress.Progress;

public class PercentageReplacer implements Replacer {
	private static final String IDENTIFIER = ":percent";

	@Override
	public final String getReplaceIdentifier() {
		return IDENTIFIER;
	}

	@Override
	public final String getReplacementForProgress(final Progress progress) {
		return String.format("%6.2f", progress.getPercentage() * 100);
	}
}
