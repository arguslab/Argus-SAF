package hu.ssh.progressbar.replacers;

import hu.ssh.progressbar.progress.Progress;

public interface Replacer {
	String getReplaceIdentifier();

	String getReplacementForProgress(Progress progress);
}
