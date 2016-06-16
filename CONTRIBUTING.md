# Welcome! Thank you for contributing to Argus-SAF!
We follow the standard GitHub [fork & pull](https://help.github.com/articles/using-pull-requests/#fork--pull) 
approach to pull requests. Just fork the official repo, develop in a branch, and submit a PR!

You're always welcome to submit your PR straight away and start the discussion.
The goal of these notes is to make your experience contributing to Argus-SAF as 
smooth and pleasant as possible. We're happy to guide you through the process once you've submitted your PR.

## What kind of PR are you submitting?

You don't need to submit separate PRs for different version of Argus-SAF.
Any changes accepted on one of these branches will, in time, be merged into the later branches.

### Documentation
Whether you finally decided you couldn't stand that annoying typo anymore, 
you fixed the outdated code sample in some comment, or you wrote a nice, 
comprehensive, overview for an under-documented package, 
some docs for a class or the specifics about a method, 
your documentation improvement is very much appreciated, and we will do our best to fasttrack it.

You can make these changes directly in your browser in GitHub, 
or follow the same process as for code. Up to you!

For bigger documentation changes, you may want to poll the (fgwei521@gmail.com) mailing list first, 
to quickly gauge whether others support the direction you're taking, 
so there won't be any surprises when it comes to reviewing your PR.

### Code
For bigger changes, we do recommend announcing your intentions on fgwei521@gmail.com first, 
to avoid duplicated effort, or spending a lot of time reworking something we are not able to 
change at this time in the release cycle, for example.

#### Bug Fix
Prefix your commit title with "#NN", where https://github.com/arguslab/Argus-SAF/issues/NN tracks the bug you're fixing. 
We also recommend naming your branch after the ticket number.

#### Enhancement or New Feature
For longer-running development, likely required for this category of code contributions, 
we suggest you include "topic/" or "wip/" in your branch name, 
to indicate that this is work in progress, and that others should be prepared to rebase if they branch off your branch.

Any language change (including bug fixes) must be accompanied by the relevant updates to the spec, which lives in the same repository for this reason.

## Guidelines

Here is some advice on how to craft a pull request with the best possible
chance of being accepted.

### Tests

Bug fixes should include regression tests -- in the same commit as the fix.

If testing isn't feasible, the commit message should explain why.

New features and enhancements must be supported by a respectable test suite.

Some characteristics of good tests:

* includes comments: what is being tested and why?
* be minimal, deterministic, stable (unaffected by irrelevant changes), easy to understand and review
* have minimal dependencies

### Documentation

This is of course required for new features and enhancements.

Any API additions should include Scaladoc.

Consider updating the package-level doc (in the package object), if appropriate.

### Coding standards

Please follow these standard code standards, though in moderation (scouts quickly learn to let sleeping dogs lie):

* Don't violate [DRY](http://programmer.97things.oreilly.com/wiki/index.php/Don%27t_Repeat_Yourself).
* Follow the [Boy Scout Rule](http://programmer.97things.oreilly.com/wiki/index.php/The_Boy_Scout_Rule).

### Clean commits, clean history

A pull request should consist of commits with messages that clearly state what problem the commit resolves and how.

Commit logs should be stated in the active, present tense.

A commit's subject should be 72 characters or less.  Overall, think of
the first line of the commit as a description of the action performed
by the commit on the code base, so use the active voice and the
present tense.  That also makes the commit subjects easy to reuse in
release notes.

For a bugfix, the title must look like "#NN - don't crash when
moon is in wrong phase".

If a commit purely refactors and is not intended to change behaviour,
say so.

Here is standard advice on good commit messages:
http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html

### Pass code review

Your PR will need to be assigned to a reviewer. (Now just assign to [`@fgwei`](https://github.com/fgwei).)

To assign a reviewer, add a "review by @reviewer" to your PR description.

NOTE: it's best not to @mention in commit messages, as github pings you every time a commit with your @name on it shuffles through the system (even in other repos, on merges,...).

A reviewer gives the green light by commenting "LGTM" (looks good to me).

A review feedback may be addressed by pushing new commits to the request, if these commits stand on their own.

Once all these conditions are met, and we agree with the change, we will merge your changes.
