/// A second *process* that tries to open a database for writing.
///
/// `spec/01-container.md` §10's rule is about processes, and Dart's
/// `RandomAccessFile.lockSync` is a POSIX `fcntl` lock, which is held per
/// process — a second handle inside the same process is granted it. So the
/// only honest test of §10 is another process, exactly as
/// `spec/13-operations.md` §8's multi-process readers are tested with real
/// processes rather than a second handle.
///
/// Prints `locked` when §10 refuses it, `opened` when it got in, or
/// `other:<type>` for anything else.
library;

import 'dart:io';

import 'package:cryptand/cryptand.dart';

void main(List<String> args) {
  try {
    DatabaseFile.open(args[0]);
    stdout.writeln('opened');
  } on LockedException {
    stdout.writeln('locked');
  } on Object catch (e) {
    stdout.writeln('other:${e.runtimeType}');
  }
}
