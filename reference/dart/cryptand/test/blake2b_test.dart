/// BLAKE2b against RFC 7693's own vectors.
///
/// `spec/14-security.md` §2's whole argument for naming primitives rather than
/// describing them is that an implementation can be checked against a
/// published vector set instead of against another implementation. This is
/// that check, and it is why `blake2b.dart` and `argon2.dart` exist at all.
library;

import 'dart:typed_data';

import 'package:cryptand/src/blake2b.dart';
import 'package:test/test.dart';

/// A signed 64-bit Dart `int` rendered as unsigned hex.
///
/// `toUnsigned(64)` is a no-op here — Dart has no wider integer to widen into,
/// so a negative word stays negative and prints with a minus sign. RFC 7693
/// prints these words unsigned, so the halves are formatted separately.
String u64(int x) =>
    ((x >>> 32) & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0') +
    (x & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0');

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String s) {
  final t = s.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([
    for (var i = 0; i < t.length; i += 2) int.parse(t.substring(i, i + 2), radix: 16)
  ]);
}

void main() {
  group('RFC 7693 Appendix A — BLAKE2b-512("abc")', () {
    test('the digest reproduces byte for byte', () {
      expect(
          hex(blake2b('abc'.codeUnits)),
          'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
          '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
    });

    test('all thirteen working vectors match, round by round', () {
      // RFC 7693 Appendix A prints v[0..15] at each point around the twelve
      // rounds: (i=0) is the vector entering round 0 and (i=12) the vector
      // leaving round 11. Checking every one is the point — a transposed
      // SIGMA row can still yield a correct digest on a single-block message,
      // and Argon2 never hashes one of those.
      const expected = <List<String>>[
      [ // i = 0
        '6a09e667f2bdc948', 'bb67ae8584caa73b', '3c6ef372fe94f82b',
        'a54ff53a5f1d36f1', '510e527fade682d1', '9b05688c2b3e6c1f',
        '1f83d9abfb41bd6b', '5be0cd19137e2179', '6a09e667f3bcc908',
        'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
        '510e527fade682d2', '9b05688c2b3e6c1f', 'e07c265404be4294',
        '5be0cd19137e2179',
      ],
      [ // i = 1
        '86b7c1568029bb79', 'c12cbcc809ff59f3', 'c6a5214cc0eaca8e',
        '0c87cd524c14cc5d', '44ee6039bd86a9f7', 'a447c850aa694a7e',
        'de080f1bb1c0f84b', '595cb8a9a1aca66c', 'bec3ae837eac4887',
        '6267fc79df9d6ad1', 'fa87b01273fa6dbe', '521a715c63e08d8a',
        'e02d0975b8d37a83', '1c7b754f08b7d193', '8f885a76b6e578fe',
        '2318a24e2140fc64',
      ],
      [ // i = 2
        '53281e83806010f2', '3594b403f81b4393', '8cd63c7462de0dff',
        '85f693f3da53f974', 'baabdbb2f386d9ae', 'ca5425aec65a10a8',
        'c6a22e2ff0f7aa48', 'c6a56a51cb89c595', '224e6a3369224f96',
        '500e125e58a92923', 'e9e4ad0d0e1a0d48', '85df9dc143c59a74',
        '92a3aaaa6d952b7f', 'c5fdf71090fae853', '2a8a40f15a462dd0',
        '572d17effdd37358',
      ],
      [ // i = 3
        '60ed96aa7ad41725', 'e46a743c71800b9d', '1a04b543a01f156b',
        'a2f8716e775c4877', 'da0a61bcde4267ea', 'b1dd230754d7bdee',
        '25a1422779e06d14', 'e6823ae4c3ff58a5', 'a1677e19f37fd5da',
        '22bdce6976b08c51', 'f1de8696bec11bf1', 'a0ebd586a4a1d2c8',
        'c804ebab11c99fa9', '8e0cec959c715793', '7c45557fae0d4d89',
        '716343f52fdd265e',
      ],
      [ // i = 4
        'bb2a77d3a8382351', '45eb47971f23b103', '98be297f6e45c684',
        'a36077dee3370b89', '8a03c4cb7e97590a', '24192e49ebf54ea0',
        '4f82c9401cb32d7a', '8ccd013726420dc4', 'a9c9a8f17b1fc614',
        '55908187977514a0', '5b44273e66b19d27', 'b6d5c9fca2579327',
        '086092cfb858437e', '5c4be2156dbeecf9', '2efede99ed4eff16',
        '3e7b5f234cd1f804',
      ],
      [ // i = 5
        'c79c15b3d423b099', '2da2224e8da97556', '77d2b26df1c45c55',
        '8934eb09a3456052', '0f6d9eeed157da2a', '6fe66467af88c0a9',
        '4eb0b76284c7aafb', '299c8e725d954697', 'b2240b59e6d567d3',
        '2643c2370e49ebfd', '79e02eef20cdb1ae', '64b3eed7bb602f39',
        'b97d2d439e4df63d', 'c718e755294c9111', '1f0893f2772bb373',
        '1205ea4a7859807d',
      ],
      [ // i = 6
        'e58f97d6385baee4', '7640aa9764da137a', 'deb4c7c23efe287e',
        '70f6f41c8783c9f6', '7127cd48c76a7708', '9e472af0be3db3f6',
        '0f244c62ddf71788', '219828aa83880842', '41cca9073c8c4d0d',
        '5c7912bc10df3b4b', 'a2c3abbd37510ee2', 'cb5668cc2a9f7859',
        '8733794f07ac1500', 'c67a6be42335aa6f', 'acb22b28681e4c82',
        'db2161604cbc9828',
      ],
      [ // i = 7
        '6e2d286eeadedc81', 'bcf02c0787e86358', '57d56a56dd015edf',
        '55d899d40a5d0d0a', '819415b56220c459', 'b63c479a6a769f02',
        '258e55e0ec1f362a', '3a3b4ec60e19dfdc', '04d769b3fcb048db',
        'b78a9a33e9bff4dd', '5777272ae1e930c0', '5a387849e578dbf6',
        '92aac307cf2c0afc', '30aaccc4f06dafaa', '483893cc094f8863',
        'e03c6cc89c26bf92',
      ],
      [ // i = 8
        'ffc83ece76024d01', '1be7bffb8c5cc5f9', 'a35a18cbac4c65b7',
        'b7c2c7e6d88c285f', '81937da314a50838', 'e1179523a2541963',
        '3a1fad7106232b8f', '1c7ede92ab8b9c46', 'a3c2d35e4f685c10',
        'a53d3f73aa619624', '30bbcc0285a22f65', 'bcefbb6a81539e5d',
        '3841def6f4c9848a', '98662c85fba726d4', '7762439bd5a851bd',
        'b0b9f0d443d1a889',
      ],
      [ // i = 9
        '753a70a1e8faeadd', '6b0d43ca2c25d629', 'f8343ba8b94f8c0b',
        'bc7d062b0db5cf35', '58540ee1b1aebc47', '63c5b9b80d294cb9',
        '490870ecad27debd', 'b2a90ddf667287fe', '316cc9ebeefad8fc',
        '4a466bcd021526a4', '5da7f7638cec5669', 'd9c8826727d306fc',
        '88ed6c4f3bd7a537', '19ae688ddf67f026', '4d8707aab40f7e6d',
        'fd3f572687fea4f1',
      ],
      [ // i = 10
        'e630c747ccd59c4f', 'bc713d41127571ca', '46db183025025078',
        '6727e81260610140', '2d04185eac2a8cba', '5f311b88904056ec',
        '40bd313009201aab', '0099d4f82a2a1eab', '6dd4fbc1de60165d',
        'b3b0b51de3c86270', '900aee2f233b08e5', 'a07199d87ad058d8',
        '2c6b25593d717852', '37e8ca471beaa5f8', '2cfc1bac10ef4457',
        '01369ec18746e775',
      ],
      [ // i = 11
        'e801f73b9768c760', '35c6d22320be511d', '306f27584f65495e',
        'b51776adf569a77b', 'f4f1be86690b3c34', '3cc88735d1475e4b',
        '5dac67921ff76949', '1cdb9d31ad70cc4e', '35ba354a9c7df448',
        '4929cbe45679d73e', '733d1a17248f39db', '92d57b736f5f170a',
        '61b5c0a41d491399', 'b5c333457e12844a', 'bd696be010d0d889',
        '02231e1a917fe0bd',
      ],
      [ // i = 12
        '12ef8a641ec4f6d6', 'bced5de977c9faf5', '733ca476c5148639',
        '97df596b0610f6fc', 'f42c16519ad5afa7', 'aa5ac1888e10467e',
        '217d930aa51787f3', '906a6ff19e573942', '75ab709bd3dcbf24',
        'ee7ce1f345947aa4', 'f8960d6c2faf5f5e', 'e332538a36b6d246',
        '885bef040ef6aa0b', 'a4939a417bfb78a3', '646cbb7af6dce980',
        'e813a23c60af3b82',
      ],
      ];
      final h = Blake2b(trace: true)..update('abc'.codeUnits);
      h.digest();
      expect(h.roundTrace.length, 13);
      for (var r = 0; r < 13; r++) {
        for (var i = 0; i < 16; i++) {
          expect(
              u64(h.roundTrace[r][i]),
              expected[r][i],
              reason: 'v[$i] at i=$r');
        }
      }
    });

    test('the final chaining state matches the RFC', () {
      // h[8] = 0D4D1C983FA580BA ... printed big-endian; the digest is the
      // same words little-endian, which is the only place byte order is
      // observable in this function.
      final h = Blake2b()..update('abc'.codeUnits);
      final digest = h.digest();
      expect(u64(h.chainingState[0]), '0d4d1c983fa580ba');
      expect(hex(digest.sublist(0, 8)), 'ba80a53f981c4d0d');
    });
  });

  group('BLAKE2b properties Argon2 depends on', () {
    test('the empty input has the published digest', () {
      expect(
          hex(blake2b(const [])),
          '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
          'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
    });

    test('a truncated digest is the prefix of the state, not a rehash', () {
      // H^x() with x < 64 is what Argon2's H_0 and H' both use.
      for (final n in [1, 16, 32, 48, 63]) {
        expect(blake2b('abc'.codeUnits, digestLength: n).length, n);
      }
      // A different nn changes the parameter block, so it is NOT a prefix of
      // the 64-byte digest. Asserting the inequality keeps a future
      // "optimization" from truncating.
      expect(hex(blake2b('abc'.codeUnits, digestLength: 32)),
          isNot(hex(blake2b('abc'.codeUnits).sublist(0, 32))));
    });

    test('input spanning several blocks is buffered correctly', () {
      // Argon2 hashes 1024-byte blocks and longer; the boundary at exactly
      // 128 bytes is where a "compress when full" bug hides, because the last
      // block must take the finalization flag.
      for (final n in [127, 128, 129, 255, 256, 1024]) {
        final data = Uint8List(n)..fillRange(0, n, 0xAB);
        final oneShot = blake2b(data);
        final streamed = Blake2b();
        for (var i = 0; i < n; i += 7) {
          streamed.update(data.sublist(i, (i + 7) > n ? n : i + 7));
        }
        expect(hex(streamed.digest()), hex(oneShot), reason: 'n = $n');
      }
    });

    test('a keyed hash differs from an unkeyed one', () {
      expect(hex(blake2b('abc'.codeUnits, key: const [1, 2, 3])),
          isNot(hex(blake2b('abc'.codeUnits))));
    });
  });
}
