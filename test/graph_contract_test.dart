import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:busystack_graph/busystack_graph.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

GraphClient graph(
  http.Client client, {
  int limit = 1024,
  Duration timeout = const Duration(seconds: 1),
  GraphTokenProvider? token,
  GraphRequestBudget? budget,
}) => GraphClient(
  httpClient: client,
  tokenProvider:
      token ??
      ({String? claims}) async => const GraphAuthorization('synthetic-fixture'),
  maximumResponseBytes: limit,
  requestTimeout: timeout,
  idleTimeout: timeout,
  budget: budget,
);

void main() {
  test('explicit immutable-ID and resource preferences, correlation and accounting', () async {
    final sent = <http.Request>[], budget = <int>[];
    final client = graph(
      MockClient((request) async {
        sent.add(request);
        return http.Response('{"value":[]}', 200);
      }),
      budget: ({required int uploadByteCount}) => budget.add(uploadByteCount),
    );
    await client.get(
      'me/contacts',
      headers: {'Prefer': 'IdType="ImmutableId"'},
    );
    await client.get(
      'me/events',
      headers: {'Prefer': 'outlook.timezone="UTC"'},
    );
    await client.get('me/messages');
    expect(sent[0].headers['prefer'], 'IdType="ImmutableId"');
    expect(sent[1].headers['prefer'], 'outlook.timezone="UTC"');
    expect(sent[2].headers.containsKey('prefer'), isFalse);
    expect(sent.every((r) => r.followRedirects == false), isTrue);
    expect(
      sent.map((r) => r.headers['client-request-id']).toSet(),
      hasLength(3),
    );
    final activity = client.takeTransportActivity();
    expect(activity.requests, 3);
    expect(activity.bytesReceived, 36);
    expect(client.takeTransportActivity().requests, 0);
    expect(budget, [0, 0, 0]);
  });
  for (final destination in [
    'http://graph.microsoft.com/v1.0/me/contacts',
    'https://graph.microsoft.com.evil.test/v1.0/me',
    'https://graph.microsoft.com@evil.test/v1.0/me',
    'https://graph.microsoft.com:444/v1.0/me',
    '//evil.test/v1.0/me',
    'https://graph.microsoft.com/beta/me',
    'https://graph.microsoft.com/v1.0/me#fragment',
    r'me\contacts',
  ]) {
    test(
      'rejects untrusted destination before token callback: ' + destination,
      () async {
        var tokens = 0, requests = 0;
        final client = graph(
          MockClient((_) async {
            requests++;
            return http.Response('{}', 200);
          }),
          token: ({String? claims}) async {
            tokens++;
            return const GraphAuthorization('synthetic');
          },
        );
        await expectLater(
          client.get(destination),
          throwsA(isA<GraphException>()),
        );
        expect(tokens, 0);
        expect(requests, 0);
      },
    );
  }
  test('opaque URL query and encoded IDs are not reconstructed', () async {
    const url =
        'https://graph.microsoft.com/v1.0/me/contactFolders/a%2Fb/contacts/delta?%24skiptoken=x%2By%3D%3D';
    late Uri actual;
    final client = graph(
      MockClient((request) async {
        actual = request.url;
        return http.Response('{}', 200);
      }),
    );
    await client.get(url);
    expect(actual.toString(), url);
  });
  test(
    'read bounds check both content length and actual streamed bytes',
    () async {
      for (final declared in [null, 200]) {
        final client = graph(
          _Client(
            (_) async => http.StreamedResponse(
              Stream.fromIterable([List.filled(40, 0), List.filled(80, 0)]),
              200,
              contentLength: declared,
            ),
          ),
          limit: 100,
        );
        await expectLater(
          client.get('me'),
          throwsA(
            isA<GraphException>().having(
              (e) => e.code,
              'code',
              'response-too-large',
            ),
          ),
        );
      }
    },
  );
  test('401 challenge and IDs normalize without echoing content', () async {
    final client = graph(
      MockClient(
        (_) async => http.Response(
          '{"error":{"code":"InvalidAuthenticationToken","message":"private-data"}}',
          401,
          headers: {
            'www-authenticate':
                'Bearer error="insufficient_claims", '
                    'authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", '
                    'claims="' +
                base64.encode(
                  utf8.encode(
                    '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}',
                  ),
                ) +
                '"',
            'request-id': 'server-id',
          },
        ),
      ),
    );
    try {
      await client.get('me');
      fail('expected challenge');
    } on GraphException catch (error) {
      expect(error.kind, GraphFailure.authentication);
      expect(
        error.claims,
        '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}',
      );
      expect(error.requestId, 'server-id');
      expect(error.clientRequestId, isNotNull);
      expect(error.toString(), isNot(contains('private-data')));
    }
  });
  test(
    '429 reports Retry-After and remains a confirmed rejection; no retries',
    () async {
      var requests = 0;
      final client = graph(
        MockClient((_) async {
          requests++;
          return http.Response('{}', 429, headers: {'retry-after': '60'});
        }),
      );
      await expectLater(
        client.post('me/messages', json: {}),
        throwsA(
          isA<GraphException>()
              .having((e) => e.kind, 'kind', GraphFailure.throttled)
              .having((e) => e.requestRejected, 'rejected', true)
              .having((e) => e.retryAt, 'retry', isNotNull)
              .having((e) => e.retryAfterProvided, 'authoritative retry', true),
        ),
      );
      expect(requests, 1);
    },
  );
  for (final method in ['POST', 'PATCH', 'DELETE', 'PUT']) {
    test(method + ' timeout is unknown and never replayed', () async {
      var calls = 0;
      final client = graph(
        _Client((_) {
          calls++;
          return Completer<http.StreamedResponse>().future;
        }),
        timeout: const Duration(milliseconds: 20),
      );
      await expectLater(
        client.request(method, 'me/contacts', json: {}),
        throwsA(
          isA<GraphException>().having(
            (e) => e.kind,
            'kind',
            GraphFailure.unknownOutcome,
          ),
        ),
      );
      expect(calls, 1);
    });
  }
  test(
    'cancellation interrupts token acquisition and an ignored abort',
    () async {
      for (final duringToken in [true, false]) {
        final token = GraphCancellationToken();
        final client = graph(
          _Client((_) => Completer<http.StreamedResponse>().future),
          token: ({String? claims}) => duringToken
              ? Completer<GraphAuthorization>().future
              : Future.value(const GraphAuthorization('synthetic')),
        );
        final future = client.get('me', cancellation: token);
        scheduleMicrotask(token.cancel);
        await expectLater(
          future.timeout(const Duration(seconds: 1)),
          throwsA(
            isA<GraphException>().having(
              (e) => e.kind,
              'kind',
              GraphFailure.cancelled,
            ),
          ),
        );
      }
    },
  );
  test('cancellation interrupts idle response body', () async {
    final source = StreamController<List<int>>(),
        token = GraphCancellationToken();
    final client = graph(
      _Client((_) async => http.StreamedResponse(source.stream, 200)),
    );
    final future = client.get('me', cancellation: token);
    await Future<void>.delayed(const Duration(milliseconds: 10));
    token.cancel();
    await expectLater(
      future,
      throwsA(
        isA<GraphException>().having(
          (e) => e.kind,
          'kind',
          GraphFailure.cancelled,
        ),
      ),
    );
    await source.close();
  });
  test(
    'preauthorized upload omits bearer and preserves backpressure',
    () async {
      var tokens = 0, count = 0;
      late http.BaseRequest captured;
      final client = graph(
        _Client((request) async {
          captured = request;
          await for (final chunk in request.finalize()) {
            count += chunk.length;
            await Future<void>.delayed(const Duration(milliseconds: 1));
          }
          return http.StreamedResponse(
            Stream.value(utf8.encode('{"id":"uploaded"}')),
            201,
          );
        }),
        token: ({String? claims}) async {
          tokens++;
          return const GraphAuthorization('must-not-send');
        },
      );
      Stream<List<int>> source() async* {
        for (var i = 0; i < 32; i++) {
          yield Uint8List(65536);
        }
      }

      await client.upload(
        GraphUploadDestination(
          Uri.parse(
            'https://outlook.office.com/upload/opaque?signature=fixture',
          ),
        ),
        source: source(),
        length: 32 * 65536,
        headers: {'Content-Range': 'bytes 0-2097151/2097152'},
      );
      expect(count, 32 * 65536);
      expect(tokens, 0);
      expect(
        captured.headers.keys.map((k) => k.toLowerCase()),
        isNot(contains('authorization')),
      );
      expect(captured.followRedirects, false);
    },
  );
  test('streaming download is independent of JSON ceiling', () async {
    final client = graph(
      _Client(
        (_) async => http.StreamedResponse(
          Stream.fromIterable(List.generate(256, (_) => Uint8List(65536))),
          200,
        ),
      ),
      limit: 1,
    );
    var count = 0;
    await for (final chunk in client.download(
      'me/messages/id/attachments/id/value',
    )) {
      count += chunk.length;
    }
    expect(count, 16 * 1024 * 1024);
  });
  test('range validation prevents corrupt resume', () async {
    for (final headers in [
      {'content-range': 'bytes 9-20/40'},
      <String, String>{},
    ]) {
      final client = graph(
        _Client(
          (_) async =>
              http.StreamedResponse(Stream.value([1]), 206, headers: headers),
        ),
      );
      await expectLater(
        client.download('me', start: 10).drain<void>(),
        throwsA(isA<GraphException>()),
      );
    }
  });
  test('caller transport programming failures retain their type', () async {
    final client = graph(
      _Client((_) async => throw StateError('fixture-programming-failure')),
    );
    await expectLater(
      client.get('me'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          'fixture-programming-failure',
        ),
      ),
    );
    await expectLater(
      client.post('me/messages', json: const {}),
      throwsA(isA<StateError>()),
    );
  });
  test('independent instances do not close a caller-owned client', () async {
    final supplied = _Client(
      (_) async => http.StreamedResponse(Stream.value([123, 125]), 200),
    );
    final first = graph(supplied), second = graph(supplied);
    first.close();
    expect(supplied.closed, false);
    expect((await second.get('me')).jsonObject(), isEmpty);
    second.close();
  });
  test(
    'malformed claims do not replay and Retry-After supports HTTP dates',
    () {
      expect(graphClaimsChallenge('Bearer claims="a\\"b"'), isNull);
      expect(graphClaimsChallenge('Bearer realm="x"'), isNull);
      final now = DateTime.utc(2026, 10, 4);
      expect(
        graphRetryAt('12', now: now),
        now.add(const Duration(seconds: 12)),
      );
      expect(
        graphRetryAt('Sun, 04 Oct 2026 00:01:00 GMT', now: now),
        now.add(const Duration(minutes: 1)),
      );
      expect(graphRetryAfterIsUsable('12'), isTrue);
      expect(graphRetryAfterIsUsable('Sun, 04 Oct 2026 00:01:00 GMT'), isTrue);
      expect(graphRetryAfterIsUsable('invalid'), isFalse);
      expect(graphRetryAfterIsUsable(null), isFalse);
    },
  );
}

class _Client extends http.BaseClient {
  _Client(this.callback);
  final Future<http.StreamedResponse> Function(http.BaseRequest) callback;
  bool closed = false;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      callback(request);
  @override
  void close() {
    closed = true;
  }
}
