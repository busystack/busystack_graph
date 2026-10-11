import 'dart:async';
import 'dart:convert';

import 'package:busystack_graph/busystack_graph.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

final class _Transport extends http.BaseClient {
  _Transport(this.respond);
  final Future<http.StreamedResponse> Function(http.BaseRequest) respond;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      respond(request);
}

http.StreamedResponse _response(
  int status, {
  Map<String, String> headers = const {},
}) => http.StreamedResponse(
  Stream.value(utf8.encode(status == 200 || status == 206 ? 'payload' : '{}')),
  status,
  headers: headers,
);

void main() {
  for (final ranged in [false, true]) {
    test('ordinary 401 refreshes before yielding (range=$ranged)', () async {
      var requests = 0, refreshes = 0;
      final authorizations = <String>[];
      final client = GraphClient(
        httpClient: _Transport((request) async {
          requests++;
          authorizations.add(request.headers['authorization']!);
          expect(request.headers['x-fixture'], 'retained');
          expect(request.headers['range'], ranged ? 'bytes=7-' : null);
          return requests == 1
              ? _response(401)
              : _response(
                  ranged ? 206 : 200,
                  headers: ranged ? {'content-range': 'bytes 7-13/14'} : {},
                );
        }),
        tokenProvider: ({claims}) async =>
            GraphAuthorization(refreshes == 0 ? 'old' : 'new'),
        authenticationRecovery: () async {
          refreshes++;
        },
      );
      expect(
        utf8.decode(
          await client
              .download(
                'me/messages/id/attachments/id/\$value',
                start: ranged ? 7 : null,
                headers: {'x-fixture': 'retained'},
              )
              .expand((chunk) => chunk)
              .toList(),
        ),
        'payload',
      );
      expect(requests, 2);
      expect(refreshes, 1);
      expect(authorizations, ['Bearer old', 'Bearer new']);
      expect(client.takeTransportActivity().requests, 2);
      client.close();
    });
  }
  test(
    'repeated ordinary rejection has one refresh and two requests',
    () async {
      var requests = 0, refreshes = 0;
      final client = GraphClient(
        httpClient: _Transport((_) async {
          requests++;
          return _response(401);
        }),
        tokenProvider: ({claims}) async => const GraphAuthorization('token'),
        authenticationRecovery: () async {
          refreshes++;
        },
      );
      await expectLater(
        client.download('me').drain<void>(),
        throwsA(
          isA<GraphException>().having(
            (e) => e.kind,
            'kind',
            GraphFailure.authentication,
          ),
        ),
      );
      expect(requests, 2);
      expect(refreshes, 1);
      client.close();
    },
  );
  test('app refresh failure retains its meaning without replay', () async {
    final cause = StateError('refresh failed');
    var requests = 0;
    final client = GraphClient(
      httpClient: _Transport((_) async {
        requests++;
        return _response(401);
      }),
      tokenProvider: ({claims}) async => const GraphAuthorization('token'),
      authenticationRecovery: () async =>
          throw GraphTokenProviderException(cause),
    );
    await expectLater(
      client.download('me').drain<void>(),
      throwsA(
        isA<GraphTokenProviderException>().having(
          (e) => e.cause,
          'cause',
          same(cause),
        ),
      ),
    );
    expect(requests, 1);
    client.close();
  });
  test('cancellation during refresh prevents replay', () async {
    final cancellation = GraphCancellationToken();
    var requests = 0;
    final client = GraphClient(
      httpClient: _Transport((_) async {
        requests++;
        return _response(401);
      }),
      tokenProvider: ({claims}) async => const GraphAuthorization('token'),
      authenticationRecovery: () async => cancellation.cancel(),
    );
    await expectLater(
      client.download('me', cancellation: cancellation).drain<void>(),
      throwsA(
        isA<GraphException>().having(
          (e) => e.kind,
          'kind',
          GraphFailure.cancelled,
        ),
      ),
    );
    expect(requests, 1);
    client.close();
  });
  test('alternating rejection types have a bounded replay budget', () async {
    for (final ordinaryFirst in [true, false]) {
      var requests = 0, refreshes = 0;
      final claims = base64.encode(
        utf8.encode('{"access_token":{"acrs":{"value":"c1"}}}'),
      );
      final client = GraphClient(
        httpClient: _Transport((_) async {
          requests++;
          final ordinary = (requests.isOdd == ordinaryFirst);
          return _response(
            401,
            headers: ordinary
                ? {}
                : {
                    'www-authenticate':
                        'Bearer error="insufficient_claims", claims="$claims"',
                  },
          );
        }),
        tokenProvider: ({claims}) async => const GraphAuthorization('token'),
        authenticationRecovery: () async {
          refreshes++;
        },
      );
      await expectLater(
        client.download('me').drain<void>(),
        throwsA(isA<GraphException>()),
      );
      expect(requests, lessThanOrEqualTo(3));
      expect(refreshes, lessThanOrEqualTo(1));
      client.close();
    }
  });
  test('a failure after payload is yielded is never replayed', () async {
    var requests = 0, refreshes = 0;
    Stream<List<int>> payload() async* {
      yield [1, 2];
      throw const GraphException(
        GraphFailure.authentication,
        'late-error',
        statusCode: 401,
        requestRejected: true,
        claims: '{"access_token":{}}',
      );
    }

    final client = GraphClient(
      httpClient: _Transport((_) async {
        requests++;
        return http.StreamedResponse(payload(), 200);
      }),
      tokenProvider: ({claims}) async => const GraphAuthorization('token'),
      authenticationRecovery: () async {
        refreshes++;
      },
    );
    final chunks = <List<int>>[];
    await expectLater(
      client.download('me').forEach(chunks.add),
      throwsA(isA<GraphException>()),
    );
    expect(chunks, [
      [1, 2],
    ]);
    expect(requests, 1);
    expect(refreshes, 0);
    client.close();
  });
}
