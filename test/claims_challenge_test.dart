import 'dart:async';
import 'dart:convert';

import 'package:busystack_graph/busystack_graph.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

const claimsJson = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
String challenge([String claims = claimsJson]) =>
    'Bearer realm="", error="insufficient_claims", '
    'authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", '
    'claims="${base64.encode(utf8.encode(claims))}"';
http.Response rejection({String? header}) => http.Response(
  '{}',
  401,
  headers: {
    'www-authenticate': header ?? challenge(),
    'request-id': 'rejected-request',
  },
);

void main() {
  test('ordinary rejected token refreshes and replays exactly once', () async {
    var requests = 0;
    var recoveries = 0;
    final tokens = <String>[];
    final client = GraphClient(
      httpClient: MockClient((request) async {
        requests++;
        tokens.add(request.headers['authorization']!);
        return requests == 1
            ? http.Response(
                '{"error":{"code":"InvalidAuthenticationToken"}}',
                401,
              )
            : http.Response('{"value":[]}', 200);
      }),
      tokenProvider: ({claims}) async =>
          GraphAuthorization(recoveries == 0 ? 'expired' : 'refreshed'),
      authenticationRecovery: () async {
        recoveries++;
      },
    );

    expect((await client.get('me/todo/lists')).statusCode, 200);
    expect(requests, 2);
    expect(recoveries, 1);
    expect(tokens, ['Bearer expired', 'Bearer refreshed']);
  });

  test(
    'app pre-dispatch token failure crosses the transport unchanged',
    () async {
      final cause = StateError('app-owned-token-failure');
      final client = GraphClient(
        httpClient: MockClient((_) async => http.Response('{}', 200)),
        tokenProvider: ({claims}) async =>
            throw GraphTokenProviderException(cause),
      );

      await expectLater(
        client.get('me/todo/lists'),
        throwsA(
          isA<GraphTokenProviderException>().having(
            (error) => error.cause,
            'cause',
            same(cause),
          ),
        ),
      );
    },
  );

  test(
    'app pre-dispatch recovery failure crosses the transport unchanged',
    () async {
      final cause = StateError('app-owned-refresh-failure');
      var sends = 0;
      final client = GraphClient(
        httpClient: MockClient((_) async {
          sends++;
          return http.Response('{}', 401);
        }),
        tokenProvider: ({claims}) async => const GraphAuthorization('expired'),
        authenticationRecovery: () async =>
            throw GraphTokenProviderException(cause),
      );

      await expectLater(
        client.get('me/todo/lists'),
        throwsA(
          isA<GraphTokenProviderException>().having(
            (error) => error.cause,
            'cause',
            same(cause),
          ),
        ),
      );
      expect(sends, 1);
    },
  );

  test(
    'base64 claims stay within one Bearer challenge and decode to MSAL JSON',
    () {
      expect(graphClaimsChallenge(challenge()), claimsJson);
      expect(
        graphClaimsChallenge('Basic realm="private, test", ${challenge()}'),
        claimsJson,
      );
      expect(
        graphClaimsChallenge('${challenge()}, Basic realm="other"'),
        claimsJson,
      );
      expect(
        graphClaimsChallenge(
          challenge('{"access_token":{"label":{"value":"Zoë, 李"}}}'),
        ),
        '{"access_token":{"label":{"value":"Zoë, 李"}}}',
      );
    },
  );

  test('malformed, URI encoded, incomplete, duplicate and oversized claims are rejected', () {
    for (final header in [
      challenge().replaceFirst('Bearer', 'Basic'),
      challenge().replaceFirst('insufficient_claims', 'invalid_token'),
      challenge().replaceFirst(RegExp(r'authorization_uri="[^"]+", '), ''),
      challenge().replaceFirst(
        RegExp(r'claims="[^"]+"'),
        'claims="%7B%22access_token%22%3A%7B%7D%7D"',
      ),
      challenge().replaceFirst(
        RegExp(r'claims="[^"]+"'),
        'claims="not base64"',
      ),
      challenge().replaceFirst(
        RegExp(r'claims="[^"]+"'),
        'claims="${base64.encode([0xff])}"',
      ),
      challenge('{bad-json'),
      challenge('[]'),
      challenge('{"id_token":{}}'),
      '${challenge()}, claims="${base64.encode(utf8.encode(claimsJson))}"',
      challenge()
          .replaceFirst('claims="', 'claims=')
          .replaceFirst(RegExp(r'"$'), ''),
      'Bearer error="insufficient_claims", Basic authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize", claims="${base64.encode(utf8.encode(claimsJson))}"',
      challenge() + '\r\n',
      challenge('{"access_token":{"value":"${'x' * (32 * 1024)}"}}'),
    ]) {
      expect(
        graphClaimsChallenge(header),
        isNull,
        reason: header.substring(0, header.length.clamp(0, 180)),
      );
    }
  });

  for (final method in ['GET', 'POST', 'PATCH', 'DELETE', 'PUT']) {
    test(
      '$method confirmed 401 acquires claims token and replays once with explicit policy',
      () async {
        final tokens = <String?>[],
            requests = <http.Request>[],
            budgets = <int>[];
        final graph = GraphClient(
          tokenProvider: ({String? claims}) async {
            tokens.add(claims);
            return GraphAuthorization(
              claims == null ? 'initial' : 'satisfying',
            );
          },
          budget: ({required int uploadByteCount}) =>
              budgets.add(uploadByteCount),
          httpClient: MockClient((request) async {
            requests.add(request);
            return requests.length == 1
                ? rejection()
                : http.Response('{"value":[]}', 200);
          }),
        );
        await graph.request(
          method,
          'me/contacts',
          json: {'displayName': 'Zoë'},
          headers: {'Prefer': 'IdType="ImmutableId"'},
        );
        expect(tokens, [null, claimsJson]);
        expect(requests, hasLength(2));
        expect(requests.map((request) => request.headers['authorization']), [
          'Bearer initial',
          'Bearer satisfying',
        ]);
        expect(requests[0].bodyBytes, requests[1].bodyBytes);
        expect(requests[0].url, requests[1].url);
        expect(
          requests.every(
            (request) =>
                request.headers['prefer'] == 'IdType="ImmutableId"' &&
                !request.followRedirects,
          ),
          isTrue,
        );
        expect(
          requests
              .map((request) => request.headers['client-request-id'])
              .toSet(),
          hasLength(2),
        );
        expect(budgets, [
          requests[0].bodyBytes.length,
          requests[1].bodyBytes.length,
        ]);
        expect(graph.takeTransportActivity().requests, 2);
        graph.close();
      },
    );
  }

  test('repeated challenge terminates after the single replay with last correlation IDs', () async {
    var sends = 0;
    final tokens = <String?>[];
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async {
        tokens.add(claims);
        return const GraphAuthorization('token');
      },
      httpClient: MockClient((request) async {
        sends++;
        return http.Response(
          '{}',
          401,
          headers: {
            'www-authenticate': challenge(),
            'request-id': 'request-$sends',
          },
        );
      }),
    );
    await expectLater(
      graph.get('me/contacts'),
      throwsA(
        isA<GraphException>()
            .having((error) => error.kind, 'kind', GraphFailure.authentication)
            .having((error) => error.requestId, 'requestId', 'request-2')
            .having((error) => error.claims, 'claims', claimsJson),
      ),
    );
    expect(sends, 2);
    expect(tokens, [null, claimsJson]);
    graph.close();
  });

  test('malformed challenge never acquires another token or replays', () async {
    var sends = 0, tokens = 0;
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async {
        tokens++;
        return const GraphAuthorization('token');
      },
      httpClient: MockClient((request) async {
        sends++;
        return rejection(header: 'Bearer claims="%7B%7D"');
      }),
    );
    await expectLater(
      graph.post('me/contacts', json: {}),
      throwsA(
        isA<GraphException>().having(
          (error) => error.kind,
          'kind',
          GraphFailure.authentication,
        ),
      ),
    );
    expect(sends, 1);
    expect(tokens, 1);
    graph.close();
  });

  test('claims token failure retains confirmed rejection and correlation without replay', () async {
    var sends = 0;
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async {
        if (claims != null) throw StateError('private-token-error');
        return const GraphAuthorization('initial');
      },
      httpClient: MockClient((request) async {
        sends++;
        return rejection();
      }),
    );
    await expectLater(
      graph.patch('me/contacts/id', {}),
      throwsA(
        isA<GraphException>()
            .having((error) => error.kind, 'kind', GraphFailure.authentication)
            .having((error) => error.code, 'code', 'token-acquisition-failed')
            .having((error) => error.requestRejected, 'requestRejected', true)
            .having((error) => error.requestId, 'requestId', 'rejected-request')
            .having(
              (error) => error.clientRequestId,
              'clientRequestId',
              isNotNull,
            )
            .having(
              (error) => error.toString(),
              'diagnostic',
              isNot(contains('private-token-error')),
            ),
      ),
    );
    expect(sends, 1);
    graph.close();
  });

  for (final closeClient in [false, true]) {
    test(
      '${closeClient ? 'account/client close' : 'cancellation'} fences pending claims acquisition before replay',
      () async {
        final entered = Completer<void>(),
            release = Completer<GraphAuthorization>();
        var sends = 0;
        final graph = GraphClient(
          tokenProvider: ({String? claims}) async {
            if (claims != null) {
              entered.complete();
              return release.future;
            }
            return const GraphAuthorization('initial');
          },
          httpClient: MockClient((request) async {
            sends++;
            return rejection();
          }),
        );
        final cancellation = GraphCancellationToken();
        final result = graph.post(
          'me/contacts',
          json: {},
          cancellation: cancellation,
        );
        final assertion = expectLater(
          result,
          throwsA(
            isA<GraphException>().having(
              (error) => error.kind,
              'kind',
              GraphFailure.cancelled,
            ),
          ),
        );
        await entered.future;
        if (closeClient) {
          graph.close();
        } else {
          cancellation.cancel();
        }
        await assertion;
        release.complete(const GraphAuthorization('stale'));
        await Future<void>.delayed(Duration.zero);
        expect(sends, 1);
        graph.close();
      },
    );
  }

  test('unknown outcome after claims replay is never replayed again', () async {
    var sends = 0;
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async =>
          const GraphAuthorization('token'),
      httpClient: MockClient((request) async {
        sends++;
        if (sends == 1) return rejection();
        throw TimeoutException('transport');
      }),
    );
    await expectLater(
      graph.post('me/contacts', json: {}),
      throwsA(
        isA<GraphException>().having(
          (error) => error.kind,
          'kind',
          GraphFailure.unknownOutcome,
        ),
      ),
    );
    expect(sends, 2);
    graph.close();
  });

  test('claims replay snapshots caller-owned bytes and headers', () async {
    final bytes = <int>[1, 2, 3];
    final headers = <String, String>{'Prefer': 'IdType="ImmutableId"'};
    var sends = 0;
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async {
        if (claims != null) {
          bytes[0] = 9;
          headers['Prefer'] = 'changed';
        }
        return const GraphAuthorization('token');
      },
      httpClient: MockClient((request) async {
        sends++;
        expect(request.bodyBytes, [1, 2, 3]);
        expect(request.headers['prefer'], 'IdType="ImmutableId"');
        return sends == 1 ? rejection() : http.Response('{}', 200);
      }),
    );
    await graph.request(
      'PUT',
      'me/contacts/id/photo/\$value',
      bytes: bytes,
      headers: headers,
    );
    expect(sends, 2);
    graph.close();
  });

  test('streaming download handles challenge before yielding while retaining ranges and accounting', () async {
    var sends = 0;
    final tokens = <String?>[];
    final graph = GraphClient(
      tokenProvider: ({String? claims}) async {
        tokens.add(claims);
        return const GraphAuthorization('token');
      },
      httpClient: MockClient((request) async {
        sends++;
        expect(request.headers['range'], 'bytes=10-');
        return sends == 1
            ? rejection()
            : http.Response.bytes(
                [1, 2, 3],
                206,
                headers: {'content-range': 'bytes 10-12/13'},
              );
      }),
    );
    expect(
      await graph
          .download('me/contacts/id/photo/\$value', start: 10)
          .expand((bytes) => bytes)
          .toList(),
      [1, 2, 3],
    );
    expect(tokens, [null, claimsJson]);
    expect(sends, 2);
    graph.close();
  });

  test('response limit remains enforced on the replay', () async {
    var sends = 0;
    final graph = GraphClient(
      maximumResponseBytes: 16,
      tokenProvider: ({String? claims}) async =>
          const GraphAuthorization('token'),
      httpClient: MockClient((request) async {
        sends++;
        return sends == 1 ? rejection() : http.Response('x' * 17, 200);
      }),
    );
    await expectLater(
      graph.get('me/contacts'),
      throwsA(
        isA<GraphException>().having(
          (error) => error.code,
          'code',
          'response-too-large',
        ),
      ),
    );
    expect(sends, 2);
    graph.close();
  });
}
