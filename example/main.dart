import 'package:busystack_graph/busystack_graph.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Future<void> main() async {
  final client = GraphClient(
    tokenProvider: ({String? claims}) async =>
        const GraphAuthorization('fixture-token'),
    httpClient: MockClient((request) async {
      if (request.url.host != 'graph.microsoft.com' ||
          request.headers['prefer'] != 'IdType="ImmutableId"')
        throw StateError('Request contract');
      return http.Response('{"value":[]}', 200);
    }),
  );
  final response = await client.get(
    'me/contacts',
    headers: {'Prefer': 'IdType="ImmutableId"'},
  );
  print((await response.jsonObjectAsync())['value']);
  client.close();
}
