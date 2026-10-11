// Adapted from BusyBox GraphClient (Apache-2.0); see NOTICE.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';

final class GraphAuthorization {
  const GraphAuthorization(this.accessToken, {this.grantedScopes = const {}});
  final String accessToken;
  final Set<String> grantedScopes;
  @override
  String toString() => 'GraphAuthorization([REDACTED])';
}

/// The app's account-scoped token provider. [claims] is decoded JSON for MSAL,
/// never the base64 WWW-Authenticate representation or a new authority URL.
typedef GraphTokenProvider = Future<GraphAuthorization> Function({
  String? claims,
});

/// Preserves an application-owned, pre-dispatch authorization failure across
/// the shared transport boundary.
///
/// The client otherwise deliberately converts token-provider failures into a
/// credential-safe [GraphException]. Applications that already have a typed
/// proof that no request was dispatched can wrap it here and unwrap [cause] at
/// their domain boundary without teaching this package about app error types.
final class GraphTokenProviderException implements Exception {
  const GraphTokenProviderException(this.cause);

  final Object cause;

  @override
  String toString() => 'GraphTokenProviderException([REDACTED])';
}

final class GraphCancellationToken {
  final _signal = Completer<void>();
  final _events = StreamController<void>.broadcast(sync: true);
  Stream<void> get cancellations => _events.stream;
  bool get isCancelled => _signal.isCompleted;
  Future<void> get whenCancelled => _signal.future;
  void cancel() {
    if (!isCancelled) {
      _signal.complete();
      _events.add(null);
      unawaited(_events.close());
    }
  }

  void throwIfCancelled() {
    if (isCancelled)
      throw const GraphException(GraphFailure.cancelled, 'cancelled');
  }
}

enum GraphFailure {
  authentication,
  permission,
  throttled,
  conflict,
  notFound,
  invalidRequest,
  connectivity,
  tls,
  timeout,
  cancelled,
  protocol,
  unknownOutcome,
  server,
}

/// Diagnostic values contain no response content, URL or token.
final class GraphException implements Exception {
  const GraphException(
    this.kind,
    this.code, {
    this.statusCode,
    this.requestId,
    this.clientRequestId,
    this.claims,
    this.retryAt,
    this.retryAfterProvided = false,
    this.requestRejected = false,
  });
  final GraphFailure kind;
  final String code;
  final int? statusCode;
  final String? requestId;
  final String? clientRequestId;
  final String? claims;
  final DateTime? retryAt;
  final bool retryAfterProvided;
  final bool requestRejected;
  @override
  String toString() => 'GraphException($kind, $code, status: $statusCode)';
}

final class GraphResponse {
  const GraphResponse({
    required this.statusCode,
    required this.headers,
    required this.bodyBytes,
  });
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List bodyBytes;
  Map<String, Object?> jsonObject() {
    if (bodyBytes.isEmpty) return {};
    final value = jsonDecode(utf8.decode(bodyBytes));
    if (value is! Map<String, dynamic>) {
      throw const GraphException(GraphFailure.protocol, 'expected-json-object');
    }
    return value.cast<String, Object?>();
  }

  /// Large JSON decoding can be moved off a Flutter frame's isolate while the
  /// same bounded response and validation rules remain in force.
  Future<Map<String, Object?>> jsonObjectAsync() => _decodeGraphJson(bodyBytes);
}

Future<Map<String, Object?>> _decodeGraphJson(Uint8List bytes) => Isolate.run(
  () => GraphResponse(
    statusCode: 200,
    headers: const {},
    bodyBytes: bytes,
  ).jsonObject(),
);

final class GraphTransportActivity {
  const GraphTransportActivity(
    this.requests,
    this.bytesSent,
    this.bytesReceived,
  );
  final int requests;
  final int bytesSent;
  final int bytesReceived;
}

typedef GraphRequestBudget = void Function({required int uploadByteCount});

/// Refreshes an ordinary rejected access token. The client invokes this only
/// after a complete 401 response and replays at most once. Claims challenges
/// continue through [GraphTokenProvider] with their decoded claims instead.
typedef GraphAuthenticationRecovery = Future<void> Function();

/// Upload capabilities are issued by the app after parsing a trusted Graph
/// upload-session response. They bind one exact URL, never an arbitrary host.
final class GraphUploadDestination {
  GraphUploadDestination(Uri url) : uri = _validateUpload(url);
  final Uri uri;
  static Uri _validateUpload(Uri value) {
    if (value.scheme != 'https' ||
        value.host.isEmpty ||
        value.userInfo.isNotEmpty ||
        value.fragment.isNotEmpty ||
        value.port != 443) {
      throw const GraphException(
        GraphFailure.protocol,
        'invalid-upload-destination',
      );
    }
    return value;
  }

  @override
  String toString() => 'GraphUploadDestination([REDACTED])';
}

/// One claims-challenge replay after a complete 401 rejection; no transport
/// retries. Callers own backoff and reconcile unknown mutation outcomes.
/// Headers, including immutable IDs and calendar timezone, are caller policy.
final class GraphClient {
  GraphClient({
    required GraphTokenProvider tokenProvider,
    http.Client? httpClient,
    this.maximumResponseBytes = 32 * 1024 * 1024,
    this.requestTimeout = const Duration(seconds: 45),
    this.idleTimeout = const Duration(seconds: 60),
    GraphRequestBudget? budget,
    this.authenticationRecovery,
    Uuid uuid = const Uuid(),
  }) : _tokenProvider = tokenProvider,
       _client = httpClient ?? http.Client(),
       _ownsClient = httpClient == null,
       _uuid = uuid,
       _budget = budget {
    if (maximumResponseBytes < 0) throw RangeError.value(maximumResponseBytes);
  }
  static final root = Uri.parse('https://graph.microsoft.com/v1.0/');
  final GraphTokenProvider _tokenProvider;
  final http.Client _client;
  final bool _ownsClient;
  final Uuid _uuid;
  final GraphRequestBudget? _budget;
  final GraphAuthenticationRecovery? authenticationRecovery;
  final int maximumResponseBytes;
  final Duration requestTimeout;
  final Duration idleTimeout;
  final Set<Completer<void>> _active = {};
  final _subscriptions = <Completer<void>, StreamSubscription<void>>{};
  bool _closed = false;
  int _requests = 0, _sent = 0, _received = 0;

  GraphTransportActivity takeTransportActivity() {
    final result = GraphTransportActivity(_requests, _sent, _received);
    _requests = _sent = _received = 0;
    return result;
  }

  /// Opaque next/delta URLs are validated before token acquisition.
  Uri resolve(String pathOrUrl) {
    if (pathOrUrl.startsWith('//') || pathOrUrl.contains(r'\')) {
      throw const GraphException(
        GraphFailure.protocol,
        'invalid-graph-destination',
      );
    }
    final parsed = Uri.parse(pathOrUrl);
    final uri = parsed.hasScheme
        ? parsed
        : root.resolve(pathOrUrl.replaceFirst(RegExp(r'^/'), ''));
    if (uri.scheme != 'https' ||
        uri.host != root.host ||
        uri.port != 443 ||
        uri.userInfo.isNotEmpty ||
        uri.fragment.isNotEmpty ||
        !uri.path.startsWith('/v1.0/') ||
        uri.pathSegments.any((segment) => segment == '..' || segment == '.')) {
      throw const GraphException(
        GraphFailure.protocol,
        'untrusted-graph-destination',
      );
    }
    return uri;
  }

  Future<GraphResponse> get(
    String path, {
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
    int? maximumBytes,
  }) => request(
    'GET',
    path,
    headers: headers,
    cancellation: cancellation,
    maximumBytes: maximumBytes,
  );
  Future<GraphResponse> post(
    String path, {
    Object? json,
    List<int>? bytes,
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
  }) => request(
    'POST',
    path,
    json: json,
    bytes: bytes,
    headers: headers,
    cancellation: cancellation,
  );
  Future<GraphResponse> patch(
    String path,
    Object json, {
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
  }) => request(
    'PATCH',
    path,
    json: json,
    headers: headers,
    cancellation: cancellation,
  );
  Future<GraphResponse> delete(
    String path, {
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
  }) => request('DELETE', path, headers: headers, cancellation: cancellation);

  Future<GraphResponse> request(
    String method,
    String path, {
    Object? json,
    List<int>? bytes,
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
    int? maximumBytes,
    String? claims,
  }) async {
    final uri = resolve(path);
    final originalHeaders = Map<String, String>.unmodifiable(headers);
    _checkHeaders(originalHeaders);
    final token = cancellation ?? GraphCancellationToken();
    _check(token);
    // Snapshot buffered payloads once: a challenge replay must use exactly the
    // original bytes even if the caller changes its source buffer meanwhile.
    final body = json == null
        ? (bytes == null ? null : Uint8List.fromList(bytes))
        : utf8.encode(jsonEncode(json));
    var authorizationClaims = claims;
    GraphException? challenge;
    var recoveredOrdinaryAuthentication = false;
    while (true) {
      final auth = await _authorization(
        token,
        claims: authorizationClaims,
        challenge: challenge,
      );
      _check(token);
      try {
        return await _bounded(
          method,
          uri,
          body,
          {
            'accept': 'application/json',
            ...originalHeaders,
            if (json != null) 'content-type': 'application/json',
            'authorization': 'Bearer ' + auth.accessToken,
          },
          token,
          maximumBytes ?? maximumResponseBytes,
        );
      } on GraphException catch (error) {
        // A complete, correctly formed 401 means the service rejected the
        // request before applying it. An ambiguous mutation never reaches this
        // branch as an authentication error and is never replayed.
        if (authorizationClaims == null &&
            !recoveredOrdinaryAuthentication &&
            _isOrdinaryAuthenticationRejection(error) &&
            authenticationRecovery != null) {
          try {
            await authenticationRecovery!();
          } on GraphTokenProviderException {
            rethrow;
          } on Object {
            throw GraphException(
              GraphFailure.authentication,
              'token-recovery-failed',
              statusCode: error.statusCode,
              requestId: error.requestId,
              clientRequestId: error.clientRequestId,
              requestRejected: true,
            );
          }
          recoveredOrdinaryAuthentication = true;
          _check(token);
          continue;
        }
        if (authorizationClaims != null || !_isClaimsRejection(error)) rethrow;
        challenge = error;
        authorizationClaims = error.claims;
        _check(token);
      }
    }
  }

  Future<GraphResponse> upload(
    GraphUploadDestination destination, {
    required Stream<List<int>> source,
    required int length,
    required Map<String, String> headers,
    GraphCancellationToken? cancellation,
  }) async {
    _checkHeaders(headers);
    if (length < 0) throw RangeError.value(length);
    final token = cancellation ?? GraphCancellationToken();
    _check(token);
    final abort = _begin(token);
    final request =
        http.AbortableStreamedRequest(
            'PUT',
            destination.uri,
            abortTrigger: abort.future,
          )
          ..followRedirects = false
          ..contentLength = length
          ..headers.addAll(_requestHeaders(headers));
    _budget?.call(uploadByteCount: length);
    _requests++;
    var written = 0;
    // Observe both tasks immediately, including early HTTP rejection.
    final responseFuture = _await(
      _client.send(request).timeout(requestTimeout),
      abort,
    );
    final pump = (() async {
      try {
        await request.sink.addStream(
          _chunks(source, token, abort).map((chunk) {
            _check(token);
            written += chunk.length;
            if (written > length)
              throw const GraphException(
                GraphFailure.protocol,
                'upload-length',
              );
            _sent += chunk.length;
            return chunk;
          }),
        );
        if (written != length)
          throw const GraphException(GraphFailure.protocol, 'upload-length');
        await request.sink.close();
      } catch (_) {
        if (!abort.isCompleted) abort.complete();
        rethrow;
      }
    })();
    try {
      final results = await Future.wait<Object?>([
        responseFuture,
        pump,
      ], eagerError: true);
      final response = results.first as http.StreamedResponse;
      return await _read(
        response,
        maximumResponseBytes,
        token,
        request.headers['client-request-id']!,
      );
    } catch (error) {
      throw _normalize(error, mutation: true);
    } finally {
      _end(abort);
    }
  }

  /// Streaming is independent of the JSON ceiling. No complete-file buffer.
  Stream<List<int>> download(
    String path, {
    int? start,
    Map<String, String> headers = const {},
    GraphCancellationToken? cancellation,
  }) async* {
    if (start != null && start < 0) throw RangeError.value(start);
    final uri = resolve(path);
    final originalHeaders = Map<String, String>.unmodifiable(headers);
    _checkHeaders(originalHeaders);
    final token = cancellation ?? GraphCancellationToken();
    _check(token);
    String? claims;
    GraphException? challenge;
    var recoveredOrdinaryAuthentication = false;
    var yieldedPayload = false;
    while (true) {
      final auth = await _authorization(
        token,
        claims: claims,
        challenge: challenge,
      );
      _check(token);
      final abort = _begin(token);
      final request =
          http.AbortableRequest('GET', uri, abortTrigger: abort.future)
            ..followRedirects = false
            ..headers.addAll(
              _requestHeaders({
                'accept': 'application/octet-stream',
                ...originalHeaders,
                'authorization': 'Bearer ' + auth.accessToken,
                if (start != null && start > 0) 'range': 'bytes=$start-',
              }),
            );
      try {
        _budget?.call(uploadByteCount: 0);
        _requests++;
        final response = await _await(
          _client.send(request).timeout(requestTimeout),
          abort,
        );
        if (response.statusCode < 200 || response.statusCode >= 300) {
          await _read(
            response,
            min(maximumResponseBytes, 1024 * 1024),
            token,
            request.headers['client-request-id']!,
          );
        }
        if (start != null && start > 0) {
          final match = RegExp(r'^bytes (\d+)-\d+/(?:\d+|\*)$')
              .firstMatch(response.headers['content-range'] ?? '');
          if (response.statusCode != 206 ||
              int.tryParse(match?.group(1) ?? '') != start) {
            throw const GraphException(
              GraphFailure.protocol,
              'invalid-download-range',
            );
          }
        }
        await for (final chunk in _chunks(response.stream, token, abort)) {
          _check(token);
          _received += chunk.length;
          yieldedPayload = true;
          yield chunk;
        }
        return;
      } catch (error) {
        final normalized = _normalize(error, mutation: false);
        // Authentication replay is permitted only for a complete rejection
        // before any payload reaches the caller. Each recovery has one budget.
        if (yieldedPayload) throw normalized;
        if (claims == null &&
            !recoveredOrdinaryAuthentication &&
            _isOrdinaryAuthenticationRejection(normalized) &&
            authenticationRecovery != null) {
          recoveredOrdinaryAuthentication = true;
          try {
            await authenticationRecovery!();
          } on GraphTokenProviderException {
            rethrow;
          } on Object {
            throw GraphException(
              GraphFailure.authentication,
              'token-recovery-failed',
              statusCode: normalized.statusCode,
              requestId: normalized.requestId,
              clientRequestId: normalized.clientRequestId,
              requestRejected: true,
            );
          }
          _check(token);
          continue;
        }
        if (claims != null || !_isClaimsRejection(normalized)) throw normalized;
        challenge = normalized;
        claims = normalized.claims;
        _check(token);
      } finally {
        _end(abort);
      }
    }
  }

  Future<GraphResponse> _bounded(
    String method,
    Uri uri,
    List<int>? bytes,
    Map<String, String> headers,
    GraphCancellationToken token,
    int limit,
  ) async {
    final mutation = !const {
      'GET',
      'HEAD',
      'OPTIONS',
    }.contains(method.toUpperCase());
    final abort = _begin(token);
    final request =
        http.AbortableRequest(method, uri, abortTrigger: abort.future)
          ..followRedirects = false
          ..maxRedirects = 0
          ..headers.addAll(_requestHeaders(headers));
    if (bytes != null) request.bodyBytes = bytes;
    _budget?.call(uploadByteCount: bytes?.length ?? 0);
    try {
      _requests++;
      _sent += bytes?.length ?? 0;
      final response = await _await(
        _client.send(request).timeout(requestTimeout),
        abort,
      );
      final result = await _read(
        response,
        limit,
        token,
        request.headers['client-request-id']!,
      );
      return result;
    } catch (error) {
      throw _normalize(error, mutation: mutation);
    } finally {
      _end(abort);
    }
  }

  Future<GraphResponse> _read(
    http.StreamedResponse response,
    int limit,
    GraphCancellationToken token,
    String id,
  ) async {
    final abort = _begin(token);
    try {
      if (limit < 0 ||
          (response.contentLength != null && response.contentLength! > limit)) {
        throw const GraphException(GraphFailure.protocol, 'response-too-large');
      }
      final builder = BytesBuilder(copy: false);
      await for (final chunk in _chunks(response.stream, token, abort)) {
        _check(token);
        _received += chunk.length;
        if (builder.length + chunk.length > limit) {
          throw const GraphException(
            GraphFailure.protocol,
            'response-too-large',
          );
        }
        builder.add(chunk);
      }
      final result = GraphResponse(
        statusCode: response.statusCode,
        headers: Map.unmodifiable(response.headers),
        bodyBytes: builder.takeBytes(),
      );
      if (result.statusCode >= 200 && result.statusCode < 300) return result;
      String code = 'graph-' + result.statusCode.toString();
      try {
        final error = result.jsonObject()['error'];
        if (error is Map &&
            error['code'] is String &&
            RegExp(r'^[a-zA-Z0-9_.-]{1,128}$')
                .hasMatch(error['code'] as String)) {
          code = error['code'] as String;
        }
      } catch (_) {
        /* A bounded non-JSON error still has a safe code. */
      }
      final status = result.statusCode;
      final kind = switch (status) {
        401 => GraphFailure.authentication,
        403 => GraphFailure.permission,
        404 => GraphFailure.notFound,
        409 || 412 => GraphFailure.conflict,
        429 || 503 => GraphFailure.throttled,
        >= 300 && < 400 => GraphFailure.protocol,
        >= 500 => GraphFailure.server,
        _ => GraphFailure.invalidRequest,
      };
      final retryAfter = response.headers['retry-after'];
      throw GraphException(
        kind,
        code,
        statusCode: status,
        requestId: response.headers['request-id'],
        clientRequestId: id,
        claims: status == 401
            ? graphClaimsChallenge(response.headers['www-authenticate'])
            : null,
        retryAt: status == 429 || status == 503
            ? graphRetryAt(retryAfter)
            : null,
        retryAfterProvided:
            (status == 429 || status == 503) &&
            graphRetryAfterIsUsable(retryAfter),
        requestRejected: status == 401 || status == 429,
      );
    } finally {
      _end(abort);
    }
  }

  Map<String, String> _requestHeaders(Map<String, String> headers) => {
    'client-request-id': _uuid.v7(),
    'return-client-request-id': 'true',
    ...headers,
  };
  void _checkHeaders(Map<String, String> headers) {
    if (headers.keys.any(
      (key) => const {
        'authorization',
        'host',
        'client-request-id',
      }.contains(key.toLowerCase()),
    )) {
      throw ArgumentError('Transport-owned header');
    }
  }

  void _check(GraphCancellationToken token) {
    token.throwIfCancelled();
    if (_closed)
      throw const GraphException(GraphFailure.cancelled, 'client-closed');
  }

  Completer<void> _begin(GraphCancellationToken token) {
    final abort = Completer<void>();
    _active.add(abort);
    _subscriptions[abort] = token.cancellations.listen((_) {
      if (!abort.isCompleted) abort.complete();
    });
    return abort;
  }

  void _end(Completer<void> abort) {
    _active.remove(abort);
    unawaited(_subscriptions.remove(abort)?.cancel());
    if (!abort.isCompleted) abort.complete();
  }

  Future<T> _await<T>(Future<T> future, Completer<void> abort) => Future.any([
    future,
    abort.future.then<T>(
      (_) => throw const GraphException(GraphFailure.cancelled, 'cancelled'),
    ),
  ]);
  Future<GraphAuthorization> _authorization(
    GraphCancellationToken token, {
    String? claims,
    GraphException? challenge,
  }) async {
    final abort = _begin(token);
    try {
      _check(token);
      final result = await _await(_tokenProvider(claims: claims), abort);
      _check(token);
      if (result.accessToken.isEmpty) {
        throw const GraphException(
          GraphFailure.authentication,
          'missing-access-token',
        );
      }
      return result;
    } catch (error) {
      if (error is GraphTokenProviderException) rethrow;
      final failure = error is GraphException
          ? error
          : const GraphException(
              GraphFailure.authentication,
              'token-acquisition-failed',
            );
      if (challenge == null) throw failure;
      throw GraphException(
        failure.kind,
        failure.code,
        statusCode: challenge.statusCode,
        requestId: challenge.requestId,
        clientRequestId: challenge.clientRequestId,
        claims: claims,
        requestRejected: true,
      );
    } finally {
      _end(abort);
    }
  }

  bool _isClaimsRejection(GraphException error) =>
      error.kind == GraphFailure.authentication &&
      error.statusCode == 401 &&
      error.requestRejected &&
      error.claims != null;

  bool _isOrdinaryAuthenticationRejection(GraphException error) =>
      error.kind == GraphFailure.authentication &&
      error.statusCode == 401 &&
      error.requestRejected &&
      error.claims == null;

  Stream<List<int>> _chunks(
    Stream<List<int>> source,
    GraphCancellationToken token,
    Completer<void> abort,
  ) async* {
    final iterator = StreamIterator(source);
    try {
      while (await _await(iterator.moveNext().timeout(idleTimeout), abort)) {
        _check(token);
        yield iterator.current;
      }
    } finally {
      await iterator.cancel();
    }
  }

  GraphException _normalize(Object error, {required bool mutation}) {
    if (error is GraphException) {
      if (mutation &&
          (error.kind == GraphFailure.cancelled ||
              error.kind == GraphFailure.protocol ||
              error.kind == GraphFailure.server ||
              (error.kind == GraphFailure.throttled &&
                  !error.requestRejected))) {
        return GraphException(
          GraphFailure.unknownOutcome,
          'reconcile-before-retry',
          statusCode: error.statusCode,
          requestId: error.requestId,
          clientRequestId: error.clientRequestId,
          claims: error.claims,
          retryAt: error.retryAt,
          retryAfterProvided: error.retryAfterProvided,
        );
      }
      return error;
    }
    if (error is! HandshakeException &&
        error is! TlsException &&
        error is! SocketException &&
        error is! HttpException &&
        error is! TimeoutException &&
        error is! http.ClientException &&
        error is! http.RequestAbortedException) {
      // Programming failures from a supplied transport are not connectivity
      // conditions and must retain their original type for the app boundary.
      throw error;
    }
    if (mutation)
      return const GraphException(
        GraphFailure.unknownOutcome,
        'reconcile-before-retry',
      );
    return GraphException(switch (error) {
      HandshakeException() || TlsException() => GraphFailure.tls,
      TimeoutException() => GraphFailure.timeout,
      http.RequestAbortedException() => GraphFailure.cancelled,
      _ => GraphFailure.connectivity,
    }, 'transport-failed');
  }

  void close() {
    _closed = true;
    for (final abort in _active.toList()) {
      if (!abort.isCompleted) abort.complete();
    }
    for (final sub in _subscriptions.values) {
      unawaited(sub.cancel());
    }
    _subscriptions.clear();
    _active.clear();
    if (_ownsClient) _client.close();
  }
}

/// Decodes Microsoft's Bearer insufficient_claims challenge to the JSON claims
/// request consumed by MSAL. Header claims are base64, not URI-encoded JSON.
/// Other/malformed challenges are ordinary authentication failures, with no
/// token acquisition or replay. The supplied authorization URI is never used
/// as a token destination: the app's registered MSAL authority remains owner.
String? graphClaimsChallenge(String? header) {
  if (header == null ||
      header.length > 64 * 1024 ||
      header.contains('\r') ||
      header.contains('\n'))
    return null;
  try {
    for (final challenge in _authenticationChallenges(header)) {
      final parameters = challenge.parameters;
      if (challenge.scheme.toLowerCase() != 'bearer' ||
          parameters['error']?.value != 'insufficient_claims')
        continue;
      final authority = Uri.tryParse(
        parameters['authorization_uri']?.value ?? '',
      );
      final encoded = parameters['claims'];
      if (authority == null ||
          authority.scheme != 'https' ||
          authority.host.isEmpty ||
          authority.userInfo.isNotEmpty ||
          authority.fragment.isNotEmpty ||
          encoded == null ||
          !encoded.quoted ||
          encoded.value.isEmpty ||
          !RegExp(r'^[A-Za-z0-9+/]*={0,2}$').hasMatch(encoded.value))
        continue;
      final bytes = base64.decode(encoded.value);
      if (bytes.length > 32 * 1024 || base64.encode(bytes) != encoded.value)
        continue;
      final claims = utf8.decode(bytes);
      final json = jsonDecode(claims);
      if (json is Map<String, dynamic> &&
          json['access_token'] is Map<String, dynamic>) {
        return claims;
      }
    }
  } on FormatException {
    // Never pass malformed input to an account's identity provider.
  }
  return null;
}

final class _AuthenticationChallenge {
  const _AuthenticationChallenge(this.scheme, this.parameters);
  final String scheme;
  final Map<String, _AuthenticationParameter> parameters;
}

final class _AuthenticationParameter {
  const _AuthenticationParameter(this.value, this.quoted);
  final String value;
  final bool quoted;
}

// RFC 7235 auth-params are comma-delimited, but quoted commas belong to their
// value. Combined WWW-Authenticate headers can contain multiple schemes; do
// not combine error/claims/authority from different challenges.
List<_AuthenticationChallenge> _authenticationChallenges(String header) {
  var offset = 0;
  final challenges = <_AuthenticationChallenge>[];
  final tokenCharacter = RegExp(r"[!#$%&'*+.^_`|~0-9A-Za-z-]");
  void spaces() {
    while (offset < header.length &&
        (header[offset] == ' ' || header[offset] == '\t'))
      offset++;
  }

  String token() {
    final start = offset;
    while (offset < header.length && tokenCharacter.hasMatch(header[offset]))
      offset++;
    if (offset == start)
      throw const FormatException('invalid authentication token');
    return header.substring(start, offset);
  }

  while (offset < header.length) {
    spaces();
    if (offset == header.length) break;
    final scheme = token();
    final afterScheme = offset;
    spaces();
    if (offset == afterScheme &&
        offset < header.length &&
        header[offset] != ',') {
      throw const FormatException('invalid authentication scheme');
    }
    final parameters = <String, _AuthenticationParameter>{};
    while (offset < header.length && header[offset] != ',') {
      final name = token().toLowerCase();
      spaces();
      if (offset == header.length || header[offset++] != '=') {
        throw const FormatException('invalid authentication parameter');
      }
      spaces();
      final quoted = offset < header.length && header[offset] == '"';
      late String value;
      if (quoted) {
        offset++;
        final buffer = StringBuffer();
        var closed = false;
        while (offset < header.length) {
          final character = header[offset++];
          if (character == '"') {
            closed = true;
            break;
          }
          if (character == r'\') {
            if (offset == header.length)
              throw const FormatException('invalid quoted pair');
            buffer.write(header[offset++]);
          } else {
            buffer.write(character);
          }
        }
        if (!closed)
          throw const FormatException('unclosed authentication parameter');
        value = buffer.toString();
      } else {
        value = token();
      }
      if (parameters.containsKey(name))
        throw const FormatException('duplicate authentication parameter');
      parameters[name] = _AuthenticationParameter(value, quoted);
      spaces();
      if (offset == header.length) break;
      if (header[offset++] != ',')
        throw const FormatException('invalid authentication separator');
      spaces();
      if (offset == header.length)
        throw const FormatException('empty authentication parameter');
      final saved = offset;
      token();
      spaces();
      final parameterFollows = offset < header.length && header[offset] == '=';
      offset = saved;
      if (!parameterFollows) break;
    }
    challenges.add(_AuthenticationChallenge(scheme, parameters));
    if (offset < header.length && header[offset] == ',') {
      offset++;
      spaces();
    }
  }
  return challenges;
}

DateTime graphRetryAt(String? value, {DateTime? now}) {
  final current = (now ?? DateTime.now()).toUtc();
  final seconds = int.tryParse(value?.trim() ?? '');
  if (seconds != null) return current.add(Duration(seconds: max(0, seconds)));
  try {
    return HttpDate.parse(value!).toUtc();
  } catch (_) {
    return current.add(const Duration(seconds: 30));
  }
}

bool graphRetryAfterIsUsable(String? value) {
  final normalized = value?.trim();
  if (normalized == null || normalized.isEmpty) return false;
  final seconds = int.tryParse(normalized);
  if (seconds != null) return seconds >= 0;
  try {
    HttpDate.parse(normalized);
    return true;
  } on Object {
    return false;
  }
}
