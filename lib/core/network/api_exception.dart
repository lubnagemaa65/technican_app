import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../storage/secure_storage_service.dart';

/// خطأ موحّد يُعرض للمستخدم (رسالة جاهزة للعرض في SnackBar أو ErrorStateWidget).
class ApiException implements Exception {
  final String message;
  final int? statusCode;

  ApiException(this.message, {this.statusCode});

  @override
  String toString() => message;
}

/// عميل Dio المركزي للمصادقة والطلبات المحمية.
///
/// مسؤولياته:
/// - إضافة Access Token إلى الطلبات.
/// - تجديد Access Token مرة واحدة عند انتهاء صلاحيته.
/// - عدم مسح الجلسة عند أخطاء الشبكة أو توقف الخادم.
/// - إبلاغ AuthProvider فقط عندما يثبت أن Refresh Token غير صالح.
class ApiClient {
  ApiClient._() {
    dio = Dio(
      BaseOptions(
        baseUrl: baseUrl,
        connectTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 20),
        headers: {'Content-Type': 'application/json'},
      ),
    );

    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          final generation = options.extra.putIfAbsent(
            _generationKey,
            () => _sessionGeneration,
          ) as int;

          if (!_isCurrent(options, generation)) {
            return handler.reject(_staleRequest(options));
          }

          try {
            final token = await _storage.read(key: _accessKey);

            if (!_isCurrent(options, generation)) {
              return handler.reject(_staleRequest(options));
            }

            if (token != null && token.isNotEmpty) {
              options.headers['Authorization'] = 'Bearer $token';
            } else {
              options.headers.remove('Authorization');
            }

            handler.next(options);
          } catch (error, stack) {
            handler.reject(
              DioException(
                requestOptions: options,
                error: error,
                stackTrace: stack,
              ),
            );
          }
        },
        onResponse: (response, handler) {
          final request = response.requestOptions;
          final generation = request.extra[_generationKey] as int?;

          if (!_isCurrent(request, generation)) {
            return handler.reject(_staleRequest(request));
          }

          handler.next(response);
        },
        onError: (error, handler) async {
          final request = error.requestOptions;
          final generation = request.extra[_generationKey] as int?;

          debugPrint(
            'API ERROR: ${error.response?.statusCode} '
            '${request.method} ${request.uri}',
          );

          if (!_isCurrent(request, generation)) {
            return handler.next(_staleRequest(request));
          }

          final isAuthCall = _isAuthCall(request);
          final isUnauthorized = error.response?.statusCode == 401;

          // Login/refresh requests يجب أن تُعاد أخطاؤها مباشرة، ولا يجوز
          // أن يؤدي فشل تسجيل الدخول إلى استدعاء تسجيل الخروج.
          if (!isUnauthorized || isAuthCall) {
            return handler.next(error);
          }

          // لا نعيد محاولة الطلب أكثر من مرة.
          if (request.extra['retried'] == true) {
            _notifyExpired();
            return handler.next(error);
          }

          try {
            // إذا كان طلب آخر قد جدّد التوكن أثناء هذه العملية، نستخدمه
            // مباشرة ولا نستهلك Refresh Token مرتين.
            final currentAccessToken = await _storage.read(key: _accessKey);

            if (!_isCurrent(request, generation)) {
              return handler.next(_staleRequest(request));
            }

            final sentAuthorization =
                request.headers['Authorization']?.toString();
            final alreadyRefreshed = currentAccessToken != null &&
                sentAuthorization != null &&
                sentAuthorization != 'Bearer $currentAccessToken';

            final refreshed = alreadyRefreshed ||
                await _refreshOnce(
                  generation!,
                  sentAuthorization,
                );

            if (!_isCurrent(request, generation)) {
              return handler.next(_staleRequest(request));
            }

            if (refreshed) {
              request.extra['retried'] = true;

              try {
                // onRequest يقرأ أحدث Access Token تلقائيًا.
                return handler.resolve(await dio.fetch(request));
              } on DioException catch (retryError) {
                return handler.next(retryError);
              }
            }
          } on DioException catch (refreshError) {
            if (!_isCurrent(request, generation)) {
              return handler.next(_staleRequest(request));
            }

            // خطأ الاتصال أو الخادم لا يثبت انتهاء الجلسة؛ نعيد الخطأ
            // للواجهة بدل مسح بيانات الدخول.
            return handler.next(refreshError);
          } catch (refreshError, stack) {
            if (!_isCurrent(request, generation)) {
              return handler.next(_staleRequest(request));
            }

            return handler.next(
              DioException(
                requestOptions: request,
                error: refreshError,
                stackTrace: stack,
              ),
            );
          }

          // نصل إلى هنا فقط عندما يرفض الخادم Refresh Token فعليًا.
          if (_isCurrent(request, generation)) {
            _notifyExpired();
          }

          handler.next(error);
        },
      ),
    );
  }

  /// يُستدعى عند ثبوت انتهاء الجلسة.
  static void Function()? onSessionExpired;
  static bool _expiredNotified = false;

  static void _notifyExpired() {
    if (_expiredNotified) return;
    _expiredNotified = true;

    final callback = onSessionExpired;
    if (callback != null) {
      callback();
    } else {
      // لا نترك جلسة منتهية قابلة للاستخدام حتى لو لم تكن الواجهة جاهزة.
      instance.invalidateSession();
      unawaited(instance._clearExpiredWithoutListener());
    }
  }

  static final ApiClient instance = ApiClient._();

  /// API_BASE_URL هو الخيار الموصى به في GitHub Actions.
  /// API_URL مدعوم للتوافق مع الإصدارات القديمة.
  static const String baseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: String.fromEnvironment(
      'API_URL',
      defaultValue: 'http://192.168.1.66:3000/v1',
    ),
  );

  static const String _accessKey = 'access_token';
  static const String _refreshKey = 'refresh_token';
  static const String _userKey = 'current_user_json';
  static const String _generationKey = 'session_generation';

  // تبقى خيارات التخزين متوافقة مع الجلسات السابقة التي أنشأها ApiClient.
  final FlutterSecureStorage _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock,
    ),
  );
  late final Dio dio;

  Future<bool>? _refreshing;
  int? _refreshGeneration;
  int _sessionGeneration = 0;
  bool _sessionBlocked = false;
  Future<void>? _storageWrites;

  bool _isAuthCall(RequestOptions request) {
    final path = Uri.parse(request.path).path;
    return path.startsWith('/auth/');
  }

  bool _isCurrent(RequestOptions request, int? generation) {
    return generation == _sessionGeneration &&
        (!_sessionBlocked || _isAuthCall(request));
  }

  DioException _staleRequest(RequestOptions request) {
    return DioException(
      requestOptions: request,
      type: DioExceptionType.cancel,
      error: 'Session changed',
    );
  }

  /// يبطل الطلبات القديمة قبل بدء تنظيف التخزين بشكل غير متزامن.
  void invalidateSession() {
    _sessionGeneration++;
    _sessionBlocked = true;
    _refreshing = null;
    _refreshGeneration = null;
  }

  /// يُستدعى بعد اكتمال تسجيل الدخول أو استعادة الجلسة بنجاح.
  void activateSession() {
    _sessionBlocked = false;
    _expiredNotified = false;
  }

  Future<void> _clearExpiredWithoutListener() async {
    try {
      await clearTokens();
    } catch (_) {
      // نتابع تنظيف بيانات الملف الشخصي حتى لو فشل حذف التوكنات.
    }

    try {
      await SecureStorageService.instance.clearSession();
    } catch (_) {
      // قد يكون التخزين غير متاح مؤقتًا؛ تبقى الجلسة محجوبة في الذاكرة.
    }
  }

  Future<T> _serializeStorage<T>(Future<T> Function() operation) {
    final previous = _storageWrites;
    final result = previous == null
        ? Future<T>.sync(operation)
        : previous.then((_) => operation());

    late final Future<void> finished;
    finished = result.then<void>(
      (_) {},
      onError: (Object _, StackTrace __) {},
    );
    _storageWrites = finished;

    unawaited(
      finished.whenComplete(() {
        if (identical(_storageWrites, finished)) {
          _storageWrites = null;
        }
      }),
    );

    return result;
  }

  // ---------------- التوكنات والجلسة ----------------

  /// شكل [tokens]:
  /// {access: {token, expires}, refresh: {token, expires}}
  Future<void> saveTokens(
    Map<String, dynamic> tokens, {
    int? expectedGeneration,
  }) {
    return _serializeStorage(() async {
      if (expectedGeneration != null &&
          expectedGeneration != _sessionGeneration) {
        return;
      }

      final access = _nestedToken(tokens['access']);
      final refresh = _nestedToken(tokens['refresh']);

      if (access == null ||
          access.isEmpty ||
          refresh == null ||
          refresh.isEmpty) {
        throw StateError('استجابة التوكنات ناقصة من الخادم.');
      }

      await _storage.write(
        key: _accessKey,
        value: access,
      );

      await _storage.write(
        key: _refreshKey,
        value: refresh,
      );
    });
  }

  String? _nestedToken(dynamic value) {
    if (value is Map) {
      final token = value['token'];
      return token?.toString();
    }

    return null;
  }

  Future<String?> get refreshToken => _storage.read(key: _refreshKey);

  Future<bool> hasToken() async {
    final access = await _storage.read(key: _accessKey);
    final refresh = await _storage.read(key: _refreshKey);

    return access != null &&
        access.isNotEmpty &&
        refresh != null &&
        refresh.isNotEmpty;
  }

  Future<void> saveUserJson(String json) =>
      _storage.write(key: _userKey, value: json);

  Future<String?> readUserJson() => _storage.read(key: _userKey);

  Future<void> clearTokens() {
    return _serializeStorage(() async {
      Object? firstError;
      StackTrace? firstStack;

      for (final key in [_accessKey, _refreshKey, _userKey]) {
        try {
          await _storage.delete(key: key);
        } catch (error, stack) {
          firstError ??= error;
          firstStack ??= stack;
        }
      }

      if (firstError != null) {
        Error.throwWithStackTrace(firstError, firstStack!);
      }
    });
  }

  Future<bool> _refreshOnce(int generation, String? sentToken) {
    if (_refreshing != null && _refreshGeneration == generation) {
      return _refreshing!;
    }

    _refreshGeneration = generation;
    late final Future<bool> future;
    future = _refresh(generation, sentToken).whenComplete(() {
      if (identical(_refreshing, future)) {
        _refreshing = null;
        _refreshGeneration = null;
      }
    });
    _refreshing = future;
    return future;
  }

  Future<bool> _refresh(int generation, String? sentToken) async {
    try {
      final currentAccess = await _storage.read(key: _accessKey);

      if (generation != _sessionGeneration || _sessionBlocked) {
        return false;
      }

      // طلب آخر سبق وجدد التوكن؛ لا نستخدم Refresh Token مرة ثانية.
      if (currentAccess != null &&
          sentToken != null &&
          sentToken != 'Bearer $currentAccess') {
        return true;
      }

      final refresh = await _storage.read(key: _refreshKey);
      if (refresh == null || refresh.isEmpty) {
        return false;
      }

      // Dio مستقل لتجنب دخول طلب التجديد في interceptor نفسه.
      final refreshDio = Dio(
        BaseOptions(
          baseUrl: baseUrl,
          connectTimeout: const Duration(seconds: 15),
          receiveTimeout: const Duration(seconds: 20),
          headers: {'Content-Type': 'application/json'},
        ),
      );

      final response = await refreshDio.post(
        '/auth/refresh-tokens',
        data: {'refreshToken': refresh},
      );

      if (generation != _sessionGeneration || _sessionBlocked) {
        return false;
      }

      if (response.data is! Map) {
        throw DioException(
          requestOptions: response.requestOptions,
          response: response,
          type: DioExceptionType.badResponse,
          error: 'Invalid token refresh response',
        );
      }

      final tokens = Map<String, dynamic>.from(response.data as Map);
      final access = _nestedToken(tokens['access']);
      final nextRefresh = _nestedToken(tokens['refresh']);

      if (access == null ||
          access.isEmpty ||
          nextRefresh == null ||
          nextRefresh.isEmpty) {
        throw DioException(
          requestOptions: response.requestOptions,
          response: response,
          type: DioExceptionType.badResponse,
          error: 'Invalid token refresh response',
        );
      }

      await saveTokens(tokens, expectedGeneration: generation);
      return generation == _sessionGeneration && !_sessionBlocked;
    } on DioException catch (error) {
      final status = error.response?.statusCode;

      // 401/403 من endpoint التجديد يعنيان أن Refresh Token غير صالح.
      if (status == 401 || status == 403) {
        return false;
      }

      // أخطاء الشبكة والخادم لا تعني انتهاء الجلسة؛ دع الواجهة تعرض الخطأ.
      rethrow;
    }
  }

  // ---------------- معالجة الأخطاء ----------------

  /// يلف أي طلب ويحوّل أخطاء Dio إلى [ApiException] مفهومة.
  static Future<T> guard<T>(Future<T> Function() fn) async {
    try {
      return await fn();
    } on DioException catch (error) {
      throw _toException(error);
    }
  }

  static ApiException _toException(DioException error) {
    final status = error.response?.statusCode;
    final data = error.response?.data;

    if (data is Map && data['message'] != null) {
      return ApiException(
        data['message'].toString(),
        statusCode: status,
      );
    }

    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
      case DioExceptionType.connectionError:
        return ApiException(
          'تعذّر الاتصال بالخادم، تحقق من الشبكة وعنوان الخادم',
          statusCode: status,
        );
      default:
        return ApiException(
          'حدث خطأ غير متوقع',
          statusCode: status,
        );
    }
  }
}
