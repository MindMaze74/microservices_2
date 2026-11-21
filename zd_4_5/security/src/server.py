from os import getenv
from flask import Flask, request, make_response, jsonify
from prometheus_flask_exporter import PrometheusMetrics, NO_PREFIX
from passlib.hash import pbkdf2_sha256
import jwt

server = Flask(__name__)
metrics = PrometheusMetrics(
    server,
    defaults_prefix=NO_PREFIX,
    buckets=[0.1, 0.5, 1, 1.5, 2],
    default_labels={"app_name": "security"},
)
metrics.info('app_info', 'Application info', version='1.0')

jwt_key = 'secret'

# Хранилище пользователей: login -> hash пароля
users = {
    'bob': pbkdf2_sha256.hash('qwe123'),
}


@server.route('/status', methods=['GET'])
def status():
    return {'status': 'OK'}


@server.route('/v1/user', methods=['POST'])
def register():
    if not request.json or 'login' not in request.json or 'password' not in request.json:
        return make_response(jsonify({'error': 'Bad request'})), 400

    login = request.json['login']
    password = request.json['password']

    if login in users:
        return make_response(jsonify({'error': 'User already exists'})), 409

    users[login] = pbkdf2_sha256.hash(password)
    return make_response(jsonify({'login': login})), 201


@server.route('/v1/user', methods=['GET'])
def get_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return make_response(jsonify({'error': 'Missing Authorization header'})), 401

    try:
        auth_schema, auth_token = auth_header.split(' ')
    except ValueError:
        return make_response(jsonify({'error': 'Invalid Authorization header'})), 401

    if auth_schema != 'Bearer' or not auth_token:
        return make_response(jsonify({'error': 'Invalid Authorization header'})), 401

    try:
        payload = jwt.decode(auth_token, jwt_key, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return make_response(jsonify({'error': 'Invalid token'})), 401

    login = payload.get('sub')
    if login not in users:
        return make_response(jsonify({'error': 'User not found'})), 404

    return make_response(jsonify({'login': login})), 200


@server.route('/v1/token', methods=['POST'])
def login():
    if not request.json or 'login' not in request.json or 'password' not in request.json:
        return make_response(jsonify({'error': 'Bad request'})), 400

    login = request.json['login']
    password = request.json['password']

    if login not in users:
        return make_response(jsonify({'error': 'Unknown login or password'})), 401

    if not pbkdf2_sha256.verify(password, users[login]):
        return make_response(jsonify({'error': 'Unknown login or password'})), 401

    token = jwt.encode({'sub': login}, jwt_key, algorithm='HS256')
    return make_response(jsonify({'token': token})), 200


@server.route('/v1/token/validation', methods=['GET'])
def validate():
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return make_response(jsonify({'error': 'Missing Authorization header'})), 401

    try:
        auth_schema, auth_token = auth_header.split(' ')
    except ValueError:
        return make_response(jsonify({'error': 'Invalid Authorization header'})), 401

    if auth_schema != 'Bearer' or not auth_token:
        return make_response(jsonify({'error': 'Invalid Authorization header'})), 401

    try:
        payload = jwt.decode(auth_token, jwt_key, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return make_response(jsonify({'error': 'Signature expired'})), 401
    except jwt.InvalidTokenError:
        return make_response(jsonify({'error': 'Invalid token'})), 401

    return make_response(jsonify(payload)), 200


if __name__ == '__main__':
    port = int(getenv('PORT') or '8080')
    server.run(host='0.0.0.0', port=port)