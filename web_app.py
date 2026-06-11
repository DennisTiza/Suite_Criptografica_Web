#!/usr/bin/env python3
"""
Suite Criptográfica - Web Server (Flask)
Servidor REST que expone la lógica del backend como API para el frontend web.
"""

import sys
import os
import socket
# pyrefly: ignore [missing-import]
from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS

# Agregar directorio al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.message_digest_logic import MessageDigestLogic
from backend.digital_signature_logic import DigitalSignatureLogic
from backend.encryption_logic import EncryptionLogic
from backend.elliptic_curves_logic import EllipticCurvesLogic
from backend.sql_injection_logic import SqlInjectionLogic

app = Flask(__name__,
            template_folder='web/templates',
            static_folder='web/static')
app.secret_key = 'crypto_suite_secret_key_2026'
CORS(app)

# ============================================================
# Instancias de lógica (una por "sesión" simplificado)
# Para un lab, se usa estado global por proceso (una persona a la vez)
# ============================================================
_digest_logic = MessageDigestLogic()
_signature_logic = DigitalSignatureLogic()
_encryption_logic = EncryptionLogic()
_curves_logic = EllipticCurvesLogic()
_sqli_logic = SqlInjectionLogic()


# ============================================================
# FRONTEND
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')


# ============================================================
# MESSAGE DIGEST — /api/digest/*
# ============================================================
@app.route('/api/digest/generate', methods=['POST'])
def digest_generate():
    data = request.get_json()
    try:
        result = _digest_logic.generate_digest(
            data.get('message', ''),
            data.get('algorithm', 'sha256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/digest/hmac', methods=['POST'])
def digest_hmac():
    data = request.get_json()
    try:
        result = _digest_logic.generate_hmac(
            data.get('message', ''),
            data.get('key', ''),
            data.get('algorithm', 'sha256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/digest/avalanche', methods=['POST'])
def digest_avalanche():
    data = request.get_json()
    try:
        result = _digest_logic.analyze_avalanche_effect(
            data.get('message', ''),
            data.get('algorithm', 'sha256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/digest/compare', methods=['POST'])
def digest_compare():
    data = request.get_json()
    try:
        result = _digest_logic.compare_messages(
            data.get('message1', ''),
            data.get('message2', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# FIRMA DIGITAL — /api/signature/*
# ============================================================
@app.route('/api/signature/generate-keys', methods=['POST'])
def signature_generate_keys():
    data = request.get_json()
    try:
        result = _signature_logic.generate_keypair(int(data.get('key_size', 2048)))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/load-private-key', methods=['POST'])
def signature_load_private_key():
    data = request.get_json()
    try:
        pem = data.get('pem', '').encode('utf-8')
        result = _signature_logic.load_private_key_from_pem(pem)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/signature/load-public-key', methods=['POST'])
def signature_load_public_key():
    data = request.get_json()
    try:
        pem = data.get('pem', '').encode('utf-8')
        result = _signature_logic.load_public_key_from_pem(pem)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/signature/sign', methods=['POST'])
def signature_sign():
    data = request.get_json()
    try:
        result = _signature_logic.sign_message(
            data.get('message', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/verify', methods=['POST'])
def signature_verify():
    data = request.get_json()
    try:
        result = _signature_logic.verify_signature(
            data.get('message', ''),
            data.get('signature_base64', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/sign-textbook', methods=['POST'])
def signature_sign_textbook():
    data = request.get_json()
    try:
        result = _signature_logic.sign_message_textbook(
            data.get('message', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/verify-textbook', methods=['POST'])
def signature_verify_textbook():
    data = request.get_json()
    try:
        result = _signature_logic.verify_signature_textbook(
            data.get('message', ''),
            data.get('signature_base64', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/generate-cert', methods=['POST'])
def signature_generate_cert():
    data = request.get_json()
    try:
        result = _signature_logic.generate_certificate(
            common_name=data.get('common_name', ''),
            organization=data.get('organization', ''),
            organizational_unit=data.get('organizational_unit', ''),
            locality=data.get('locality', ''),
            state=data.get('state', ''),
            country=data.get('country', ''),
            validity_days=int(data.get('validity_days', 365))
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/signature/key-status', methods=['GET'])
def signature_key_status():
    return jsonify({
        'has_private_key': _signature_logic.has_private_key(),
        'has_public_key': _signature_logic.has_public_key(),
        'has_certificate': _signature_logic.has_certificate()
    })


# ============================================================
# CIFRADO RSA — /api/encryption/*
# ============================================================
@app.route('/api/encryption/generate-keys', methods=['POST'])
def encryption_generate_keys():
    data = request.get_json()
    try:
        result = _encryption_logic.generate_keypair(int(data.get('key_size', 2048)))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/load-private-key', methods=['POST'])
def encryption_load_private_key():
    data = request.get_json()
    try:
        pem = data.get('pem', '').encode('utf-8')
        result = _encryption_logic.load_private_key_from_pem(pem)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/load-public-key', methods=['POST'])
def encryption_load_public_key():
    data = request.get_json()
    try:
        pem = data.get('pem', '').encode('utf-8')
        result = _encryption_logic.load_public_key_from_pem(pem)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/encrypt-public', methods=['POST'])
def encryption_encrypt_public():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_with_public_key(data.get('message', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/decrypt-private', methods=['POST'])
def encryption_decrypt_private():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_with_private_key(data.get('ciphertext_base64', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/encrypt-private', methods=['POST'])
def encryption_encrypt_private():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_with_private_key(
            data.get('message', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/decrypt-public', methods=['POST'])
def encryption_decrypt_public():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_with_public_key(
            data.get('ciphertext_base64', ''),
            data.get('original_message', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/des-ecb-encrypt', methods=['POST'])
def encryption_des_ecb_encrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_des_ecb(data.get('plaintext', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/des-ecb-decrypt', methods=['POST'])
def encryption_des_ecb_decrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_des_ecb(data.get('ciphertext_base64', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/des-cfb-encrypt', methods=['POST'])
def encryption_des_cfb_encrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_des_cfb(data.get('plaintext', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/des-cfb-decrypt', methods=['POST'])
def encryption_des_cfb_decrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_des_cfb(
            data.get('ciphertext_base64', ''),
            data.get('key', ''),
            data.get('iv_base64', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/aes-cbc-encrypt', methods=['POST'])
def encryption_aes_cbc_encrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_aes_cbc(data.get('plaintext', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/aes-cbc-decrypt', methods=['POST'])
def encryption_aes_cbc_decrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_aes_cbc(
            data.get('ciphertext_base64', ''),
            data.get('key', ''),
            data.get('iv_base64', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/arc4-encrypt', methods=['POST'])
def encryption_arc4_encrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_arc4(data.get('plaintext', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/arc4-decrypt', methods=['POST'])
def encryption_arc4_decrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_arc4(data.get('ciphertext_base64', ''), data.get('key', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/encryption/hybrid-encrypt', methods=['POST'])
def encryption_hybrid_encrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.encrypt_hybrid(data.get('plaintext', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/hybrid-decrypt', methods=['POST'])
def encryption_hybrid_decrypt():
    data = request.get_json()
    try:
        result = _encryption_logic.decrypt_hybrid(
            data.get('encrypted_session_key_b64', ''),
            data.get('ciphertext_b64', ''),
            data.get('nonce_b64', ''),
            data.get('tag_b64', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/encryption/key-status', methods=['GET'])
def encryption_key_status():
    return jsonify({
        'has_private_key': _encryption_logic.has_private_key(),
        'has_public_key': _encryption_logic.has_public_key()
    })


# ============================================================
# CURVAS ELÍPTICAS — /api/curves/*
# ============================================================
@app.route('/api/curves/generate-ecdsa', methods=['POST'])
def curves_generate_ecdsa():
    data = request.get_json()
    try:
        result = _curves_logic.generate_ecdsa_keypair(data.get('curve', 'secp256k1'))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/load-ecdsa-private', methods=['POST'])
def curves_load_ecdsa_private():
    data = request.get_json()
    try:
        pem = data.get('pem', '').encode('utf-8')
        result = _curves_logic.load_ecdsa_private_key_from_pem(pem)
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/curves/sign-ecdsa', methods=['POST'])
def curves_sign_ecdsa():
    data = request.get_json()
    try:
        result = _curves_logic.sign_message_ecdsa(
            data.get('message', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/verify-ecdsa', methods=['POST'])
def curves_verify_ecdsa():
    data = request.get_json()
    try:
        result = _curves_logic.verify_signature_ecdsa(
            data.get('message', ''),
            data.get('signature_base64', ''),
            data.get('hash_algorithm', 'SHA256')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/generate-ed25519', methods=['POST'])
def curves_generate_ed25519():
    try:
        result = _curves_logic.generate_ed25519_keypair()
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/sign-ed25519', methods=['POST'])
def curves_sign_ed25519():
    data = request.get_json()
    try:
        result = _curves_logic.sign_message_ed25519(data.get('message', ''))
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/verify-ed25519', methods=['POST'])
def curves_verify_ed25519():
    data = request.get_json()
    try:
        result = _curves_logic.verify_signature_ed25519(
            data.get('message', ''),
            data.get('signature_hex', '')
        )
        return jsonify({'success': True, 'data': result})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/curves/key-status', methods=['GET'])
def curves_key_status():
    return jsonify(_curves_logic.get_key_info())


# ============================================================
# SQL INJECTION — /api/sqli/*
# ============================================================
@app.route('/api/sqli/login-vulnerable', methods=['POST'])
def sqli_login_vulnerable():
    data = request.get_json()
    # Capturar la IP real del cliente que origina la petición
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip_address = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr
    try:
        result = _sqli_logic.login_vulnerable(
            data.get('username', ''),
            data.get('password', ''),
            ip_address
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sqli/login-secure', methods=['POST'])
def sqli_login_secure():
    data = request.get_json()
    # Capturar la IP real del cliente que origina la petición
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    ip_address = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr
    try:
        result = _sqli_logic.login_secure(
            data.get('username', ''),
            data.get('password', ''),
            ip_address
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sqli/monitor', methods=['GET'])
def sqli_monitor():
    try:
        logs = _sqli_logic.get_monitor_logs()
        return jsonify({'success': True, 'data': logs})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    # Obtener IP local
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print("=" * 60)
    print("Suite Criptografica - Servidor Web")
    print("=" * 60)
    print("Accede localmente en: http://localhost:5000")
    print(f"Accede desde la red en: http://{local_ip}:5000")
    print("Presiona Ctrl+C para detener")
    print("=" * 60)
    app.run(host='0.0.0.0', debug=True, port=5000)
