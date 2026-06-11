#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
BACKEND: Digital Signature Logic (Punto 1b)

Lógica de negocio para firma digital RSA.
Sin dependencias de UI - solo operaciones criptográficas.
"""

import base64
import datetime
import hashlib
from typing import Dict, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


class DigitalSignatureLogic:
    """Clase con la lógica pura de operaciones de firma digital RSA"""
    
    # Tamaños de clave soportados
    SUPPORTED_KEY_SIZES = [1024, 2048, 4096]
    
    # Algoritmos hash soportados
    SUPPORTED_HASH_ALGORITHMS = {
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384(),
        'SHA512': hashes.SHA512()
    }
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None
    
    # ==================== GESTIÓN DE CLAVES ====================
    
    def generate_keypair(self, key_size: int = 2048) -> Dict[str, str]:
        """
        Generar par de claves RSA.
        
        Args:
            key_size: Tamaño de la clave en bits (1024, 2048, 4096)
            
        Returns:
            Dict con claves en formato PEM: {
                'private_key_pem': str,
                'public_key_pem': str,
                'key_size': int
            }
            
        Raises:
            ValueError: Si el tamaño de clave no es soportado
        """
        if key_size not in self.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Tamaño de clave no soportado: {key_size}. Use {self.SUPPORTED_KEY_SIZES}")
        
        # Generar clave privada
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Obtener clave pública
        self.public_key = self.private_key.public_key()
        
        # Serializar a PEM
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return {
            'private_key_pem': private_pem,
            'public_key_pem': public_pem,
            'key_size': key_size
        }
    
    def load_private_key_from_pem(self, pem_data: bytes) -> Dict[str, any]:
        """
        Cargar clave privada desde datos PEM.
        
        Args:
            pem_data: Datos PEM de la clave privada
            
        Returns:
            Dict con información: {'success': bool, 'key_size': int}
            
        Raises:
            ValueError: Si los datos no son válidos
        """
        try:
            self.private_key = serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            return {
                'success': True,
                'key_size': self.private_key.key_size
            }
        except Exception as e:
            raise ValueError(f"Error al cargar clave privada: {str(e)}")
    
    def load_public_key_from_pem(self, pem_data: bytes) -> Dict[str, any]:
        """
        Cargar clave pública desde datos PEM.
        
        Args:
            pem_data: Datos PEM de la clave pública
            
        Returns:
            Dict con información: {'success': bool, 'key_size': int}
            
        Raises:
            ValueError: Si los datos no son válidos
        """
        try:
            self.public_key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )
            
            return {
                'success': True,
                'key_size': self.public_key.key_size
            }
        except Exception as e:
            raise ValueError(f"Error al cargar clave pública: {str(e)}")
    
    # ==================== FIRMA DIGITAL ====================
    
    def sign_message(self, message: str, hash_algorithm: str = 'SHA256') -> Dict[str, str]:
        """
        Firmar un mensaje usando la clave privada.
        
        Args:
            message: Mensaje a firmar
            hash_algorithm: Algoritmo hash ('SHA256', 'SHA384', 'SHA512')
            
        Returns:
            Dict con firma: {
                'signature_base64': str,
                'signature_hex': str,
                'hash_algorithm': str,
                'message_length': int
            }
            
        Raises:
            ValueError: Si no hay clave privada o algoritmo inválido
        """
        if not self.private_key:
            raise ValueError("No hay clave privada cargada")
        
        if not message:
            raise ValueError("El mensaje no puede estar vacío")
        
        if hash_algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        hash_func = self.SUPPORTED_HASH_ALGORITHMS[hash_algorithm]
        
        # Firmar mensaje con PSS padding
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hash_func),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_func
        )
        
        return {
            'signature_base64': base64.b64encode(signature).decode('utf-8'),
            'signature_hex': signature.hex(),
            'hash_algorithm': hash_algorithm,
            'message_length': len(message)
        }
    
    def sign_message_textbook(self, message: str, hash_algorithm: str = 'SHA256') -> Dict[str, str]:
        """
        Firmar usando RSA textbook (matemática pura) para fines educativos.
        
        ⚠️ SOLO USO EDUCATIVO ⚠️
        Implementa RSA sin padding para demostrar la matemática subyacente.
        
        Vulnerabilidades:
        - Sin padding: vulnerable a ataques
        - Determinístico
        - No cumple estándares modernos
        
        Args:
            message: Mensaje a firmar
            hash_algorithm: Algoritmo hash ('SHA256', 'SHA384', 'SHA512')
            
        Returns:
            Dict con firma: {
                'signature_base64': str,
                'signature_hex': str,
                'signature_int': str (número entero como string),
                'hash_int': str (hash como número entero),
                'hash_algorithm': str,
                'message_length': int,
                'warning': str
            }
            
        Raises:
            ValueError: Si no hay clave privada o algoritmo inválido
        """
        if not self.private_key:
            raise ValueError("No hay clave privada cargada")
        
        if not message:
            raise ValueError("El mensaje no puede estar vacío")
        
        if hash_algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        # Seleccionar función hash según algoritmo
        if hash_algorithm == 'SHA256':
            import hashlib
            hash_digest = hashlib.sha256(message.encode('utf-8')).digest()
        elif hash_algorithm == 'SHA384':
            import hashlib
            hash_digest = hashlib.sha384(message.encode('utf-8')).digest()
        else:  # SHA512
            import hashlib
            hash_digest = hashlib.sha512(message.encode('utf-8')).digest()
        
        # Convertir hash a entero
        hash_int = int.from_bytes(hash_digest, byteorder='big')
        
        # Obtener parámetros RSA de la clave privada
        private_numbers = self.private_key.private_numbers()
        d = private_numbers.d  # Exponente privado
        n = private_numbers.public_numbers.n  # Módulo
        
        # RSA textbook: signature = pow(hash, d, n)
        signature_int = pow(hash_int, d, n)
        
        # Convertir a bytes para base64 y hex
        # Calcular tamaño en bytes del módulo
        n_bytes = (n.bit_length() + 7) // 8
        signature_bytes = signature_int.to_bytes(n_bytes, byteorder='big')
        
        return {
            'signature_base64': base64.b64encode(signature_bytes).decode('utf-8'),
            'signature_hex': signature_bytes.hex(),
            'signature_int': str(signature_int),
            'hash_int': str(hash_int),
            'hash_algorithm': hash_algorithm,
            'message_length': len(message),
            'warning': 'RSA TEXTBOOK - SOLO PARA DEMOSTRACIÓN EDUCATIVA'
        }
    
    def verify_signature(self, message: str, signature_base64: str) -> Dict[str, any]:
        """
        Verificar una firma digital.
        
        Args:
            message: Mensaje original
            signature_base64: Firma en formato base64
            
        Returns:
            Dict con resultado: {
                'valid': bool,
                'hash_algorithm_used': str (si es válida),
                'message': str
            }
            
        Raises:
            ValueError: Si no hay clave pública o datos inválidos
        """
        if not self.public_key:
            raise ValueError("No hay clave pública cargada")
        
        if not message or not signature_base64:
            raise ValueError("El mensaje y la firma no pueden estar vacíos")
        
        try:
            signature = base64.b64decode(signature_base64)
        except Exception:
            raise ValueError("La firma no está en formato base64 válido")
        
        # Intentar verificar con cada algoritmo hash
        for hash_name, hash_func in self.SUPPORTED_HASH_ALGORITHMS.items():
            try:
                self.public_key.verify(
                    signature,
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hash_func),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_func
                )
                return {
                    'valid': True,
                    'hash_algorithm_used': hash_name,
                    'message': 'Firma válida'
                }
            except Exception:
                continue
        
        return {
            'valid': False,
            'message': 'Firma inválida o mensaje alterado'
        }
    
    def verify_signature_textbook(self, message: str, signature_base64: str, hash_algorithm: str = 'SHA256') -> Dict[str, any]:
        """
        Verificar firma RSA textbook.
        
        ⚠️ SOLO USO EDUCATIVO ⚠️
        
        Args:
            message: Mensaje original
            signature_base64: Firma en formato base64
            hash_algorithm: Algoritmo hash usado para firmar
            
        Returns:
            Dict con resultado: {
                'valid': bool,
                'hash_original': str (hash del mensaje como entero),
                'hash_from_signature': str (hash recuperado de la firma),
                'hash_algorithm': str,
                'message': str,
                'warning': str
            }
            
        Raises:
            ValueError: Si no hay clave pública o datos inválidos
        """
        if not self.public_key:
            raise ValueError("No hay clave pública cargada")
        
        if not message or not signature_base64:
            raise ValueError("El mensaje y la firma no pueden estar vacíos")
        
        if hash_algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        try:
            signature_bytes = base64.b64decode(signature_base64)
        except Exception:
            raise ValueError("La firma no está en formato base64 válido")
        
        # Calcular hash del mensaje original
        if hash_algorithm == 'SHA256':
            import hashlib
            hash_digest = hashlib.sha256(message.encode('utf-8')).digest()
        elif hash_algorithm == 'SHA384':
            import hashlib
            hash_digest = hashlib.sha384(message.encode('utf-8')).digest()
        else:  # SHA512
            import hashlib
            hash_digest = hashlib.sha512(message.encode('utf-8')).digest()
        
        hash_original = int.from_bytes(hash_digest, byteorder='big')
        
        # Convertir firma a entero
        signature_int = int.from_bytes(signature_bytes, byteorder='big')
        
        # Obtener parámetros RSA de la clave pública
        public_numbers = self.public_key.public_numbers()
        e = public_numbers.e  # Exponente público
        n = public_numbers.n  # Módulo
        
        # RSA textbook: hashFromSignature = pow(signature, e, n)
        try:
            hash_from_signature = pow(signature_int, e, n)
        except Exception as ex:
            return {
                'valid': False,
                'hash_original': str(hash_original),
                'hash_from_signature': 'Error al descifrar',
                'hash_algorithm': hash_algorithm,
                'message': f'Error en la verificación: {str(ex)}',
                'warning': '⚠️ RSA TEXTBOOK - SOLO PARA DEMOSTRACIÓN EDUCATIVA'
            }
        
        # Verificar si los hashes coinciden
        valid = (hash_original == hash_from_signature)
        
        return {
            'valid': valid,
            'hash_original': str(hash_original),
            'hash_from_signature': str(hash_from_signature),
            'hash_algorithm': hash_algorithm,
            'message': 'Firma válida ✓' if valid else 'Firma inválida o mensaje alterado ✗',
            'warning': '⚠️ RSA TEXTBOOK - SOLO PARA DEMOSTRACIÓN EDUCATIVA'
        }
    
    # ==================== CERTIFICADOS X.509 ====================
    
    def generate_certificate(self, 
                            common_name: str,
                            organization: str = '',
                            organizational_unit: str = '',
                            locality: str = '',
                            state: str = '',
                            country: str = '',
                            validity_days: int = 365) -> Dict[str, any]:
        """
        Generar certificado X.509 auto-firmado.
        
        Args:
            common_name: Nombre completo (CN)
            organization: Organización (O)
            organizational_unit: Unidad organizacional (OU)
            locality: Ciudad (L)
            state: Estado/Provincia (ST)
            country: País (C) - 2 letras
            validity_days: Días de validez (1-3650)
            
        Returns:
            Dict con certificado: {
                'certificate_pem': str,
                'serial_number': str,
                'not_valid_before': str,
                'not_valid_after': str
            }
            
        Raises:
            ValueError: Si faltan datos o son inválidos
        """
        if not self.private_key:
            raise ValueError("No hay clave privada cargada")
        
        if not common_name:
            raise ValueError("El nombre completo (CN) es obligatorio")
        
        if country and len(country) != 2:
            raise ValueError("El código de país debe tener 2 letras")
        
        if validity_days < 1 or validity_days > 3650:
            raise ValueError("La validez debe estar entre 1 y 3650 días")
        
        # Crear subject
        subject_components = []
        if country:
            subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
        if state:
            subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
        subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        
        subject = issuer = x509.Name(subject_components)
        
        # Fechas de validez
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=validity_days)
        
        # Construir certificado
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(self.public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(not_valid_before)
        cert_builder = cert_builder.not_valid_after(not_valid_after)
        
        # Agregar extensiones
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.public_key),
            critical=False
        )
        
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Firmar certificado
        self.certificate = cert_builder.sign(self.private_key, hashes.SHA256(), default_backend())
        
        # Serializar a PEM
        cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return {
            'certificate_pem': cert_pem,
            'serial_number': hex(self.certificate.serial_number),
            'not_valid_before': not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'not_valid_after': not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
        }
    
    def load_certificate_from_pem(self, pem_data: bytes) -> Dict[str, any]:
        """
        Cargar certificado desde datos PEM.
        
        Args:
            pem_data: Datos PEM del certificado
            
        Returns:
            Dict con información del certificado
            
        Raises:
            ValueError: Si los datos no son válidos
        """
        try:
            self.certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
            self.public_key = self.certificate.public_key()
            
            return {
                'success': True,
                'subject': self.certificate.subject.rfc4514_string(),
                'serial_number': hex(self.certificate.serial_number)
            }
        except Exception as e:
            raise ValueError(f"Error al cargar certificado: {str(e)}")
    
    def get_certificate_details(self) -> Dict[str, any]:
        """
        Obtener detalles completos del certificado cargado.
        
        Returns:
            Dict con toda la información del certificado
            
        Raises:
            ValueError: Si no hay certificado cargado
        """
        if not self.certificate:
            raise ValueError("No hay certificado cargado")
        
        # Información básica
        subject_info = {}
        for attr in self.certificate.subject:
            subject_info[attr.oid._name] = attr.value
        
        issuer_info = {}
        for attr in self.certificate.issuer:
            issuer_info[attr.oid._name] = attr.value
        
        # Estado de validez
        now = datetime.datetime.utcnow()
        if now < self.certificate.not_valid_before:
            status = "not_yet_valid"
        elif now > self.certificate.not_valid_after:
            status = "expired"
        else:
            status = "valid"
        
        # Fingerprints
        cert_der = self.certificate.public_bytes(serialization.Encoding.DER)
        md5_hash = hashlib.md5(cert_der).hexdigest()
        sha1_hash = hashlib.sha1(cert_der).hexdigest()
        sha256_hash = hashlib.sha256(cert_der).hexdigest()
        
        # Información de la clave pública
        public_key = self.certificate.public_key()
        key_info = {}
        if isinstance(public_key, rsa.RSAPublicKey):
            key_info = {
                'type': 'RSA',
                'size': public_key.key_size,
                'exponent': public_key.public_numbers().e
            }
        
        # Extensiones
        extensions_info = []
        for ext in self.certificate.extensions:
            extensions_info.append({
                'name': ext.oid._name,
                'critical': ext.critical,
                'value': str(ext.value)
            })
        
        return {
            'subject': subject_info,
            'issuer': issuer_info,
            'serial_number': hex(self.certificate.serial_number),
            'not_valid_before': self.certificate.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'not_valid_after': self.certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'status': status,
            'signature_algorithm': self.certificate.signature_algorithm_oid._name,
            'fingerprints': {
                'md5': ':'.join([md5_hash[i:i+2] for i in range(0, len(md5_hash), 2)]).upper(),
                'sha1': ':'.join([sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2)]).upper(),
                'sha256': ':'.join([sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2)]).upper()
            },
            'public_key': key_info,
            'extensions': extensions_info
        }
    
    def export_certificate_pem(self) -> str:
        """
        Exportar certificado en formato PEM.
        
        Returns:
            Certificado en formato PEM
            
        Raises:
            ValueError: Si no hay certificado cargado
        """
        if not self.certificate:
            raise ValueError("No hay certificado cargado")
        
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # ==================== UTILIDADES ====================
    
    def has_private_key(self) -> bool:
        """Verificar si hay una clave privada cargada"""
        return self.private_key is not None
    
    def has_public_key(self) -> bool:
        """Verificar si hay una clave pública cargada"""
        return self.public_key is not None
    
    def has_certificate(self) -> bool:
        """Verificar si hay un certificado cargado"""
        return self.certificate is not None
    
    def clear_keys(self):
        """Limpiar todas las claves y certificados cargados"""
        self.private_key = None
        self.public_key = None
        self.certificate = None
