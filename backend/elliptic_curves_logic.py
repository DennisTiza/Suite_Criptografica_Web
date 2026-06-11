#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
Backend: Elliptic Curves Logic (Punto 1e)

Lógica pura de firma digital con curvas elípticas sin dependencias de UI.
Implementa ECDSA (secp256k1, secp384r1, secp521r1) y Ed25519.
"""

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
from typing import Dict, Tuple


class EllipticCurvesLogic:
    """
    Lógica de firma digital con Curvas Elípticas.
    
    Soporta:
    - ECDSA: secp256k1 (Bitcoin), secp384r1 (NIST P-384), secp521r1 (NIST P-521)
    - Ed25519: Firma rápida y moderna (EdDSA)
    """
    
    # Curvas soportadas para ECDSA
    SUPPORTED_CURVES = {
        'secp256k1': ec.SECP256K1(),      # Bitcoin, Ethereum
        'secp384r1': ec.SECP384R1(),      # NIST P-384
        'secp521r1': ec.SECP521R1()       # NIST P-521
    }
    
    # Algoritmos hash soportados para ECDSA
    SUPPORTED_HASH_ALGORITHMS = {
        'SHA256': hashes.SHA256(),
        'SHA384': hashes.SHA384(),
        'SHA512': hashes.SHA512()
    }
    
    def __init__(self):
        """Inicializar con claves vacías"""
        # ECDSA
        self.ecdsa_private_key = None
        self.ecdsa_public_key = None
        self.current_curve = None
        
        # Ed25519
        self.ed25519_private_key = None
        self.ed25519_public_key = None
    
    # ==================== ECDSA (CURVAS SECP) ====================
    
    def generate_ecdsa_keypair(self, curve_name: str = 'secp256k1') -> Dict:
        """
        Generar par de claves ECDSA.
        
        Args:
            curve_name: Nombre de la curva (secp256k1, secp384r1, secp521r1)
            
        Returns:
            Dict con:
                - private_key_pem: Clave privada en formato PEM
                - public_key_pem: Clave pública en formato PEM
                - curve: Nombre de la curva
                - key_size: Tamaño en bits
                
        Raises:
            ValueError: Si la curva no es soportada
        """
        if curve_name not in self.SUPPORTED_CURVES:
            raise ValueError(f"Curva no soportada: {curve_name}. Use: {list(self.SUPPORTED_CURVES.keys())}")
        
        try:
            curve = self.SUPPORTED_CURVES[curve_name]
            self.current_curve = curve_name
            
            # Generar clave privada
            self.ecdsa_private_key = ec.generate_private_key(curve, default_backend())
            
            # Obtener clave pública
            self.ecdsa_public_key = self.ecdsa_private_key.public_key()
            
            # Serializar a PEM
            private_pem = self.ecdsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            public_pem = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            return {
                'private_key_pem': private_pem,
                'public_key_pem': public_pem,
                'curve': curve_name,
                'key_size': curve.key_size,
                'message': f'Par de claves ECDSA generado correctamente ({curve_name})'
            }
            
        except Exception as e:
            raise ValueError(f"Error al generar claves ECDSA: {str(e)}")
    
    def load_ecdsa_private_key_from_pem(self, pem_data: bytes) -> Dict:
        """
        Cargar clave privada ECDSA desde formato PEM.
        
        Args:
            pem_data: Datos de la clave en formato PEM (bytes)
            
        Returns:
            Dict con información de la clave
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            self.ecdsa_private_key = serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
            
            # Extraer clave pública
            self.ecdsa_public_key = self.ecdsa_private_key.public_key()
            
            # Detectar curva
            curve = self.ecdsa_private_key.curve
            for name, c in self.SUPPORTED_CURVES.items():
                if curve.name == c.name:
                    self.current_curve = name
                    break
            
            return {
                'curve': self.current_curve,
                'key_size': curve.key_size,
                'message': f'Clave privada ECDSA cargada ({self.current_curve})'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave privada ECDSA: {str(e)}")
    
    def load_ecdsa_public_key_from_pem(self, pem_data: bytes) -> Dict:
        """
        Cargar clave pública ECDSA desde formato PEM.
        
        Args:
            pem_data: Datos de la clave en formato PEM (bytes)
            
        Returns:
            Dict con información de la clave
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            self.ecdsa_public_key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )
            
            # Detectar curva
            curve = self.ecdsa_public_key.curve
            for name, c in self.SUPPORTED_CURVES.items():
                if curve.name == c.name:
                    self.current_curve = name
                    break
            
            return {
                'curve': self.current_curve,
                'key_size': curve.key_size,
                'message': f'Clave pública ECDSA cargada ({self.current_curve})'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave pública ECDSA: {str(e)}")
    
    def sign_message_ecdsa(self, message: str, hash_algorithm: str = 'SHA256') -> Dict:
        """
        Firmar un mensaje usando ECDSA.
        
        Args:
            message: Mensaje a firmar
            hash_algorithm: Algoritmo hash (SHA256, SHA384, SHA512)
            
        Returns:
            Dict con:
                - signature_base64: Firma en base64
                - signature_hex: Firma en hexadecimal
                - curve: Curva utilizada
                - hash_algorithm: Algoritmo hash usado
                
        Raises:
            ValueError: Si no hay clave privada o algoritmo inválido
        """
        if not self.ecdsa_private_key:
            raise ValueError("No hay clave privada ECDSA cargada. Genera o carga una primero.")
        
        if not message or not message.strip():
            raise ValueError("El mensaje no puede estar vacío")
        
        if hash_algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        try:
            hash_func = self.SUPPORTED_HASH_ALGORITHMS[hash_algorithm]
            
            # Firmar mensaje con ECDSA
            signature = self.ecdsa_private_key.sign(
                message.encode('utf-8'),
                ec.ECDSA(hash_func)
            )
            
            return {
                'signature_base64': base64.b64encode(signature).decode('utf-8'),
                'signature_hex': signature.hex(),
                'curve': self.current_curve,
                'hash_algorithm': hash_algorithm,
                'message_length': len(message),
                'message': f'Mensaje firmado con ECDSA ({self.current_curve})'
            }
            
        except Exception as e:
            raise ValueError(f"Error al firmar con ECDSA: {str(e)}")
    
    def verify_signature_ecdsa(self, message: str, signature_base64: str, 
                              hash_algorithm: str = 'SHA256') -> Dict:
        """
        Verificar una firma ECDSA.
        
        Args:
            message: Mensaje original
            signature_base64: Firma en base64
            hash_algorithm: Algoritmo hash usado para firmar
            
        Returns:
            Dict con:
                - valid: Si la firma es válida
                - curve: Curva utilizada
                - message: Mensaje de resultado
                
        Raises:
            ValueError: Si no hay clave pública o datos inválidos
        """
        if not self.ecdsa_public_key:
            raise ValueError("No hay clave pública ECDSA cargada. Carga una primero.")
        
        if not message or not signature_base64:
            raise ValueError("El mensaje y la firma no pueden estar vacíos")
        
        if hash_algorithm not in self.SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        try:
            signature = base64.b64decode(signature_base64)
            hash_func = self.SUPPORTED_HASH_ALGORITHMS[hash_algorithm]
            
            # Verificar firma
            self.ecdsa_public_key.verify(
                signature,
                message.encode('utf-8'),
                ec.ECDSA(hash_func)
            )
            
            return {
                'valid': True,
                'curve': self.current_curve,
                'hash_algorithm': hash_algorithm,
                'message': f'✅ Firma ECDSA válida ({self.current_curve})'
            }
            
        except Exception:
            return {
                'valid': False,
                'curve': self.current_curve,
                'message': '❌ Firma ECDSA inválida o mensaje alterado'
            }
    
    # ==================== ED25519 ====================
    
    def generate_ed25519_keypair(self) -> Dict:
        """
        Generar par de claves Ed25519.
        
        Returns:
            Dict con:
                - private_key_hex: Clave privada en hex (64 bytes)
                - public_key_hex: Clave pública en hex (32 bytes)
                - private_key_bytes: Clave privada en bytes
                - public_key_bytes: Clave pública en bytes
        """
        try:
            # Generar clave privada Ed25519
            self.ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
            
            # Obtener clave pública
            self.ed25519_public_key = self.ed25519_private_key.public_key()
            
            # Serializar a bytes crudos (formato Ed25519 estándar)
            private_bytes = self.ed25519_private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_bytes = self.ed25519_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            return {
                'private_key_hex': private_bytes.hex(),
                'public_key_hex': public_bytes.hex(),
                'private_key_base64': base64.b64encode(private_bytes).decode('utf-8'),
                'public_key_base64': base64.b64encode(public_bytes).decode('utf-8'),
                'message': 'Par de claves Ed25519 generado'
            }
            
        except Exception as e:
            raise ValueError(f"Error al generar claves Ed25519: {str(e)}")
    
    def load_ed25519_private_key_from_hex(self, private_key_hex: str) -> Dict:
        """
        Cargar clave privada Ed25519 desde hexadecimal.
        
        Args:
            private_key_hex: Clave privada en formato hexadecimal
            
        Returns:
            Dict con información de la clave
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            private_bytes = bytes.fromhex(private_key_hex)
            
            self.ed25519_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            self.ed25519_public_key = self.ed25519_private_key.public_key()
            
            return {
                'message': 'Clave privada Ed25519 cargada correctamente',
                'key_length': len(private_bytes)
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave privada Ed25519: {str(e)}")
    
    def load_ed25519_public_key_from_hex(self, public_key_hex: str) -> Dict:
        """
        Cargar clave pública Ed25519 desde hexadecimal.
        
        Args:
            public_key_hex: Clave pública en formato hexadecimal
            
        Returns:
            Dict con información de la clave
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            public_bytes = bytes.fromhex(public_key_hex)
            
            self.ed25519_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            
            return {
                'message': 'Clave pública Ed25519 cargada correctamente',
                'key_length': len(public_bytes)
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave pública Ed25519: {str(e)}")
    
    def sign_message_ed25519(self, message: str) -> Dict:
        """
        Firmar un mensaje usando Ed25519.
        
        Args:
            message: Mensaje a firmar
            
        Returns:
            Dict con:
                - signature_hex: Firma en hexadecimal
                - signature_base64: Firma en base64
                
        Raises:
            ValueError: Si no hay clave privada
        """
        if not self.ed25519_private_key:
            raise ValueError("No hay clave privada Ed25519 cargada. Genera o carga una primero.")
        
        if not message or not message.strip():
            raise ValueError("El mensaje no puede estar vacío")
        
        try:
            # Firmar mensaje con Ed25519
            signature = self.ed25519_private_key.sign(message.encode('utf-8'))
            
            return {
                'signature_hex': signature.hex(),
                'signature_base64': base64.b64encode(signature).decode('utf-8'),
                'message_length': len(message),
                'message': 'Mensaje firmado con Ed25519'
            }
            
        except Exception as e:
            raise ValueError(f"Error al firmar con Ed25519: {str(e)}")
    
    def verify_signature_ed25519(self, message: str, signature_hex: str) -> Dict:
        """
        Verificar una firma Ed25519.
        
        Args:
            message: Mensaje original
            signature_hex: Firma en hexadecimal
            
        Returns:
            Dict con:
                - valid: Si la firma es válida
                - message: Mensaje de resultado
                
        Raises:
            ValueError: Si no hay clave pública o datos inválidos
        """
        if not self.ed25519_public_key:
            raise ValueError("No hay clave pública Ed25519 cargada. Carga una primero.")
        
        if not message or not signature_hex:
            raise ValueError("El mensaje y la firma no pueden estar vacíos")
        
        try:
            signature = bytes.fromhex(signature_hex)
            
            # Verificar firma
            self.ed25519_public_key.verify(signature, message.encode('utf-8'))
            
            return {
                'valid': True,
                'message': '✅ Firma Ed25519 válida'
            }
            
        except Exception:
            return {
                'valid': False,
                'message': '❌ Firma Ed25519 inválida'
            }
    
    # ==================== UTILIDADES ====================
    
    def has_ecdsa_private_key(self) -> bool:
        """Verificar si hay una clave privada ECDSA cargada"""
        return self.ecdsa_private_key is not None
    
    def has_ecdsa_public_key(self) -> bool:
        """Verificar si hay una clave pública ECDSA cargada"""
        return self.ecdsa_public_key is not None
    
    def has_ed25519_private_key(self) -> bool:
        """Verificar si hay una clave privada Ed25519 cargada"""
        return self.ed25519_private_key is not None
    
    def has_ed25519_public_key(self) -> bool:
        """Verificar si hay una clave pública Ed25519 cargada"""
        return self.ed25519_public_key is not None
    
    def get_key_info(self) -> Dict:
        """
        Obtener información sobre las claves cargadas.
        
        Returns:
            Dict con información de las claves ECDSA y Ed25519
        """
        info = {
            'ecdsa': {
                'has_private_key': self.has_ecdsa_private_key(),
                'has_public_key': self.has_ecdsa_public_key(),
                'current_curve': self.current_curve
            },
            'ed25519': {
                'has_private_key': self.has_ed25519_private_key(),
                'has_public_key': self.has_ed25519_public_key()
            }
        }
        
        return info
    
    def clear_keys(self):
        """Limpiar todas las claves de la memoria"""
        self.ecdsa_private_key = None
        self.ecdsa_public_key = None
        self.current_curve = None
        self.ed25519_private_key = None
        self.ed25519_public_key = None
    
    def export_ecdsa_public_key_pem(self) -> str:
        """Exportar la clave pública ECDSA en formato PEM"""
        if not self.ecdsa_public_key:
            raise ValueError("No hay clave pública ECDSA para exportar")
        
        return self.ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def export_ecdsa_private_key_pem(self) -> str:
        """Exportar la clave privada ECDSA en formato PEM"""
        if not self.ecdsa_private_key:
            raise ValueError("No hay clave privada ECDSA para exportar")
        
        return self.ecdsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
