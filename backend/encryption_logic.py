#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
Backend: Encryption Logic (Punto 1c, 1d y Cifrado Simétrico)

Lógica pura de cifrado/descifrado sin dependencias de UI.
Implementa:
- RSA: Cifrado con clave privada (1c) y clave pública (1d)
- Simétrico: DES (ECB, CFB), AES (CBC), ARC4
- Híbrido: RSA + AES (como ejemplo del profesor)
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Dict, Optional


class EncryptionLogic:
    """
    Lógica de cifrado y descifrado RSA + Cifrado Simétrico.
    
    Soporta múltiples modos:
    - RSA: Cifrado con clave privada (1c) y clave pública (1d)
    - Simétrico: DES (ECB, CFB), AES (CBC, CTR, GCM), ARC4
    - Híbrido: RSA + AES (como en los ejemplos del profesor)
    """
    
    def __init__(self):
        """Inicializar con claves vacías"""
        self.private_key = None
        self.public_key = None
        
    # ==================== GENERACIÓN Y CARGA DE CLAVES ====================
    
    def generate_keypair(self, key_size: int = 2048) -> Dict:
        """
        Generar un par de claves RSA.
        
        Args:
            key_size: Tamaño de la clave en bits (1024, 2048, 4096)
            
        Returns:
            Dict con:
                - public_key_pem: Clave pública en formato PEM
                - private_key_pem: Clave privada en formato PEM
                - key_size: Tamaño de la clave
                
        Raises:
            ValueError: Si el tamaño de clave no es válido
        """
        if key_size not in [1024, 2048, 4096]:
            raise ValueError("El tamaño de clave debe ser 1024, 2048 o 4096 bits")
        
        try:
            # Generar clave privada
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Obtener clave pública
            self.public_key = self.private_key.public_key()
            
            # Serializar clave pública (PEM)
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Serializar clave privada (PEM)
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            return {
                'public_key_pem': public_pem,
                'private_key_pem': private_pem,
                'key_size': key_size,
                'message': f'Par de claves RSA-{key_size} generado correctamente'
            }
            
        except Exception as e:
            raise ValueError(f"Error al generar claves: {str(e)}")
    
    def load_private_key_from_pem(self, key_data: bytes) -> Dict:
        """
        Cargar clave privada desde formato PEM.
        
        Args:
            key_data: Datos de la clave en formato PEM (bytes)
            
        Returns:
            Dict con información de la clave cargada
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Extraer clave pública de la privada
            self.public_key = self.private_key.public_key()
            
            # Obtener tamaño de clave
            key_size = self.private_key.key_size
            
            return {
                'key_size': key_size,
                'message': f'Clave privada RSA-{key_size} cargada correctamente'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave privada: {str(e)}")
    
    def load_public_key_from_pem(self, key_data: bytes) -> Dict:
        """
        Cargar clave pública desde formato PEM.
        
        Args:
            key_data: Datos de la clave en formato PEM (bytes)
            
        Returns:
            Dict con información de la clave cargada
            
        Raises:
            ValueError: Si la clave no es válida
        """
        try:
            self.public_key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            
            # Obtener tamaño de clave
            key_size = self.public_key.key_size
            
            return {
                'key_size': key_size,
                'message': f'Clave pública RSA-{key_size} cargada correctamente'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cargar clave pública: {str(e)}")
    
    # ==================== CIFRADO CON CLAVE PÚBLICA (Punto 1d - Estándar) ====================
    
    def encrypt_with_public_key(self, message: str) -> Dict:
        """
        Cifrar mensaje con clave pública usando OAEP (método estándar).
        Solo quien tenga la clave privada podrá descifrar.
        
        Args:
            message: Mensaje a cifrar (texto plano)
            
        Returns:
            Dict con:
                - ciphertext_base64: Mensaje cifrado en base64
                - original_length: Longitud del mensaje original
                - method: Método de cifrado usado
                
        Raises:
            ValueError: Si no hay clave pública o el mensaje es inválido
        """
        if not self.public_key:
            raise ValueError("No hay clave pública cargada. Genera o carga una primero.")
        
        if not message or not message.strip():
            raise ValueError("El mensaje no puede estar vacío")
        
        try:
            # Cifrar con clave pública usando OAEP
            ciphertext = self.public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convertir a base64
            cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            return {
                'ciphertext_base64': cipher_b64,
                'original_length': len(message),
                'encrypted_length': len(ciphertext),
                'method': 'RSA-OAEP (SHA-256)',
                'message': 'Mensaje cifrado correctamente con clave pública'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cifrar con clave pública: {str(e)}")
    
    def decrypt_with_private_key(self, ciphertext_base64: str) -> Dict:
        """
        Descifrar mensaje cifrado con clave pública usando OAEP.
        
        Args:
            ciphertext_base64: Mensaje cifrado en base64
            
        Returns:
            Dict con:
                - plaintext: Mensaje descifrado
                - length: Longitud del mensaje descifrado
                
        Raises:
            ValueError: Si no hay clave privada o el cifrado es inválido
        """
        if not self.private_key:
            raise ValueError("No hay clave privada cargada. Genera o carga una primero.")
        
        if not ciphertext_base64 or not ciphertext_base64.strip():
            raise ValueError("El texto cifrado no puede estar vacío")
        
        try:
            # Decodificar de base64
            cipher_bytes = base64.b64decode(ciphertext_base64)
            
            # Descifrar con clave privada
            plaintext_bytes = self.private_key.decrypt(
                cipher_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            plaintext = plaintext_bytes.decode('utf-8')
            
            return {
                'plaintext': plaintext,
                'length': len(plaintext),
                'method': 'RSA-OAEP (SHA-256)',
                'message': 'Mensaje descifrado correctamente con clave privada'
            }
            
        except Exception as e:
            raise ValueError(f"Error al descifrar con clave privada: {str(e)}")
    
    # ==================== CIFRADO CON CLAVE PRIVADA (Punto 1c - Firma) ====================
    
    def encrypt_with_private_key(self, message: str, hash_algorithm: str = 'SHA256') -> Dict:
        """
        "Cifrar" con clave privada usando firma digital.
        En RSA, esto se implementa mediante firma digital con padding PKCS1v15.
        Solo quien tenga la clave pública podrá verificar/descifrar.
        
        Args:
            message: Mensaje a cifrar
            hash_algorithm: Algoritmo hash (SHA256, SHA384, SHA512)
            
        Returns:
            Dict con:
                - ciphertext_base64: "Mensaje cifrado" (firma) en base64
                - hash_algorithm: Algoritmo usado
                
        Raises:
            ValueError: Si no hay clave privada o el mensaje es inválido
        """
        if not self.private_key:
            raise ValueError("No hay clave privada cargada. Genera o carga una primero.")
        
        if not message or not message.strip():
            raise ValueError("El mensaje no puede estar vacío")
        
        # Mapeo de algoritmos
        hash_map = {
            'SHA256': hashes.SHA256(),
            'SHA384': hashes.SHA384(),
            'SHA512': hashes.SHA512()
        }
        
        if hash_algorithm not in hash_map:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        try:
            # "Cifrar" firmando el mensaje
            signature = self.private_key.sign(
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hash_map[hash_algorithm]
            )
            
            # Convertir a base64
            cipher_b64 = base64.b64encode(signature).decode('utf-8')
            
            return {
                'ciphertext_base64': cipher_b64,
                'hash_algorithm': hash_algorithm,
                'original_length': len(message),
                'signature_length': len(signature),
                'method': f'RSA-Sign-PKCS1v15 ({hash_algorithm})',
                'message': 'Mensaje "cifrado" con clave privada (firma digital)',
                'note': 'Este método implementa cifrado mediante firma digital. ' +
                        'Para descifrar, usa la clave pública con verificación.'
            }
            
        except Exception as e:
            raise ValueError(f"Error al cifrar con clave privada: {str(e)}")
    
    def decrypt_with_public_key(self, ciphertext_base64: str, original_message: str, 
                                hash_algorithm: str = 'SHA256') -> Dict:
        """
        "Descifrar" con clave pública verificando firma digital.
        Verifica que el mensaje cifrado corresponda al mensaje original.
        
        Args:
            ciphertext_base64: "Mensaje cifrado" (firma) en base64
            original_message: Mensaje original para verificar
            hash_algorithm: Algoritmo hash usado (SHA256, SHA384, SHA512)
            
        Returns:
            Dict con:
                - valid: Si la verificación fue exitosa
                - plaintext: Mensaje original (si es válido)
                
        Raises:
            ValueError: Si no hay clave pública o los datos son inválidos
        """
        if not self.public_key:
            raise ValueError("No hay clave pública cargada. Carga una primero.")
        
        if not ciphertext_base64 or not ciphertext_base64.strip():
            raise ValueError("El texto cifrado no puede estar vacío")
        
        if not original_message:
            raise ValueError("Se requiere el mensaje original para verificar")
        
        # Mapeo de algoritmos
        hash_map = {
            'SHA256': hashes.SHA256(),
            'SHA384': hashes.SHA384(),
            'SHA512': hashes.SHA512()
        }
        
        if hash_algorithm not in hash_map:
            raise ValueError(f"Algoritmo hash no soportado: {hash_algorithm}")
        
        try:
            # Decodificar de base64
            signature_bytes = base64.b64decode(ciphertext_base64)
            
            # Verificar firma
            self.public_key.verify(
                signature_bytes,
                original_message.encode('utf-8'),
                padding.PKCS1v15(),
                hash_map[hash_algorithm]
            )
            
            # Si llegamos aquí, la verificación fue exitosa
            return {
                'valid': True,
                'plaintext': original_message,
                'hash_algorithm': hash_algorithm,
                'method': f'RSA-Verify-PKCS1v15 ({hash_algorithm})',
                'message': 'Firma verificada correctamente. El mensaje es auténtico.',
                'note': 'La verificación exitosa confirma que el mensaje fue cifrado ' +
                        'con la clave privada correspondiente.'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'plaintext': None,
                'hash_algorithm': hash_algorithm,
                'message': f'Verificación fallida: {str(e)}',
                'note': 'El mensaje no pudo ser verificado. Puede que la firma no ' +
                        'corresponda al mensaje o se usó una clave incorrecta.'
            }
    
    # ==================== UTILIDADES ====================
    
    def has_private_key(self) -> bool:
        """Verificar si hay una clave privada cargada"""
        return self.private_key is not None
    
    def has_public_key(self) -> bool:
        """Verificar si hay una clave pública cargada"""
        return self.public_key is not None
    
    def get_key_info(self) -> Dict:
        """
        Obtener información sobre las claves cargadas.
        
        Returns:
            Dict con información de las claves
        """
        info = {
            'has_private_key': self.has_private_key(),
            'has_public_key': self.has_public_key()
        }
        
        if self.private_key:
            info['private_key_size'] = self.private_key.key_size
        
        if self.public_key:
            info['public_key_size'] = self.public_key.key_size
        
        return info
    
    def clear_keys(self):
        """Limpiar las claves de la memoria"""
        self.private_key = None
        self.public_key = None
    
    def export_public_key_pem(self) -> str:
        """
        Exportar la clave pública en formato PEM.
        
        Returns:
            Clave pública en formato PEM (string)
            
        Raises:
            ValueError: Si no hay clave pública
        """
        if not self.public_key:
            raise ValueError("No hay clave pública para exportar")
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return public_pem
    
    def export_private_key_pem(self) -> str:
        """
        Exportar la clave privada en formato PEM.
        
        Returns:
            Clave privada en formato PEM (string)
            
        Raises:
            ValueError: Si no hay clave privada
        """
        if not self.private_key:
            raise ValueError("No hay clave privada para exportar")
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        return private_pem

