#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
BACKEND: Message Digest Logic (Punto 1a)

Lógica de negocio para generación de resúmenes digitales.
Sin dependencias de UI - solo operaciones criptográficas.
"""

import hashlib
import hmac
from typing import Dict, Tuple


class MessageDigestLogic:
    """Clase con la lógica pura de operaciones de message digest"""
    
    # Algoritmos soportados
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
    
    @staticmethod
    def generate_digest(message: str, algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Generar digest de un mensaje usando el algoritmo especificado.
        
        Args:
            message: Mensaje a hashear
            algorithm: Algoritmo de hash ('md5', 'sha1', 'sha256', 'sha384', 'sha512')
            
        Returns:
            Dict con información del digest: {
                'algorithm': str,
                'digest_hex': str,
                'digest_size': int,
                'digest_size_bits': int,
                'block_size': int,
                'message_length': int
            }
            
        Raises:
            ValueError: Si el algoritmo no es soportado o el mensaje está vacío
        """
        if not message:
            raise ValueError("El mensaje no puede estar vacío")
        
        if algorithm not in MessageDigestLogic.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
        
        # Crear objeto hash
        hash_obj = hashlib.new(algorithm, message.encode('utf-8'))
        
        return {
            'algorithm': algorithm.upper(),
            'digest_hex': hash_obj.hexdigest(),
            'digest_size': hash_obj.digest_size,
            'digest_size_bits': hash_obj.digest_size * 8,
            'block_size': hash_obj.block_size,
            'message_length': len(message)
        }
    
    @staticmethod
    def generate_hmac(message: str, key: str, algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Generar HMAC (Hash-based Message Authentication Code).
        
        Args:
            message: Mensaje a autenticar
            key: Clave secreta
            algorithm: Algoritmo de hash
            
        Returns:
            Dict con información del HMAC: {
                'algorithm': str,
                'hmac_hex': str,
                'digest_size': int,
                'key_length': int,
                'message_length': int
            }
            
        Raises:
            ValueError: Si el mensaje o clave están vacíos
        """
        if not message or not key:
            raise ValueError("El mensaje y la clave no pueden estar vacíos")
        
        if algorithm not in MessageDigestLogic.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")
        
        # Generar HMAC
        mac = hmac.new(key.encode('utf-8'), message.encode('utf-8'), algorithm)
        
        return {
            'algorithm': f"HMAC-{algorithm.upper()}",
            'hmac_hex': mac.hexdigest(),
            'digest_size': mac.digest_size,
            'key_length': len(key),
            'message_length': len(message)
        }
    
    @staticmethod
    def analyze_avalanche_effect(message: str, algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Analizar el efecto avalancha cambiando un solo carácter del mensaje.
        
        Args:
            message: Mensaje original
            algorithm: Algoritmo de hash
            
        Returns:
            Dict con análisis del efecto avalancha: {
                'original_message': str,
                'modified_message': str,
                'original_hash': str,
                'modified_hash': str,
                'bits_changed': int,
                'total_bits': int,
                'percentage': float
            }
        """
        if not message:
            raise ValueError("El mensaje no puede estar vacío")
        
        # Hash del mensaje original
        hash1 = hashlib.new(algorithm, message.encode('utf-8')).hexdigest()
        
        # Modificar último carácter
        modified = message[:-1] + ('a' if message[-1] != 'a' else 'b')
        hash2 = hashlib.new(algorithm, modified.encode('utf-8')).hexdigest()
        
        # Calcular diferencias en bits
        diff_bits = bin(int(hash1, 16) ^ int(hash2, 16)).count('1')
        total_bits = len(hash1) * 4  # 4 bits por carácter hexadecimal
        percentage = (diff_bits / total_bits) * 100
        
        return {
            'original_message': message,
            'modified_message': modified,
            'original_hash': hash1,
            'modified_hash': hash2,
            'bits_changed': diff_bits,
            'total_bits': total_bits,
            'percentage': percentage,
            'algorithm': algorithm.upper()
        }
    
    @staticmethod
    def compare_messages(message1: str, message2: str, 
                        algorithms: list = None) -> Dict[str, Dict[str, any]]:
        """
        Comparar dos mensajes usando múltiples algoritmos de hash.
        
        Args:
            message1: Primer mensaje
            message2: Segundo mensaje
            algorithms: Lista de algoritmos (por defecto usa todos)
            
        Returns:
            Dict con comparación por algoritmo: {
                'md5': {'hash1': str, 'hash2': str, 'match': bool},
                'sha1': {...},
                ...
                'messages_identical': bool
            }
        """
        if not message1 or not message2:
            raise ValueError("Ambos mensajes deben tener contenido")
        
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        results = {}
        
        for algo in algorithms:
            hash1 = hashlib.new(algo, message1.encode('utf-8')).hexdigest()
            hash2 = hashlib.new(algo, message2.encode('utf-8')).hexdigest()
            
            results[algo] = {
                'hash1': hash1,
                'hash2': hash2,
                'match': hash1 == hash2,
                'algorithm': algo.upper()
            }
        
        results['messages_identical'] = message1 == message2
        
        return results
    
    @staticmethod
    def get_hash_comparison(hash1: str, hash2: str) -> list:
        """
        Comparar dos hashes y obtener posiciones donde difieren.
        
        Args:
            hash1: Primer hash (hex)
            hash2: Segundo hash (hex)
            
        Returns:
            Lista de índices donde los hashes difieren
        """
        if len(hash1) != len(hash2):
            raise ValueError("Los hashes deben tener la misma longitud")
        
        differences = []
        for i in range(len(hash1)):
            if hash1[i] != hash2[i]:
                differences.append(i)
        
        return differences
    
    @staticmethod
    def validate_algorithm(algorithm: str) -> bool:
        """
        Validar si un algoritmo es soportado.
        
        Args:
            algorithm: Nombre del algoritmo
            
        Returns:
            True si es válido, False si no
        """
        return algorithm.lower() in MessageDigestLogic.SUPPORTED_ALGORITHMS
