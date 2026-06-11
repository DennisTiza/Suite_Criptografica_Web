import re
import mysql.connector
from mysql.connector import Error
from datetime import datetime

class SqlInjectionLogic:
    def __init__(self):
        self.connection = None
        self.host = "127.0.0.1" # Conexión a la base de datos local
        self.user = "root"
        self.password = "admin" # PON TU CONTRASEÑA DE MYSQL AQUÍ
        self.database = "crypto_suite_db"
        
        # Intentar crear la DB al instanciar si la contraseña es correcta
        try:
            self.setup_database()
        except:
            pass # Si falla (por contraseña incorrecta, por ejemplo), no detiene el servidor.

    def _get_raw_connection(self):
        try:
            conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password
            )
            return conn
        except Error as e:
            raise ValueError(f"Error conectando a MySQL: {e}")

    def _get_db_connection(self):
        try:
            conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            return conn
        except Error as e:
            raise ValueError(f"Error conectando a la base de datos: {e}")

    def setup_database(self):
        """Crea la base de datos y las tablas si no existen."""
        conn = self._get_raw_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            cursor.close()
            conn.close()

            db_conn = self._get_db_connection()
            db_cursor = db_conn.cursor()

            # Crear tabla de usuarios
            db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'user'
                )
            """)

            # Crear tabla de logs de ataque
            db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    attack_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    attack_type VARCHAR(100),
                    query_executed TEXT
                )
            """)

            # Insertar usuario admin de prueba si no existe
            db_cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if db_cursor.fetchone()[0] == 0:
                db_cursor.execute(
                    "INSERT INTO users (username, password, role) VALUES ('admin', 'super_secret_password_123!', 'admin')"
                )
                db_conn.commit()

            db_cursor.close()
            db_conn.close()
            return True
        except Error as e:
            raise ValueError(f"Error configurando base de datos: {e}")

    def _log_attack(self, ip_address, attack_type, query_executed):
        """Registra un ataque en la base de datos."""
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            sql = "INSERT INTO attack_logs (ip_address, attack_type, query_executed) VALUES (%s, %s, %s)"
            cursor.execute(sql, (ip_address, attack_type, query_executed))
            conn.commit()
            cursor.close()
            conn.close()
        except Error as e:
            print(f"Error al registrar log de ataque: {e}")

    def login_vulnerable(self, username, password, ip_address):
        """
        Login vulnerable a SQL Injection (Concatenación Directa).
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1) Concatenación Directa de Variables
        # 2) Sin Sanitización de Entrada
        # 3) Sin Prepared Statements
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            # Ejecuta multiples consultas si es necesario (para inyecciones con ;), 
            # pero por defecto python connector requiere multi=True. 
            # Para el OR 1=1 basta con execute normal.
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            conn.close()

            # Verificación de bypass
            if len(results) > 0:
                # Si encontró más de 1 usuario, o el usuario/contraseña devueltos no coinciden
                # exactamente con el input original, es un bypass exitoso mediante inyección
                if len(results) > 1 or results[0]['username'] != username or results[0]['password'] != password:
                    self._log_attack(ip_address, "SQLi Vulnerable Bypass (Exitoso)", query)
                    return {"success": True, "message": "¡Bypass de autenticación exitoso! Acceso concedido.", "users": results, "query": query}
                
                # Login normal
                self._log_attack(ip_address, "Login Normal", query)
                return {"success": True, "message": "Login exitoso (Flujo normal).", "users": results, "query": query}
            else:
                self._log_attack(ip_address, "Login Fallido", query)
                return {"success": False, "message": "Usuario o contraseña incorrectos.", "query": query}
        except Error as e:
            # Error de sintaxis SQL causado por inyección
            self._log_attack(ip_address, "SQLi Syntax Error", query)
            raise ValueError(f"Error SQL (posible inyección malformada): {e}")

    def login_secure(self, username, password, ip_address):
        """
        Login seguro contra SQL Injection.
        """

        # 2) Detección de Patrones Maliciosos
        # 3) Validación y Sanitización de Entrada
        suspicious_patterns = [
            r"(\bOR\b|\bAND\b)\s+\d+.*=.*\d+", # OR 1=1
            r"--", # Comentarios SQL
            r"/\*.*\*/", # Comentarios SQL /* */
            r";", # Fin de sentencia
            r"\bUNION\b", # UNION SELECT
            r"'", # Comillas simples sin escapar
            r'"'  # Comillas dobles
        ]

        # Verificar si hay patrones sospechosos en username o password
        for pattern in suspicious_patterns:
            if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
                # 4) Logging de Intentos de Ataque
                mock_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '***'"
                self._log_attack(ip_address, "SQLi Attempt Blocked (Patrón Detectado)", mock_query)
                raise ValueError("Intento de Inyección SQL detectado y bloqueado.")

        conn = self._get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1) Prepared Statements (Consultas Preparadas)
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        
        try:
            cursor.execute(query, (username, password))
            results = cursor.fetchall()
            cursor.close()
            conn.close()

            if len(results) > 0:
                self._log_attack(ip_address, "Login Seguro Exitoso", query)
                return {"success": True, "message": "Login exitoso de forma segura.", "users": results}
            else:
                self._log_attack(ip_address, "Login Seguro Fallido", query)
                return {"success": False, "message": "Usuario o contraseña incorrectos."}
        except Error as e:
            raise ValueError(f"Error en consulta segura: {e}")

    def get_monitor_logs(self):
        """Obtiene los registros de ataques."""
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, attack_time, ip_address, attack_type, query_executed FROM attack_logs ORDER BY attack_time DESC LIMIT 50")
            logs = cursor.fetchall()
            
            # Formatear fechas para JSON
            for log in logs:
                if isinstance(log['attack_time'], datetime):
                    log['attack_time'] = log['attack_time'].strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.close()
            conn.close()
            return logs
        except Error as e:
            raise ValueError(f"Error al obtener logs: {e}")
