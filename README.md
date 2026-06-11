# Suite Criptográfica Web

Una aplicación web educativa y demostrativa diseñada para ilustrar conceptos fundamentales de seguridad informática y criptografía. Originalmente una aplicación de escritorio (Tkinter), ha sido migrada a una arquitectura web moderna con un backend en **Flask** (Python) y un frontend web puro.

## 🚀 Características y Módulos

La suite está dividida en varios módulos que permiten explorar diferentes áreas de la criptografía y la seguridad de aplicaciones:

1. **Message Digest (Resúmenes de Mensaje)**
   - Generación de hashes con múltiples algoritmos (SHA256, MD5, etc.).
   - Generación de HMAC con clave compartida.
   - Análisis del Efecto Avalancha.
   - Comparación directa de mensajes y sus resúmenes.

2. **Firma Digital**
   - Generación de pares de claves RSA.
   - Carga y exportación de claves públicas y privadas en formato PEM.
   - Firma y verificación de mensajes (Estándar y "Textbook" RSA).
   - Generación de certificados X.509 básicos.

3. **Cifrado (Simétrico y Asimétrico)**
   - **RSA**: Cifrado y descifrado con clave pública/privada.
   - **Simétrico**: Cifrado y descifrado con DES (ECB/CFB), AES (CBC) y ARC4.
   - **Híbrido**: Demostración de intercambio seguro de claves y cifrado de datos utilizando una combinación de RSA y AES.

4. **Curvas Elípticas**
   - Generación de claves, firma y verificación usando **ECDSA** (ej. curva secp256k1).
   - Generación de claves, firma y verificación usando **Ed25519**.

5. **Monitor de SQL Injection**
   - Módulo interactivo para demostrar vulnerabilidades de inyección SQL (SQLi).
   - Comparativa en tiempo real entre un inicio de sesión "Vulnerable" y uno "Seguro".
   - Monitor de eventos para detectar e identificar ataques.

## 🛠️ Tecnologías Utilizadas

*   **Backend:** Python 3, Flask, Flask-CORS.
*   **Frontend:** HTML5, CSS3, JavaScript Vanilla (se comunica vía REST API con el backend).
*   **Criptografía:** Utiliza bibliotecas estándar y robustas de Python para operaciones criptográficas (`cryptography`).

## ⚙️ Requisitos Previos

Asegúrate de tener instalado Python 3.8 o superior y las dependencias necesarias. Puedes instalar las dependencias ejecutando:

```bash
pip install -r requirements.txt
```
*(Nota: Asegúrate de que paquetes como `Flask`, `Flask-CORS` y `cryptography` estén listados en tu entorno).*

## 🏃‍♂️ Cómo Ejecutar la Aplicación

1.  Abre una terminal o consola de comandos en el directorio del proyecto (donde se encuentra `web_app.py`).
2.  Ejecuta el archivo principal:

    ```bash
    python web_app.py
    ```

3.  El servidor se iniciará. Abre tu navegador web y navega a la siguiente dirección:

    ```
    http://localhost:5000
    ```

    *(La consola también mostrará la dirección IP local si deseas acceder desde otro dispositivo en la misma red).*

## 🗂️ Estructura del Proyecto

*   `web_app.py`: Archivo principal de la aplicación Flask, define todas las rutas de la API REST.
*   `backend/`: Contiene la lógica del negocio de cada módulo criptográfico.
*   `web/templates/`: Contiene el archivo `index.html` (interfaz principal).
*   `web/static/`: Contiene los recursos estáticos (CSS, JS, imágenes).
