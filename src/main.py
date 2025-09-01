from http.client import HTTPException
import os
import re
import base64
import json
import pycades
import time
from typing import Optional
from fastapi import FastAPI, Body, HTTPException as FastAPIHTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from os import environ

CRYPTOPRO_SIGN_PASSWORD = environ.get('CRYPTOPRO_SIGN_PASSWORD')
app = FastAPI()

async def parse_meta(lists: str):
    if len(lists):
        ret = dict((x, y) for x, y in re.findall(r'(CN|OU|SN|G|E|O|C|L|STREET|emailAddress)=([^,]*)', f'{lists} ,'))
        ret['raw'] = lists
        return ret

async def certificate_info(cert):
    cert_info = {}
    pk = cert.PrivateKey
    cert_info['PrivateKey'] = {
            'ProviderName': pk.ProviderName,
            'UniqueContainerName': pk.UniqueContainerName,
            'ContainerName': pk.ContainerName,
    }
    algo = cert.PublicKey().Algorithm
    cert_info['Algorithm'] = {
        'FriendlyName': algo.FriendlyName,
        'Value': algo.Value,
    }
    cert_info.update(
        {
            'Valid': {
                'ValidFromDate': cert.ValidFromDate,
                'ValidToDate': cert.ValidToDate,
            },
            'IssuerName': await parse_meta(cert.IssuerName),
            'SubjectName': await parse_meta(cert.SubjectName),
            'Thumbprint': cert.Thumbprint,
            'SerialNumber': cert.SerialNumber,
            'HasPrivateKey': cert.HasPrivateKey()
        }
    )
    return cert_info

async def certificate_info_public_only(cert):
    """Информация о сертификате без приватного ключа"""
    cert_info = {}
    
    try:
        algo = cert.PublicKey().Algorithm
        cert_info['Algorithm'] = {
            'FriendlyName': algo.FriendlyName,
            'Value': algo.Value,
        }
    except:
        cert_info['Algorithm'] = None
    
    cert_info.update(
        {
            'Valid': {
                'ValidFromDate': cert.ValidFromDate,
                'ValidToDate': cert.ValidToDate,
            },
            'IssuerName': await parse_meta(cert.IssuerName),
            'SubjectName': await parse_meta(cert.SubjectName),
            'Thumbprint': cert.Thumbprint,
            'SerialNumber': cert.SerialNumber,
            'HasPrivateKey': False
        }
    )
    return cert_info

async def retrieve_certificate_store():
    store = pycades.Store()
    store.Open(
        pycades.CADESCOM_CONTAINER_STORE, 
        pycades.CAPICOM_MY_STORE, 
        pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
    )
    certificates = store.Certificates
    assert certificates.Count != 0, "No certificates with private key found"
    return certificates

async def create_signer(pin: str = None):
    certificates = await retrieve_certificate_store()
    signer = pycades.Signer()
    signer.Certificate = certificates.Item(1)
    signer.CheckCertificate = False
    signer.Options = pycades.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY
    if pin:
        signer.KeyPin = pin
    return signer

def base64url_encode(data: bytes) -> str:
    """Кодирование в base64url"""
    return base64.b64encode(data).decode('ascii').rstrip('=').replace('+', '-').replace('/', '_')

def base64url_decode(data: str) -> bytes:
    """Декодирование base64url"""
    # Добавляем padding если необходимо
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    # Заменяем символы base64url на base64
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def hex_to_base64url(hex_string: str) -> str:
    """Конвертация HEX строки в base64url"""
    # Убираем пробелы и приводим к верхнему регистру
    hex_string = hex_string.replace(' ', '').upper()
    # Конвертируем HEX в bytes
    signature_bytes = bytes.fromhex(hex_string)
    # Кодируем в base64url
    return base64url_encode(signature_bytes)

def base64url_to_hex(base64url_string: str) -> str:
    """Конвертация base64url строки в HEX"""
    # Декодируем base64url в bytes
    signature_bytes = base64url_decode(base64url_string)
    # Конвертируем bytes в HEX
    return signature_bytes.hex().upper()

def parse_jwt(token: str) -> tuple:
    """Парсинг JWT токена"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        signature = base64url_decode(parts[2])
        
        return header, payload, signature
    except Exception as e:
        raise ValueError(f"Failed to parse JWT: {str(e)}")

async def create_jwt_token(payload: dict, pin: str = None) -> str:
    """Создание JWT токена с подписью GOST3410_2012_256"""
    try:
        # Создаем заголовок JWT
        header = {
            "alg": "GOST3410_2012_256",
            "typ": "JWT"
        }
        
        # Добавляем стандартные поля если их нет
        current_time = int(time.time())
        if 'iat' not in payload:
            payload['iat'] = current_time
        if 'exp' not in payload:
            payload['exp'] = current_time + 3600  # 1 час по умолчанию
        
        # Кодируем заголовок и payload в base64url
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        
        # Создаем сообщение для подписи
        message = f"{header_encoded}.{payload_encoded}"
        
        # Создаем подпись
        signer = await create_signer(pin)
        hashed_data = pycades.HashedData()
        hashed_data.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256
        hashed_data.DataEncoding = pycades.CADESCOM_STRING_TO_UCS2LE
        hashed_data.Hash(message)
        
        # Получаем сырую подпись в HEX формате
        raw_signature = pycades.RawSignature()
        signature_hex = raw_signature.SignHash(hashed_data, signer.Certificate)
        
        # Убираем пробелы из HEX строки и конвертируем в base64url
        signature_hex_clean = ''.join(signature_hex.split())
        signature_base64url = hex_to_base64url(signature_hex_clean)
        
        # Собираем JWT
        jwt_token = f"{message}.{signature_base64url}"
        
        return jwt_token
        
    except Exception as e:
        raise Exception(f"Failed to create JWT: {str(e)}")

async def verify_jwt_signature(jwt_token: str, public_key_pem: str = None) -> tuple[bool, Optional[dict], Optional[str]]:
    """Проверка подписи JWT с использованием КриптоПро"""
    cert_info = None
    
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        if public_key_pem:
            # Используем переданный публичный ключ
            cert = pycades.Certificate()
            
            # Очищаем PEM от заголовков и форматирования
            pem_data = public_key_pem.strip()
            pem_data = pem_data.replace('-----BEGIN CERTIFICATE-----', '')
            pem_data = pem_data.replace('-----END CERTIFICATE-----', '')
            pem_data = pem_data.replace('\n', '').replace('\r', '').replace(' ', '')
            
            # Импортируем сертификат
            cert.Import(pem_data)
            
            # Получаем информацию о сертификате
            cert_info = await certificate_info_public_only(cert)
        else:
            # Используем наш сертификат из хранилища
            certificates = await retrieve_certificate_store()
            cert = certificates.Item(1)
            cert_info = await certificate_info(cert)
        
        # Создаем объект для хеширования
        hashed_data = pycades.HashedData()
        hashed_data.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256
        hashed_data.DataEncoding = pycades.CADESCOM_STRING_TO_UCS2LE
        
        # Хешируем сообщение (header.payload как строку)
        message_to_hash = f"{parts[0]}.{parts[1]}"
        hashed_data.Hash(message_to_hash)
        
        # Конвертируем подпись из base64url в HEX формат для проверки
        signature_base64url = parts[2]
        signature_hex = base64url_to_hex(signature_base64url)
        
        # Создаем объект RawSignature для проверки
        raw_signature = pycades.RawSignature()
        
        # Проверяем подпись (передаем HEX строку)
        raw_signature.VerifyHash(hashed_data, cert, signature_hex)
        
        return True, cert_info, None
        
    except Exception as e:
        return False, cert_info, str(e)

@app.get('/')
async def root():
    return RedirectResponse('/docs#/')

@app.get('/info')
async def list_certificates():
    certificates = await retrieve_certificate_store()
    certificate_data = []
    
    for i in range(1, certificates.Count + 1):
        certificate_data.append(await certificate_info(certificates.Item(i)))
    
    return JSONResponse(content=certificate_data)

@app.post('/license')
async def configure_license(serial_number: str):
    os.system(f'cpconfig -license -set {serial_number}')
    return JSONResponse(content={'statusLicense': 'Serial number license installed'})

@app.post('/sign')
async def sign_content(
    data: str = Body(...),
    encoding: Optional[str] = Body('utf-8'),
    pin: Optional[str] = Body(None),
    password: Optional[str] = Body(None)
):
    if CRYPTOPRO_SIGN_PASSWORD and password != CRYPTOPRO_SIGN_PASSWORD:
        raise HTTPException(status_code=401, detail="Incorrect password")
    
    signer = await create_signer(pin)
    hashedData = pycades.HashedData()
    hashedData.DataEncoding = pycades.CADESCOM_BASE64_TO_BINARY
    
    if isinstance(data, str):
        data = bytes(data.encode(encoding))
        
    hashedData.Algorithm = pycades.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256
    hashedData.Hash(base64.b64encode(data).decode())
    signed_data = pycades.SignedData()
    signature = signed_data.SignHash(hashedData, signer, pycades.CADESCOM_CADES_BES)
    return JSONResponse(content={'signature': ''.join(signature.split())})

@app.post('/create-jwt')
async def create_jwt(
    payload: dict = Body(...),
    pin: Optional[str] = Body(None),
    password: Optional[str] = Body(None)
):
    """
    Создание JWT токена с подписью GOST3410_2012_256
    """
    if CRYPTOPRO_SIGN_PASSWORD and password != CRYPTOPRO_SIGN_PASSWORD:
        raise FastAPIHTTPException(status_code=401, detail="Incorrect password")
    
    try:
        jwt_token = await create_jwt_token(payload, pin)
        
        return JSONResponse(content={
            'jwt': jwt_token,
            'payload': payload
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                'error': f"Failed to create JWT: {str(e)}"
            }
        )

@app.post('/verify-jwt')
async def verify_jwt(
    jwt_token: str = Body(...),
    public_key: Optional[str] = Body(None),
    password: Optional[str] = Body(None)
):
    """
    Проверка JWT токена с подписью GOST3410_2012_256
    Если public_key не передан, используется сертификат из хранилища
    """
    if CRYPTOPRO_SIGN_PASSWORD and password != CRYPTOPRO_SIGN_PASSWORD:
        raise FastAPIHTTPException(status_code=401, detail="Incorrect password")
    
    try:
        # Парсим JWT
        header, payload, signature = parse_jwt(jwt_token)
        
        # Проверяем алгоритм
        if header.get('alg') != 'GOST3410_2012_256':
            return JSONResponse(
                status_code=400,
                content={
                    'error': f"Unsupported algorithm: {header.get('alg')}. Expected GOST3410_2012_256",
                }
            )
        
        # Проверяем подпись и получаем информацию о сертификате
        is_valid, cert_info, error = await verify_jwt_signature(jwt_token, public_key)
        
        return JSONResponse(content={
            'valid': is_valid,
            'header': header,
            'payload': payload,
            'certificate': cert_info,
            'error': error
        })
        
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                'error': str(e)
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                'error': f"Internal server error: {str(e)}"
            }
        )

@app.post('/convert-signature')
async def convert_signature(
    signature: str = Body(...),
    from_format: str = Body(...),  # "hex" или "base64url"
    to_format: str = Body(...),    # "hex" или "base64url"
    password: Optional[str] = Body(None)
):
    """
    Конвертация подписи между HEX и base64url форматами
    """
    if CRYPTOPRO_SIGN_PASSWORD and password != CRYPTOPRO_SIGN_PASSWORD:
        raise FastAPIHTTPException(status_code=401, detail="Incorrect password")
    
    try:
        if from_format == "hex" and to_format == "base64url":
            result = hex_to_base64url(signature)
        elif from_format == "base64url" and to_format == "hex":
            result = base64url_to_hex(signature)
        else:
            return JSONResponse(
                status_code=400,
                content={
                    'error': f"Unsupported conversion from {from_format} to {to_format}"
                }
            )
        
        return JSONResponse(content={
            'original': signature,
            'converted': result,
            'from_format': from_format,
            'to_format': to_format
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                'error': f"Conversion failed: {str(e)}"
            }
        )