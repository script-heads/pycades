import os
import re
import base64
import pycades
from typing import Optional
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse

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
async def sign_content(data: str, encoding: Optional[str] = 'utf-8', pin: Optional[str] = None):
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