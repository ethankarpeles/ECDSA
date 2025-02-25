from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

def validate_code(product, signature, publicKeyFileName):
    #Open the files
    productFile = open(product, "rb")
    sigFile = open(signature, "rb")
    publicKeyFile = open(publicKeyFileName, "rb")
    
    #Read the files
    publicKey = ECC.import_key(publicKeyFile.read())
    product = productFile.read()
    sig = sigFile.read()
    
    #Close the files
    productFile.close()
    sigFile.close()
    publicKeyFile.close()
    
    #Check the signature
    verifier = DSS.new(publicKey, 'fips-186-3')
    try:
        verifier.verify(SHA256.new(product), sig)
        print("Code certificate valid: execution allowed")
        exec(product)
    except ValueError:
        print("Code certificate invalid: execution denied")

validate_code("product.py", "signature", "public.pem")