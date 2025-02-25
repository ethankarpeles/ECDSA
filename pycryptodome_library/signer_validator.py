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

def sign_code(product):
    #Generate ECC keys with the NIST P-192 curve
    key = ECC.generate(curve='p192')
    
    #Open the files
    signatureFile = open("signature.", "wb")
    publicKeyFile = open("public.pem", "wt")
    privateKeyFile = open("private.pem", "wt")
    unsignedProductFile = open(product, "rb")
    
    #Write the public and private keys to their respective files
    publicKeyFile.write(key.public_key().export_key(format='PEM'))
    privateKeyFile.write(key.export_key(format='PEM'))
    #Read the unsigned product data
    productData = unsignedProductFile.read()
    #Create a ECDSA signature object
    signer = DSS.new(key, 'fips-186-3')
    #Generate the signature from the hash of the product
    signature = signer.sign(SHA256.new(productData))
    #Write the signature to the signature file
    signatureFile.write(signature)
    
    #Close the files
    signatureFile.close()
    publicKeyFile.close()
    privateKeyFile.close()
    unsignedProductFile.close()
    
    #Make sure the signature is accurate
    signer.verify(SHA256.new(productData), signature)

if __name__ == '__main__':
    #Sign the code and then validate it
    sign_code("product.py")
    validate_code("product.py", "signature", "public.pem")