from ecdsa import VerifyingKey, keys
import hashlib

def validate_code(product, signature, verifyingkey):
    #Open the files
    productfile = open(product, "rb")
    sigfile = open(signature, "rb")
    vk_file = open(verifyingkey, "rb")
    
    #Read the files
    vk = VerifyingKey.from_pem(vk_file.read(), hashlib.sha256)
    product = productfile.read()
    sig = sigfile.read()
    
    #Close the files
    productfile.close()
    sigfile.close()
    vk_file.close()
    
    #Check the signature
    try:
        vk.verify(sig, product, hashlib.sha256)
        print("Code certificate valid: execution allowed")
        exec(product)
    except keys.BadSignatureError:
        print("Code certificate invalid: execution denied")


validate_code("product.py", "signature", "public.pem")