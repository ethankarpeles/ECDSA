import sys
from ecdsa import SigningKey, VerifyingKey, keys
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

    
def sign_code(product):
    #Generate a signing key
    sk = SigningKey.generate()
    
    #Open the files
    signature_file = open("signature.", "wb")
    public_key = open("public.pem", "wb")
    private_key = open("private.pem", "wb")
    unsigned_product = open(product, "rb")
    
    #Use the files
    vk = sk.verifying_key
    private_key.write(sk.to_pem())
    public_key.write(vk.to_pem())
    project_data = unsigned_product.read()
    signature = sk.sign(project_data, hashfunc=hashlib.sha256)
    signature_file.write(signature)
    
    #Close the files
    signature_file.close()
    public_key.close()
    private_key.close()
    unsigned_product.close()
    
    #Make sure the signature is accurate
    assert vk.verify(signature, project_data, hashlib.sha256)



if __name__ == '__main__':
    #Sign the code and then validate it
    sign_code("product.py")
    validate_code("product.py", "signature", "public.pem")
