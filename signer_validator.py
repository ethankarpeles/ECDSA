import sys
from ecdsa import SigningKey, VerifyingKey

def validate_code(product, signature, verifyingkey):
    productfile = open(product, "rb")
    sigfile = open(signature, "rb")
    vk_file = open(verifyingkey, "rb")
    vk = VerifyingKey.from_pem(vk_file.read())

    product = productfile.read()
    sig = sigfile.read()
    if (vk.verify(sig, product)):
            print ("good")
            exec(open("product.py").read())
    else: return False

    
def sign_code(product):
    sk = SigningKey.generate()
    signature_file = open("signature.", "wb")
    public_key = open("public.pem", "wb")
    private_key = open("private.pem", "wb")
    unsigned_product = open(product, "rb")

    project_data = unsigned_product.read()

    vk = sk.verifying_key
    private_key.write(sk.to_pem())
    public_key.write(vk.to_pem())
    signature = sk.sign(project_data)
    signature_file.write(signature)
    assert vk.verify(signature, project_data)



if __name__ == '__main__':
    #if(validate_code(sys.argv[1])):
       # print("Code certificate valid: execution allowed")
    #else:
        #print("Code certificate invalid: execution denied")
    sign_code("product.py")
    validate_code("product.py", "signature", "public.pem")
