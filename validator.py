from ecdsa import VerifyingKey, BadSignatureError

def validate_code(product, signature, verifyingkey):

    productfile = open(product, "rb")
    sigfile = open(signature, "rb")
    vk_file = open(verifyingkey, "rb")
    vk = VerifyingKey.from_pem(vk_file.read())

    product = productfile.read()
    sig = sigfile.read()
    try:
        if (vk.verify(sig, product)):
            print ("good")
            exec(open("product.py").read())
        
    except BadSignatureError:
        print("Bad Signature")


    else: return False

validate_code("product.py", "signature", "public.pem")
