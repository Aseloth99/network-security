from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

class Signature:
    def __init__(self,n,e,d):
        self.rsaKey=RSA.construct((int(n), int(e), int(d)))
        self.pubKey=self.rsaKey.publickey()

    def Signaturing(self,msg):
        hash = SHA256.new(bytes(str(msg),encoding='utf-8'))
        signer = PKCS115_SigScheme(self.rsaKey)
        return signer.sign(hash)
        
    def Verify(self,wantVerifyMsg,msg):
        hash = SHA256.new(bytes(str(msg),encoding='utf-8'))
        verifier = PKCS115_SigScheme(self.pubKey)
        try:
            verifier.verify(hash, wantVerifyMsg)
            return True
        except:
            return False

# n = 682497107911059868474515568822675861839409977131877244150377613316562827099833309015734293756396768899056899821120329465791547329906585933238461779680346606605047793568554683302195662230694795144989211750325302718692286355723616470835862148151685926667087307327761971475464060909841988849152555220626966854344516785112253437119412268242879769238871084813766246715554507203992565515376657980465344113616157860162915190162751201401043799220574081777730816611881160832516374440590184325155639813930170490050199593597307126775244769219877204411221172886163059311985605852062136667074140639618720478222951639767054998923495065434405360720483628415766956931859602845077649036739652166381540641718636316502919996144489594559189808405988104200077061934972017644404395707793526969769154139684078528351872773453399581845490435959666679190061927673152746515914886547413349788514405387725884412592610313290563316703854329681456573012855447889517326284942257705275354548973800270029817489383207075637448939060228997686125781525850239689900026739385270346479109558565000630798815770645622860455622352398562441306628766774023704830364142088288251645751146616057620584314664106093751392533052959639546937139477321368445147330499086492348852127616783
# e = 65537
# d = 276510417157551636903357452788191242863726043499177633805038777923636666084116972412313303444158979016551853213457848054926181618073449649806180282498017350482585852492977462365379849909965488208031395248403763336538407118378526092644365957515961437430222655662705584122198479412822138454959773047562250696805706847708936223238699277452201712510955720340801705644008777870216985818152814787025890976162110311778777242308945632232182049176872347213975443530809597363702561517105613229191640574629200098445349949024149699103350765404674909311179098562238148692369833934784226509973794684882681021984158749089748452498821151197224485660384109546558456315524506487281772741870897711399484567389331900353627893555936376653051191313822576733863747687657565509180390350302034276297247437202190659928023127583323441174327839163934010956744506466314673439183819674068283860254976712104963851890356231247223741407005819703982875617374955321455535760756140400259403162227461957609606808474273991342572603940843954072884611324636846277616028214575308447158304880010033479342694274483027505564826533585263315371774664726306160887239660231539333760966664088837592487228781987012204868307692327086491464880883293241417861789091018511087763720698113
# rsa_key = RSA.construct((n, e, d))
# pubKey2=rsa_key.publickey()

# # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
# msg = b'anan'
# hash = SHA256.new(msg)
# signer = PKCS115_SigScheme(rsa_key) #RSA anahtarı ile imzalama
# signature = signer.sign(hash)
# #print("Signature:", binascii.hexlify(signature))

# # Verify valid PKCS#1 v1.5 signature (RSAVP1)
# msg = b'anan'
# hash = SHA256.new(msg)
# verifier = PKCS115_SigScheme(pubKey2) #Rsa public anahtarı
# try:
#     verifier.verify(hash, signature) 
#     print("Signature is valid.")
# except:
#     print("Signature is invalid.")


#Public key (e,n)
#Private key (d,n)
#Generate 2048-bit RSA key pair (private + public key)
#keyPair = RSA.generate(bits=2048,e=65537)
#pubKey = keyPair.publickey()
#print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
#print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
#print(f"Public key:  (n={keyPair.n}, e={keyPair.e})")
#print(f"Private key: (n={keyPair.n}, d={keyPair.d})") 