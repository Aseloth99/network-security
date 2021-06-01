from base64 import encode
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii
from base64 import b64encode,b64decode

class Signature:
    def __init__(self,n,e,d):
        self.rsaKey=RSA.construct((int(n), int(e), int(d)))
        self.pubKey=self.rsaKey.publickey()

    def Signaturing(self,msg):
        hash = SHA256.new(bytes(str(msg),encoding='utf-8'))
        signer = PKCS115_SigScheme(self.rsaKey)
        return signer.sign(hash)


class Verifyer:
    def __init__(self,n,e):
        self.rsaKey=RSA.construct((int(n), int(e) ))
        self.pubKey=self.rsaKey.publickey()

    def Verify(self,wantVerifyMsg,msg):

        hash = SHA256.new(bytes(str(msg),encoding='utf-8'))
        verifier = PKCS115_SigScheme(self.pubKey)
        
        try:
            verifier.verify(hash, wantVerifyMsg)
            return True
        except Exception as e:
            print(e)
            return False

# n = 503591335186393219362889058875513766185804175254109841161520658964614292349823588540946661286490466767854226576389672711627538641038240551013036239537643245460385619223907071388933454208741389530272784408731696885658361131973085790842971472241866141893503848051609861423936927929796982988569969641192672566077365607387225816042626482830407708080840651910911102998057739363283671979542950045317602257245310357511498769813886945677383901580035019803766408962137072770801034427475510071758106668830305030369075578330623931003348776294513185618757699750172885454949220251388412918312683870681600997384775911908019360587549355183608433892936411728518021528430915893695482341852653328668011806434443245813034454967487331193332859674791464004099179380337453821070497699052531619292036159071161101399309502823943099773571025949598025010571431170804601042469961517718074313051028428826250832213371937152286374050391585340065519048565313368370590769269640605796050204466797878006129324023839830461892279420173644609013197921073059997351097022586541424071212128971998473820078654222151966945371876853900649439428581505761232322013742127825541317660750535378446809580887728809048408442330988755578068116967245356124202944034643627256091431825631
# e = 65537
# d = 93868681060118399800678284682290555987087962599816986124313538457844091053076047997561750069056678548546732866276702348982132414344921900165940624413565617689916699336851683538874392734088908776749200212659511560724515000506327967727203556844326667216550086329836063096492264088841416973440510690706161222930575068432219213097589531322096839371889915677307323103350372218164904357875653108222833348711547848198124249996894012975798735701995938201669445532774867341625424364344428811764301555860521632833187775834824632515020654763168486130258389309063765029184425203945265303723205916722560351924140905745889566335610942303995049878868019564179107959345473053725635477411088412973143037067892554996728075382828125096881057263677670649080443322002822118051741459433942888054572153644329884031865485085429085952097296893224635208362332939761348943760566436894660963845689545577322503301521960862330213067135350883491592505058171588658087955230113986637359825590483846075167395201665151196297138666511026814255719797319956027996808171353117237335442184603682296088236467434490683021003180891192534562022328682791333121553950263381197608030074859736514624474716651829096590721435581076983366868360348866088313411821295340252039666477825

# mySignature = Signature(n,e,d)
# signMsg = mySignature.Signaturing("klavyefl@gmail.com")



# signature="b'\\x1a\\xe2\\xa9 \\x8c\\x86\\x9a*7L\\x8e\\x87\\xfb\\xf2-\\x9b\\r\\xd7\\xc3\\nS\\xc98\\x15\\x8a\\x0b\\xe2\\x15\\t!M:\\xe4\\xe0:.\\x89.\\xe2;\\xab\\xee\\x95\\xfe\\x87\\x86\\x89\\xf6\\x05t[\\x06\\xee\\xe5\\xa8@\\x82\\x88&\\xac;\\xde\\x111\\x98\\xdaw\\xc3\\x99\\xc6\\xfa\\xd7\\xac\\x7f\\x95D\\xebAb\\xc2\\xb9\\xfdz6\\xbd\\xdd}\\r\\xd1T\\xb8\\x02L6n\\xf2\\x99\\xef\\xb1\\xc7\\x16\\xf2\\xad!Ie\\x87,\\x18h\\xdb\\x1fY\\xdd\\x1aCS3\\x7f\\x94t\\x8dxAa\\x8f\\r\\x81`X\\x96\\xde;4\\x94\\xb3\\x13h\\x135\\xe7\\xa3\\x9e\\xe7\\xf6\\x83\\xfe\\xd9A}\\x070\\x1e\\xde\\xfb}\\xe0\\xd8\\xa4K\\xe1\\xee\\xfa\\xa5\\xaarB\\xc0\\xe6\\xb1\\xe2\\xd5\\xb3\\x90!\\x05@\\xf7\\xf6\\xb1O\\x86\\xae\\xd9\\xd5x\\xcdx\\xb9\\xa7Z\\x08\\xd8\\x0f\\xfa\\xd8\\xf8\\xdf&9\\x94\\x97\\xf9A\\x12O\\x15\\x9f\\xe7^\\xf8\\x1e\\xcfln\\xd7\\xa9\\xae\\xbb\\x03\\xf7\\xd0r\\xc8\\x90O\\xb4B\\x85v\\xe87\\xa5\\x84z!\\x88\\xce\\xa6\\xde\\xbd\\x18}\\x96b\\x13\\x84\\xdbTr\\xc49\\xae\\xa93{\\xb30\\x15/\\x92o\\xc5\\xbc\\xfaw\\xb4\\x02Bi\\xd3\\x9ap\\xf4\\x7fb\\x16\\xf9*I\\x1c\\n\\xee\\x0b\\xa3\\xf0\\xe7\\xe8\\xaa\\xf9\\x84h\\x02\\x00q\\xeb{5\\x8f\"\\xbc\\xae\\x8bx\\xdfB\\x16\\xc6\\x7f}H\\xae\\xdf\\xf7\\xce,r\\x90\\x8f\\xa1\\x94\\x0f|\\x17X\\xc3\\x84^\\n6gC\\xe7&X;.7\\xa9\\x1a\\x0e\\xd7\\xf1\\x04\\x1f\\xc5\\x81\\xb4\\xd2\\xb5\\xb7\\x86rHjG\\x80\\x16\\x1ek\\xde\\xc1\\x8d\\xd3\\xa3\\x9c\\xef\\xd5)\\xddh\\xfaRa\\xf0\\xf6\\x84\\x9b^\\x82{7\\xab\\xf6\\xcdD\\x11qE|\\xa4\\xcd\\xc9\\xc8]\\xed\\xcb\\xc6b\\xfd\\x10I,\\x19\\xbbh\\xaa,\\xb4\\x8d\\xe6\\xe1+W\\xa9X\\x03\\xc5\\xbc\\x97$\\x96\\xc9|\\x07\\xcd\\xbd\\'\\x99\\xd0_\\xe8/\\x1b|\\x04\\xbf\\x88;\\xd0\\xdb\\xf1\\xcfD\\x12\\xe7x\\xd7\\xe4a\\xcf\\xf9\\xf7\\xb2\\x16\\x94\\xcco\\xa89\\xf8\\x89\\xbdmx\\x94\\xee\\x90\\xf3\\'\\xf9\\x94\\xfb1z\\xed\\xd3\\xc2bu\\x8fx\\x1b_\\x85\\x1a\\x17\\xbd\\xc9E\\rq\\xf2}\\x91\\x13~P\\xab\\xd6\\x9a\\xba.\\xf6\\xdb\\x08[\\xd8\\x97\\xa4r3'"

# print("signMsg  ",signMsg)
# print("signMsg  ",type(signMsg))
# print("signature  ",len(signature))

# print("signature  ",bytes(signature,encoding="utf-8"))
# print("signature  ",type(bytes(signature,encoding="utf-8")))
# print("signature  ",len(bytes(signature,encoding="utf-8")))

# myVerifyer = Verifyer(n,e)

# print(myVerifyer.Verify(signMsg,"klavyefl@gmail.com"))

# if signMsg == bytes(signature[2:-1:],encoding="utf-8"):
#     print("Burada")


# mySignature = Signature(n,e,d)

# signMsg = mySignature.Signaturing("klavyefl@gmail.com")

# #print("i[FromSignature] ",i["FromSignature"], len(i["FromSignature"]))
# #print("i[From] ",i["From"], len(i["From"]))

# print(type(signMsg))
# print(signMsg)

# myVerifyer = Verifyer(n,e)

# print(myVerifyer.Verify(signMsg,"klavyefl@gmail.com"))


# # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
# # msg = b'anan'
# # hash = SHA256.new(msg)
# # signer = PKCS115_SigScheme(rsa_key) #RSA anahtarı ile imzalama
# # signature = signer.sign(hash)
# # #print("Signature:", binascii.hexlify(signature))

# # # Verify valid PKCS#1 v1.5 signature (RSAVP1)
# # msg = b'anan'
# # hash = SHA256.new(msg)
# # verifier = PKCS115_SigScheme(pubKey2) #Rsa public anahtarı
# # try:
# #     verifier.verify(hash, signature) 
# #     print("Signature is valid.")
# # except:
# #     print("Signature is invalid.")


# #Public key (e,n)
# #Private key (d,n)
# #Generate 2048-bit RSA key pair (private + public key)
# #keyPair = RSA.generate(bits=2048,e=65537)
# #pubKey = keyPair.publickey()
# #print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
# #print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
# #print(f"Public key:  (n={keyPair.n}, e={keyPair.e})")
# #print(f"Private key: (n={keyPair.n}, d={keyPair.d})") 