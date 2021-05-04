from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes 
import Crypto
import libnum
from Crypto.PublicKey import RSA

class RSAGenerator:
    def __init__(self):
        bits=2048
        msg="goodbye"

        p = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)
        q = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)

        n = p*q
        PHI=(p-1)*(q-1)

        e=65537
        d=libnum.invmod(e,PHI)

        m=  bytes_to_long(msg.encode('utf-8'))

        c=pow(m,e, n)
        res=pow(c,d ,n)

        self.privateKey=d
        self.privateP=p
        self.privateQ=q
        self.publicKey=[e,n]

        #print("Public key (e,n)",(e,n))
        #print("Private key (d,n)",(d, n))
        #print ("Message=%s\np=%s\nq=%s\n\nd=%d\ne=%d\nN=%s\n\nPrivate key (d,n)\nPublic key (e,n)\
        #\ncipher=%s\ndecipher=%s" % (msg,p,q,d,e,n,c,(long_to_bytes(res))))
        
#Public key (e,n) (65537, 738345778137112577490377808567006088783102504465965627061257947399551108759552165535235443613577473236083681674689066854053801295426875598382300230217773556706502343046272208723062834174987653524159088398608977224758247657708930107499480983450211822268170689490221647954843577754887400705702792175552394176762420417553036613169302313047253027347743258072052813222781984638015483901602972134853341620982674539433425665374385510367717995670224420778750476391199536418899852408516296918591760554931056549848490389503633701112875813837599483098128306099389210582108515755086446741634960645281293462340608674220141245265748164955723470818770019195044385617058823350709503266661829895013798625587173108074244275588479623606316213436585594855430032627222678279550332575170062062578649888189476767728635714692135940463004898528090914977038904075738984130219158541726140524868474707566102617469430382124061135791345408955011791754700746483329137740515152118757020472839085972389924855432886282425187125584942925661774216719197861885345909441364167428036424259245391220845877035320754513847075802377683492996361913134461501051783654931652830975722761270780339252366777586888917192935485991130362044180805178401813340297943565225173620492998461)
#Private key (d,n) (139237613439684061601897849094093843954870742522466228006318369347255018587352262292292519456493339513935001935051683434536993304700867533155421342833231050968699550753145219152666944894771997648734030753900977303214782226858487071403727443649559301027088843728117694540090510360142413984799133443667730284123575292438439042100788978545722266276923858683072168677546463038302536972090744657440109390019757917403263924170499573105797133046802624721982653122950929560419049939985854000288013926459754457780757323708369454080199462642765033669679230588558390734764776328136982090725338032180775835040779751967388279143670056436097057354033721242211971925929281335402380500329182291690507970552329431064153959762249195185963337233901020268787504161714936340543245501561859923760841370154246694658557280028138617442337152123828486192470428778618764836859238282628634467963946965405228088117704971515128379719987651746433191814711288786234967041457807841972472394253344050735504656238360393717878010459215448174753737665610761868399685602099942631153903625758223129537566146980125535830279812520256768177205639290291501010529232012887945834838956171552607337523002133203691804001158161026671417350656180999584818953356341856003729038626017, 738345778137112577490377808567006088783102504465965627061257947399551108759552165535235443613577473236083681674689066854053801295426875598382300230217773556706502343046272208723062834174987653524159088398608977224758247657708930107499480983450211822268170689490221647954843577754887400705702792175552394176762420417553036613169302313047253027347743258072052813222781984638015483901602972134853341620982674539433425665374385510367717995670224420778750476391199536418899852408516296918591760554931056549848490389503633701112875813837599483098128306099389210582108515755086446741634960645281293462340608674220141245265748164955723470818770019195044385617058823350709503266661829895013798625587173108074244275588479623606316213436585594855430032627222678279550332575170062062578649888189476767728635714692135940463004898528090914977038904075738984130219158541726140524868474707566102617469430382124061135791345408955011791754700746483329137740515152118757020472839085972389924855432886282425187125584942925661774216719197861885345909441364167428036424259245391220845877035320754513847075802377683492996361913134461501051783654931652830975722761270780339252366777586888917192935485991130362044180805178401813340297943565225173620492998461)


# #https://blog.epalm.ca/img/sign-and-verify.png