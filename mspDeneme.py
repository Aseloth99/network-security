import FBConf

if 1622493995.7042875 > float(1622493995.7042875)-10:
    myReplyAttack = FBConf.db.child("Inbox").child(
        "XlNnsQo9dZdVkliDFtzIwVJD0wI3").child("3gHF8d7hyEbPuicl9gyIQltfeXb2").get()
    for replyAttackMail in myReplyAttack.each():
        replyAttackMailVal=replyAttackMail.val()

        if float(replyAttackMailVal["TimeStamp"]) == 1622493995.7042875:
            replyAttackKey = replyAttackMail.key()
            print(replyAttackKey)
            break
    print(replyAttackKey)
    FBConf.db.child("Inbox").child("XlNnsQo9dZdVkliDFtzIwVJD0wI3").child(
        "3gHF8d7hyEbPuicl9gyIQltfeXb2").child(replyAttackKey).remove()
