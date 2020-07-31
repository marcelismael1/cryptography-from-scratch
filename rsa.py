# Marcel Ismael
# Week 10 RSA

# 1024 bit generated key
p = 11003378959096834724676546774061387323366640315376248759704778733861819318638880334019013198255253637201505215283454116581559061011493945035043282347726567
q = 13352889525665842987778367770008624367016738648357150498263337383873676994755016453139838515936896298380832735119884881555123452210776892442746292021125831
e = 65537
d = 69357425854335667435469380960551384845473529705172208755274378055130556220144321336280182386572376501722777078239543992605048261113781725370395014753635278111987701312950756882999549218951256463733424485080811858880863848299798658061367375851385442141410733493910441693585064588874291332393795622978366749253
n = q*p


def encrypt_RSA(message, e , n):
    '''
    >>> encrypt_RSA(1412,e,n)
    86570912637207688430658050442534138686860113447750593750129115867611069795980400149875084938172511059077111775763831984800728158009625476246509869646143906270016350813522907485120229804954044822840485338235665911639144492389863191230410694146471337610863228296869316878318424832455813948760206789878680061806
    >>> encrypt_RSA(423523131313,e,n)
    83815489698949425454503411340462271441833577560361070073340854340767697288862182622524598818990559851595417109271788865693175864183668088463270319213547090274280405302127646890044893707234611412838644930391470657208403905675470886164666899520786460799826428450507750448082240371010595240565614073056710598296
    '''
    return pow(message,e,n)

def decrypt_RSA(cipher,d,n):
    '''
    >>> decrypt_RSA(86570912637207688430658050442534138686860113447750593750129115867611069795980400149875084938172511059077111775763831984800728158009625476246509869646143906270016350813522907485120229804954044822840485338235665911639144492389863191230410694146471337610863228296869316878318424832455813948760206789878680061806,d,n)
    1412
    >>> decrypt_RSA(83815489698949425454503411340462271441833577560361070073340854340767697288862182622524598818990559851595417109271788865693175864183668088463270319213547090274280405302127646890044893707234611412838644930391470657208403905675470886164666899520786460799826428450507750448082240371010595240565614073056710598296,d,n)
    423523131313
    '''
    return pow(cipher,d,n)

# Test Pure encryption Decryption
test_result = True
import random
for i in range(100):
    test_case = random.randint(0,100000000000000000)
    if decrypt_RSA(encrypt_RSA(test_case,e,n),d,n) != test_case:
         test_result = False
print(test_result)            


# RSA Padding

import base64
# Ciphers are
ciphers = [
    b'fkQKtKSJR0xafjo8dn8o8yseq90I30z1jofzB0Qu0SiUosyKzqNYR9Oh08zgnbK2/C3j8pHyGK7kadH6aFHCQoVkDUFva8H5jJcJbCfJj8u4z3396+acsqPhVeGg6M6L/nyygsTz2aIB7+tVUkVZiqwZK/p96xdAlB4gOqIDjBFyVBJDAPOi9NMBW4nyPdK3WhqVtXCDWoTTqhbSWrJcm7FcMQZlai8XT5C3f6TkUjf8ktyZWj9yZHWlhdhf8HKtdSq4y3VMWKufYa9EbYVEDoSF2iGxe4CkOv1QiNqjDLllT+tdULpm0EAa1WtJhG4LoWPt4TEW+0KVDJrg9Xcgsw==',
    b'O0d5jJC8X8OPc9jFG0eHHEGHxXTqc8tuVFMShxCn3rrBBGOShNO4Kx1nfnoL8SvQjGMdSNV64xh53ohwMGZhGVlj9FL4ydDrWhc0U74jI7REQODCXdXWZxBB0aKn/rPsPcL9h6957cof0z6H8XJtpTYcpgTV6UthEqwGIvf2qnxqpGC8WCbKhuXjqxX3JCmfBOripqiN/XgjNhpET2AVXEVJayo0dW4RTLi6k2VctXhkhK5YAfB94AbaEIfpuJiMfqMEedkle1YcMVI5tsMN1KwIcLkvBTctT6vvNWr+YXD45WlpZo1sCTpVsBfSU1vqfzxkOU3mdHKaCMOADxok6g==',
    b'TcEAH3j8dy+ZlkV9hpD4G3PXuHNnOBYsEjt9OGWsaIU03D7EA+L0BU8/1QRAhemC3l2jKChmQXLRpb89dpz2yJCM6JcFPT/nMRNmXxQD9l3dqmwdOTWlZ03SXa1IrQoSfOSzwOOmeAI+7Vs+bypJbPKIoOLxjtHNnDhWkSJ23Kfk1Gi3Y/XqhZgyFxejY8k8eg7PfLXU62S/zVd6T0HmDljV2w5iQqC8mgBLCr0ZFwMY5U3/NeWxxbZih1cgN1mk1UgE/PeshwoBr/VQGTZgsyOcq4BN3R3LpDrFFw1eP085WXsC+il6Uoe8rEod3MxfaS9tisFWiXfcf7xU/VzQsw==',
    b'MnCqdOXNssZprkjwlymjUC2qhmhoRdYoCl6m2edKw9bRh78KjvGWzXVMbAYxQRoMcpfPjrBHnuirOwU/LceNLnHGN/mTuWkf72erfhzIYvRcyvMNiAn2uWk6c31gO3Opyc30T7HcjxGxzKaMtAP899t3daEIH9SkJ1ILo4X4wnVZTMOzK6VpBM9aFPY0KKanjryaPgcbkPH8pT/BiRnDZpVRX7lkjxuK4mEQnYTNAJB6iZ/aZlHdlYo0M9OKR6FJSJcnl6wGh5wwxqg6JmW1Jv1cIZviibUip97hUNBmUgZcRT5gFLlnUBLZ/aON2BVJPh0DyBFGi0jvJ7bbclGWtA==',
    b'UftzvH2m4/rtFsArr2NdUC4fSUZhTzqwwXiuesX+eLR5qWHrRE91bUWxBSVi5xR67u5JcCsffzhro4ipUe1vgEyGhJTYxYOHs4P6TraTH0P0r9VFaD5PckaZsz0ClFbnu/iCUMvzc9uBdob8JYosUyJiUFinnzzLR5Q/YPjnoabjh7AdxHEZs7rHKeY9Tim+rsfpxvdtzUgw6ktSotA2QxuyOshcPxjXTTdriCI/g5IxXi/jFbYG2yazbcptYfuY/gT5NAIduIM1NMpDVP0Tbi+1Fo1kzU3AFwMwIM/6EpysnqrlFJlerwFBTy/qnUNKznjdJNsUzzkvRZ1+XEfzHA==',
    b'f8OgNf/XhUmUazQqMwRbv2lNH7pFk4/SNagr6JOm7+E+ZJuW0WrSpP9qaTxSsRB7a3OsjKwR5o0JixWpcp8JHr/E7FMnRL6TFQlU8yGJFNy8HWxi/jAdGm8fOvjsdwqw/yyA6ilTIHbBYctYb3LvOLCpRKbFKba4c0jAPSISdbEpP7Un7lmK5HGfPVhQ3lSB9Xp+8AMQYSL3RXp36Bxy019QWk6Q5CZj6e4e77sWLHxJd22eAV8nyV0HIxg82oEeXV+vcpy3kk71D1RbKeFSshTzLcu0HWmUfaAIROPrxsgWHzWQEY53OrnfpxWbGItJ2xAdPXJvGosLgE4lRBAHaw==',
    b'QzSIAj4kOCdkjhYX2kNoRxybIDBt8ckJBDYKx3th7TWFkGlnocYV7xgqa7xsCp1xyXkf3IltR4LYwLWwKKHblZ1DIICok3/6GpQ7VJ1U2Ym/ZGrOQ4w500Gv73giUL1vzNBidmmOJaq2qz54Q2xaHtY2urXa33xhiwCBxM81HpvjNeJvj1IJ09+9qGLk+QWNbNjmRrCDechbaMu71I4Zb4RPMI6uHIkSZzsoTkJAg3+IVbCc57OpjMQb8K8oL/BZePtIaDxvAI9/YxZLVeZSeuN7LjjZGUcVwCtVjr8athcfD6SDIcOAbrAEYiNs2LBdMC0IglmK5p6DFhtG8sTCbg==',
    b'C2aJcd9kgP5WFK9XkFUJKLbanLMcAoAV0aaI/1hVfkTB1O++jeNagyLgMtAN8RtC1ucDf/ThIrHU4o7ag+mjVkXUUFTK/gimPQl9wnoHRDUZa3bAik28kdF4Hf9Jj4fzTS+vQ7yvC2DD1XdWcKMucjgOhzTlihSmDkEvGZmhtmgfc3H5fsi0CzjW8rLJVhvtKsmNTWXz49slBixc9AEYiliox1kuw5SKMpgcnGW0pwQqrczAaNg+Y//ltKz7xYR+oDagkIlSRQOUpwfMdn05flRyNAhdWb4+aM/R6atSiNaJtBO5byabU0N/fXc2zhsajET/yxEuqIa3FGYUzv18Zg==',
    b'CB7QphKYRp5O7FajF4oEDMnQg15U9uSyQN2Lb3+ukN3ft4T/nHf1Bv5eSpsXWtDQGNVQh/6hluVK2ExLEjntpB9IhCZHKYDH4d5AL6AQs0AWpAfCoIAWKEH51nFA2rFWg7pa7V0Rh95cYXvLMGR0xlQcqXJpKVyv4EhD4nPXtrSSbwap/TlyoVCk051GDqEmUQuflONCJIbBEAioRc2pzyJ03oiiK3H6IMni6TAaqPG1HBOQYT1TbX6UpVWQm5gPqqFp+XPcOec8SlhyPMufrXBF6kawxGhQ4Bk3xHNVmE6bxCmlFk7095QIzJnbpCx3DRWvV9CT4RfgIxW1qHwSXg==',
    b'MQRaAwwloljDgzH+wTtY/l16l8oBpggykK9ld5mckuvTc1KcjtKf58r8QTADusZhPPtUlsvMVlomh9WoPIhBmm+o0q4IhBzob35jvtBSKlJlgcRYUee0+RZBojIQaKkMe2OFHsT1Fn4IK4KejVZiVh/GVYkbw7CJAuQW56pKgXHOQOTRNj1t6TD+KstIYSZ5Y0S17IYo9EB/f3jUPxmLLPlp+fuYz5lJIVKsH3zh7UJ19uuQat93ezuI9j5f/FapGuw0704zBO6ufmkM9BAt3M5S1CDkJqs1Ve6XN/EruMyqZK4snumhkB9KRl+j9KKwOVL1MkM/2EDX420iRh31oQ==',
    b'ozp8X+E9VGx/IAwVDhyNwacjMZt2xTSa8mqlIERO5qXTCPcYpSMvzidxybZyEJP4047cMCXz3aePO6oUYlW4Osry9El95p0adeoUWBkaiEIRNuHcOM6rO/oFUTwiKavmEIEdDFI0t4F1FBHbC7p+j3H3a1Izar7TMpHiJ+UYyqt2SAetjCmgFMYpUpe8vdLdU4Gcujf/aMt32wmzFXvg3q+DGHAL+NvjjBj8oJ6GzKa2nsfWEBiKRZixPMlV3H4D4hUhxHQOWALjhKfggV8zFZR1VHp1r3/jOdF5shgHIIM+j0gxPW/MfvXmoMPCqQyMmA6AAjJ7nEai78goEG44Ow==',
    b'TN5a8ejPt7bBR8xldIDFZr1ytNFPcF6FVmHURymlENJysXa2CKp6PmHy6sjFCVulngRuWbm4snOgOa4PxFjic7FNVAO1oWm2cEGoolVQQQ+zdGIhpHZLLwIDSnCCHev/sgF/kUHG9ZU8meid3qjXC47IQ6637yfvElNkZsYEIam4qiaM/I/fa9Cyfoio+uBzG8RBiHudFJzwy86/icys8TIUd7bxKIXDvRem2eqOtADbbnF2rPl8kiIg3c5Cv4hssCT/jQqtzEf+FApTI5jwPL6dDHhP6wrtllB/1nCl1U3JyfWte0iicxDJSQPOcfVvf/8Kne7d+9ud5KgOJ/m04g==',
    b'B1CKW0KBqoit4aWueBVfA4RFLisrsv5h6DH4okH29svYAJKV65SW5+GJd+bWyESohdtdnqRegSQZaaslLiQg6Z9pJIso3P7EfmYyioajsDfJic6KNazagRo1kZjNqrzD0Ny0SVPQNmXVEJsejZvjkDt97tqnLhyy1soR5Da3zvMVQgQ7m/OH1rStcikZHwTPCeytLM60kBRYRREDrcU+urkEokkaVOYXN5Zvg9dUhhoSl3ohKU+rJNBFaySAre70ffMSN6mPy6gGmaHRIhgoEl9RsaDp3nVAyJape2UjRIGdCFqV5Wd4HI1fy4OOMDVxjbUJBih7mVzcHf9CHszuvQ==',
    b'KeswSWZM0DitUpwaab138tWVq0p5vWurWnFTyBS7gHzEWIHO93YSuMbYmVkyYunC1C74z56WVwQPUBZszW0FztTFi3nxU3nol1VjJfs3lncx9H+xk2P497dm2b/PTZoUMLS7BNBgdbZCaX7G/de6aG+hLKIlVq6xFT8bGF8rYMt+hD4CET3VjCt3tgjF/btfihlLjDyzqPcdqaUtSJzQm4uawCPX6R0P2LVy7O0GyWrXAccTi2KFnsoaXdnQsSlKE+zbiQwcS9OaYnEeGlYcb0YzJfrchRFI9a/ulhWrcXI8f7BR3lR956Q9izTAEja8QmW4a02dBN5m41y/x/ztqw==',
    b'LF/PtlCw5e3Iv4ypakOchSe0MTFsJ7wqzz09QerFNx1mJAmyHifuUUzrUAM+VEHI+MDzSkUc3hdnscmMxVy/ZJpWfFc3UqmfNdyESFBZfnRq2SHm7FrYzREQBWBzQz5DCVSSasx4WF97TEY8ajmeR6LiB2xSFtcA9BqXZ3TEXAlwlLnhqa9wi0ihX+lmdvCySuzz0cq3ZsHFBoNGCdhyC5ZfjLzi5wfFWPAkNi+RH7ciMQFtm0rbGr3wZ522ReeToyIzkCFCWQukl0dqt8mYwSPSWaZbdlQYxIMN9UpNwiEVU7jWoaMDxPrqdIs1SF0ejV261YhyVgIejh7XkowSnw==',
    b'BlFHM9RGBbVCJ7b03cyooHlv+DsrNUokP2CR+bCkI8cbueZpNBN0poZYafMv7qR4D1eayyvVrwAOCj9KGHKzJpkPnwjg4thuXnH/ZEinsqyVvbg7dpQSzRsM6dxH75whBofJXvzabzDIpORDn+QG6RGxc6VLdQyAUQ7LWrL6D7GCMwwO+AHhid+4r23jTGYncbotwmDsv4YS3aoNhbPFHBzni64i1SeZUnMDiVA46zsDDbNH83V/glo6mTFl7xy2BYak+ohMDJiiNbrVdT+NF3nOD+jIqz7vBsKItzN5NEtaQMkubE18vqCSLgFcaoYLKkI1SB5T/g9fhILtcuxipg==',
    b'Zs+afNP9lHzPPUEOJLTjnQGbiisGy0s2cNsX6I/fEP7/maL1T1gSyAkeKrg3x5bYbep5YNMWOTqIRpXevnGnFvB+zqPw2te3E/saA2Y8xnJOSd1bVLoa31EuLF+H4s7oTSjdJDZsvjP5I7ARZanPOQiru+PCCp5oo/Ab3UladhY5As7bEw7A+YEfKERLVfinj/dX8IsaNpuq9BkomvyyxGTiBjRFHGHrZLML1LowoLhcOZ0Z/vFeIr7rhl8S93hzfeBw1RhIAN74k0F4POBNWNTt4CljTABV+gvvglv7rU1OZWMk0LAzP9bTrLXFAEYcERe9OIRJV7hnVAlljmUa9A==',
    b'xreXej7YGEo8th3+CYLMG2RTx3zFETLtlfdYB4TDdIj4/DZ5MOmp7jMiS1rewXmJLAKE1YATXBapNnp8IuFgjURzRxwQ+tlIOA33BAd9t4yLMn8W2+JUcLHOVOcDjVviqOOE9YKsIDhIDQVkmHV6XnvqyIUveA/vH4J/QOQuLV9cv+cmCpBD9S5wL2NyhqhjzTUvrnJq4MQg2b6ZnGjASaecAeoYu3VyG/60N3XBzY5+f5CIX8JfjEJ0ZXNwMhpigqoFFmv1FIFfi4+ChgSsdj5f7o7C2ylU+vo1ao+lrTgtqnI6HzSUF6uAuD01ZjT46aLRfVfsrFilKoIUoAtxiQ==',
    b'ZBdRxsGAm5PJ7QiCAt/S7FUU0Qqdq+6Gap6IDLCdjor2W3Vu4lEt+tjazmJXJ4FUwVc3yW83xejsRG/XbkAQu/AunZPN2CRdoDkRUNWghMY/muDPuXpkiLTbvSSq2fb0aGtwfCceXS2SkN8aIZqOQddqS+jhaoVzRyblrbsZGFcQCynXzoI7jZBvBrnfH2KOsPM88JiqEWvDQltYWTg8j688GAcH3FsAuXhkmj+8EflbxHR0WvC+srMtQls4Oqc4PrJ+UuToL/ezHK6hLfTo9sujQRhlGVnFdcojBzbW+n84fubBuqAHMXkZzdSyjicGlLamYa/btppPsJ8MFNGYCA==',
    b'SYapMoN/T/5/tRQlZnsISZ9vtKmMZnEK5kq4x/WKHnBhDZTtzsYpwsB7r49Ee3TvnkbJo2S+FQOdhcslceQvIG3W7kdc6CvJ/3P5LsGjCijvTOtiDPjXlzRrzYyksUKfG1KNfCaqgTrNxiTGO2/9uKX5/ZcNpTnVO8UpV4HAodyOEUsVOGo+WP25Pp+7BEpOkSGqTjPFz/pwKFIl7N50EnPYjfjwIg12+Z5KyG7bXJbTN5sAQwEylf7P+KaEGk61A7SzJFAd8TYMx+0pC4ibS7vXh2NoBHx4mh1VoDnxfihklLEW+owaogJeD6LvKzajNo+QvEgtQvBp7caBV2K/ng==',
    b'cgUEyPODmmGvNExGXEuWYI06GyGeSNTefk8SrW7qDJBDm2oYOsoRjmC0xjeguWlGsc2TBvqTOXlSMvOn8wlCWJc+eJi5/XqeE+Th5CA5lCrd7ATlZSh1gF7PU46kbHr6WDAfmQvYayFmLR9IgAefjAbrHMDjsMkoWHN34JliQQCCcrG+N0OZEW1Qlar08pblRadRcWJ9fY5gZtO/ug2AsY6CZr65ueU2GonupzaXOJLe5hb4NQclk38mf5sr/BAFni623/ES1xHO56jkReSgZ02isrxF+sjIVMimMuElzx5A7Hx8scEY201qA0eCE013b7WaS4t5lUKjHJKJALyMlg==',
    b'LsriyazGHs06tMujKcDSKfvg1cmDgV3ml2Gx0qA5m0AAl5W4T3c3Z1kGdOrAeG632oX/aTGOpja1f85pmlj32QrNqdWT56cyTrj40c5ougHIhpJjaiML0cc3k0LeGMjSZtlznUCLSyKgZJaa2tHBFSsY2kODwtNlpBQf+IWE73NceQaNaQ310mbmV7u+z1nK+zq1ij3dsEloprQujR9WRYzQZIDtti87iIaLe4tb9XXbEZ0eREx9tfDP1QCEzuzaC5txnghX4bR6lMgporzp/5Rk2cq1C2HVQZuz0rBRdfMfRdC/nLLTzo/JveS4btnk3aGt4KPw7WKea3hzErxNBw==',
    b'bFWuwPKVYnjRuxYGATyZvTA1XNFAmjjtBpp9be0y0JNFD+Zd/XvJyYTPgJbhqxhc8+aeXs3iT66a+oxplWpS/T0T0FmLVAccLdwYi7hESfg7F4RZJbyLSDKTUkslPTF87PjoJr579lxMflutx6shvkAZm10p7KbCHf20VOcmCK/AaTAvf10/HBo4Ex4Z767fMAnjVRK65fQBE6/7cPzSCXg3L37NTeiv1WHoaGv2Xx6+GbkxyZikYb7ZAVL+w5Log9l+3HvILYWCNHPSwUnnszaoqwzoTmwDrUkARd8L2z0YS3DUQJUO3Q2+mVGj6+y4fe+SGGq13VRP/0uy/KNyoQ==',
    b'IQHoYovLnFq8J+1qmB8ZQhaYsx99RKfKYnjmIsjPgdcGeQAQM8jqN5T9xYr+XNDQkZCGVhLpigQ00FGTi+lPnx7RJUOGqtrY6bZBrGO4xmZb0MdfKc1BdQQnLLUYkOwow86Y3pSUM0047wPOkDroqiippjrI8UDkya1lDruEihawdGIlVSYwrUfRUGUR6nxQmGOuyQB7fj+MhCRy2MNh/hu7lnfzTTCkHK2b25cjRGDa1p/ePajzuyQGbkf5fF5yybViYiS5lA9DG7Y3GMH76BD05lwbWsfFTvJmP3+XoHD3N4ZGzEZydHJbnnvE8rXW1QYogJAy+HWdQdETt7smJg==',
    b'd1rZcRrhJHADTdxVpX3ij+/F5/jsCq5I/XEy4b5CR8I7XQBuOKhHn9YS5dUKPEQeIZUphiTdrQNJwn/pp4qlDJJtODcAN82vB6CR0DORp7zPXCiLuW1aa7/THccfFRGGOP44jdcRoWDSb335IwY28Ubl886RUOEAV68Q7xzt4GtsZujr7Cf9sXfvPO+MTgBMAcecJRirqa6UoWfuRZGf0LXSwozynO+skJRZhpJuR9lq1/yEL2Dgx8ycl145EgmMrYkIbfm53SD/QH9tYYYILRl7rbq44M1emNtL2GIImNBmu9d20HpJgtDw9794sNqCtXE4zdqS0DmeYcsF7SEMxQ=='
]
# ciphers as hex bytes
hex_ciphers = [base64.b64decode(i) for i in ciphers]
print(hex_ciphers)

# Cryptodome block
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# get the key
f = open('secret_key.pem','r')
key = RSA.import_key(f.read())

decryptor = PKCS1_OAEP.new(key)
#decrypted = decryptor.decrypt(encrypted)


for i in hex_ciphers:
    try:
        decrypted = decryptor.decrypt(i)
        print(decrypted)
        break
    except:
        pass

# b'I love cryptography still'



# Signatures
messages = [
    {'text':b'The code is uehqn', 'signature':b'IZceGm/mkewdAeS3wc+Qhk4L/55lRe9L2NwUSH2o0wSDnDnKnSMDQon+bLLnl6pvUtEhpjZoDGvC26TMRg2dXCDZiocNnFPMbBSa6nc+4yaDkbxtHWEhuXk3rOtbHagr8MQzuKBK0CJeZ13i+iMN7OLVpTsCxNpP9Fx96I8t1OtNAZq4yIz2f0MmAvDMdqDSnuX40RIzq11La8xuJPuCO872Y3eBFyPWFMxbpghTtlCQqcdyIy3EmBbnskA4Gw077TzKZJ5V5ntUYdVercSpJ9Ax0mDd/xmYFTmUHmb973NvIzlf//IJ/Q0IDdQObEvB2cVQpqeCxABpsCfxxJiBPA=='},
    {'text':b'The code is rplps', 'signature':b'fcch/RNP8K+Hqe7ORB6f58gAnPhA8kz35j33MqvxGz72YpQdQXicPCWYcAkqs6nM0tQ55mNqhMta+RSGtsYMFndpriKTZRXngPHS+CpFbNhIonQll+7zmPZXkEdNoB5TcdS7vkt26j+xn1u6mlCQgctZFa1RcXLZewkfsoofNt3e/1mqoE9MqZdpNgt+od8RQ7eKNMTrzQuTeabpCWcCgW12gBFoGRNG/cBUZKeskxwM264aaCgzgijcUCxEaN9lJDUvSmTDtncWlVoFt3vN8A8DXUzDUMOLb7sZca7p5U/aiJ7g0LDetzjK9IDWGAVqUa5rLBUGiX5B5uXcg95yrg=='},
    {'text':b'The code is zhijc', 'signature':b'Fwv9XATss7knUy+nyUU05E9bJS6zgd4cPMn7hbT/7mhl+hV7l9LP0A9ZJTNVwX1Z5tW+IrCPyPDFROtjmsGFmqBD5nmbDXp6YIZnn1atBG6mnlUQZ4F5Ph+vvvQUyB21r0fWWQ4m4U96V/SQ+/FK08NYj8qYplibZqXgKkszAF6dwIJhAZ8KVM8l8LY6djI5vghhtvd/RZuyig6PAqx5iY9nB/je1IZO3ntIUp+LfuIcHS5X6Vcc40okWAsQd8mDYzftvYUJnkcnxjfPUxgcJoyChC50psfo1LaUqsWRu2Ck0fC5DjiKj4tePf2sjenib9D3Wc8xuLkS6IyTQQeAyg=='},
    {'text':b'The code is ylaqd', 'signature':b'IL7oELlFaFr8FqOPc/1n3ATZufVsJFW47CGHpJu+zfp1K0YeOwWthw31MEAFMAXqg0DRbR14VEly2LE2MQxqLGjbf+cZE9aNBrck7GDtFeRz9G3gGysHanz9NoM55YbR56Fs+olj7BDxUnaF51wCpliUG+kNr8ApfxT0h5Nd8+4DIAp1rhzovrg7WZXPeOGE6h/orpizlbj331WGhKvimUGKjMannwdOtTnuU7ht5UGnZWIDs0TsXGK1Bn6a6ZcgNu5gl7emk1IbR3LwnJLOI//xj3t6RWKinDHdzwmaWrfwjky/UrFMMs54qgJWmGHB9hpEHcbHLJ1LvJwKOUDuqg=='},
    {'text':b'The code is bvxie', 'signature':b'pYjvtm2Ibjzvz5x1zmsHk60yIakkwXOJ2957auW2IAS2TRnsRTBSSSOhZdN9gixVL6YfpCs7AhgPS4u+ZLX+Y5sZIpr3FZHzRU7WGboYqxBWa8sOSXmOj+4B9v+r+A9mBAtHobdVIUmAd/FmHH9jHqSyGXRJw38mjkOlENTmjdwwKzPKCMcpCpVEHx9DzxzR4ELNtk5HtgRbBnjSxXJDND6kA45/IbcvPdznTIO42p+4J1tlKXKp283Wwlg7g02gSiboM+cVyt3kMjuOTYKG+DIIDcQObzgY3W6fWRVSGSIZaaOdR54ll6Kn79zG8W6nUjxUIZ9i1OMfT5G08zBfLg=='}
]

# get the pub key
f = open('my_friend_key.pub','r')
pubkey = RSA.import_key(f.read())


from hashlib import sha512

def bytes2binary(b):
    bb=int.from_bytes(b, byteorder='big')
    bb = bin(bb)[2:]
    target_length = len(bb) + (8 - len(bb) % 8) % 8
    
    # Solve and exception
    j = 0
    while b[j]==0:
        target_length =target_length+8
        j+=1
    return bb.zfill(target_length)

# RSA verify signature
for i in range(5):
    msg = messages[i]['text']
    hashh = int.from_bytes(sha512(msg).digest(), byteorder='big')
    hashFromSignature = pow(int(bytes2binary(base64.b64decode(messages[i]['signature'])),2), pubkey.e, pubkey.n)
    if hashh == hashFromSignature:
        print(msg)
        break
# b'The code is zhijc'



