import sha3
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from easygui import * 
from ctypes import sizeof
from scipy import ndimage
import cv2
import math 
from math import gcd as bltin_gcd
import random
import numpy as np
np.seterr(over='ignore')

def getRandom(inputVideo):

    first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67,
                     71, 73, 79, 83, 89, 97, 101, 103,
                     107, 109, 113, 127, 131, 137, 139,
                     149, 151, 157, 163, 167, 173, 179,
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]
 
    def isMillerRabinPassed(mrc):
        maxDivisionsByTwo = 0
        ec = mrc-1
        while ec % 2 == 0:
            ec >>= 1
            maxDivisionsByTwo += 1
        assert(2**maxDivisionsByTwo * ec == mrc-1)
        def trialComposite(round_tester):
            if pow(round_tester, ec, mrc) == 1:
                return False
            for i in range(maxDivisionsByTwo):
                if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                    return False
            return True
        numberOfRabinTrials = 20
        for i in range(numberOfRabinTrials):
            round_tester = random.randrange(2, mrc)
            if trialComposite(round_tester):
                return False
        return True
    def getBase(n):
        return 2**(n-1)+1
    def getTopBase(n):
        return 2**n - 1
    #Get R, G, B from igm 
    def R(x, y, img):
        return img[y, x, 2]
    def G(x, y, img):
        return img[y, x, 1]
    def B(x, y, img):
        return img[y, x, 0]
    #Generte color of x, y from img
    def getColor(x, y, img):
        return (R(x, y, img) << 16) + (G(x, y, img)  << 8) + B(x, y, img) 
        
    firstBase = getBase(512)
    secondBase = getTopBase(512)

    firstPrime = 0 
    secondPrime = 0

    firstPrimeFlag = False
    secondPrimeFlag = False

    source = inputVideo
    #Read video
    vidcap = cv2.VideoCapture(source)
    fps = int(vidcap.get(cv2.CAP_PROP_FPS))
    #Get frame
    success, image = vidcap.read()
    #Get frame dimensions
    height = image.shape[0]
    width = image.shape[1]

    x_c = round(height/2)
    y_c = round(width/2)

    color_i = (getColor(x_c-1, y_c-1, image) + getColor(x_c-1, y_c, image) + getColor(x_c-1, y_c+1, image) + getColor(x_c, y_c-1, image) + getColor(x_c, y_c+1, image) + getColor(x_c+1, y_c-1, image) + getColor(x_c+1, y_c, image) + getColor(x_c+1, y_c+1, image) + getColor(x_c, y_c, image))/9

    vidcap.set(1, fps*3)
    success, image_3rd_second = vidcap.read()
    vt = math.sqrt(ndimage.variance(image_3rd_second))
    th = 100
    watchdog = 0

    R_1 = 0
    G_1 = 0
    B_1 = 0
    frameDiscardFlag = False
    outputR = 0
    outputG = 0
    outputB = 0
    buforR = ''
    buforG = ''
    buforB = ''
    vidcap.set(1, 0)
    bitCounter = 0
    byteCounter = 0

    x = round((color_i)%(width/2)+(width/4))
    y = round((color_i)%(height/2)+(height/4))

    while 1:
        success, image = vidcap.read()
    
        #Check if file not ended
        if(not success):
            break
        #set coords
        while 1:
            R = image[y, x, 2]
            G = image[y, x, 1]
            B = image[y, x, 0]
            if((R-R_1)**2 + (G-G_1)**2 + (B - B_1) ** 2 < vt):
                watchdog += 1
                x = (x+(R^G)+1)%width
                y = (y+(R^G)+1)%height
                if(watchdog > th):
                    frameDiscardFlag = True
                    break
            else: 
                break
        if(frameDiscardFlag):
            frameDiscardFlag = False
            continue
        

        outputR = R%2
        outputG = G%2
        outputB = B%2


        R_1 = R
        G_1 = G
        B_1 = B 
        x = (((R^x) << 4)^(G^y))%width
        y = (((G^x) << 4)^(B^y))%height

        buforR += str(outputR)
        buforG += str(outputG)
        buforB += str(outputB)
        bitCounter += 1

        if(bitCounter > 7):

            if(not firstPrimeFlag):
                firstBase += int(buforB, 2)
                for divisor in first_primes_list:
                    if firstBase % divisor == 0 and divisor**2 <= firstBase:
                        break
                if isMillerRabinPassed(firstBase): 
                    firstPrime = firstBase
                    firstPrimeFlag = True
            
            if(not secondPrimeFlag):
                secondBase -= int(buforG, 2)
                for divisor in first_primes_list:
                    if secondBase % divisor == 0 and divisor**2 <= secondBase:
                        break
                if isMillerRabinPassed(secondBase): 
                    secondPrime = secondBase
                    secondPrimeFlag = True
            
            if(firstPrimeFlag and secondPrimeFlag): break

            buforR = ''
            buforG = ''
            buforB = ''
            byteCounter += 1
            bitCounter = 0 

    return(firstPrime, secondPrime)
 
def getSHA3(filename):
    f = open(filename, "rb")
    return sha3.sha3_224(f.read()).hexdigest()

def sideSender():
    def rsakeys(inputVideo):  
        
        def notcoprime2(a, b):
            return bltin_gcd(a, b) != 1

        #Return private key and save public key to directory
        p, q = getRandom(inputVideo)
        n = p*q
        lcm = math.lcm(p-1, q-1)
        i = lcm-1
        while(notcoprime2(i, lcm)):
            i -= 1
        e = i
        d = pow(e, -1, lcm)
        privatekey = RSA.construct((n, e, d ))
        publickey = privatekey.publickey()  
        f = open('publickey.pem','wb')
        f.write(publickey.export_key('PEM'))
        f.close()
        return privatekey

    fieldNames = ["Filename:", "Video filename:"]
    filename, inputVideo = multenterbox("Enter details of files to sign", "", fieldNames)

    print("Please wait, generating keys")

    priv_k = rsakeys(inputVideo)
    file = open(filename, "rb")
    h = SHA256.new(file.read())
    val = pkcs1_15.new(priv_k).sign(h)

    with open("signature.txt", 'wb+') as f:
        f.write(val)
    msgbox("Generated publickey.pem and signature.txt", "")
    

def sideReceiver():
    filename = ''
    publickey = ''
    signature = ''
    
    fieldNames = ["Original filename:","Public key filename:", "Signature filename:"]
    filename, publickey, signature = multenterbox("Enter details of files to verify", "", fieldNames)

    file = open(filename, "rb")
    key = open(publickey, 'rb')
    key = RSA.importKey(key.read())
    sig = open(signature, 'rb').read()
    try:
        pkcs1_15.new(key).verify(SHA256.new(file.read()), sig)
        msgbox("File is valid", "")
    except (ValueError, TypeError):
        msgbox("File is not valid", "")

msg = "Select side"
title = "Encryptonator"
choices=['Sender','Receiver']
choice=buttonbox(msg, title,choices)
if choice=='Sender':
    sideSender()
elif choice=='Receiver':
    sideReceiver()

