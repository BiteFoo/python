# -*- coding:UTF-8 -*-
import zipfile
import os
import sys
apk = sys.path[0]+os.sep+"apk"+os.sep+"100comnanjingzqdzh8202017.apk"
print ("apk  ={} ".format(apk))
def unzip(file):
    if not os.path.isfile(file):
        print ("not file")
        return
    zip_entry =  zipfile.ZipFile(file,'r')
    for name in zip_entry.namelist():
        print ("name = {}".format(name))
        if name =='META-INF/CERT.RSA':
            print ("found sign information")
            break
unzip(apk)



    
    




