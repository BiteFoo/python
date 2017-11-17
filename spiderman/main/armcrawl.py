# -*- coding:UTF-8 -*-
import urllib
import sys
import os
import itertools
import time

def getsystem_tiem():
    '''
    获取系统时间
    '''
    return  time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

def gener_8_num():
    return itertools.product('0123456789', '0123456789', '0123456789', '0123456789','0123456789', '0123456789', '0123456789', '0123456789') 

class Spider(object):
    '''
    spider
    '''
    def __init__(self):
        self.indexs =[1,2,3]
        self.armpdf_url ="http://bear.ces.cwru.edu/eecs_382/ARM7-TDMI-manual-pt%d.pdf"
        self.urls =set()
        pass
    def parsehtml(self):
        pass
    def progrss(self,a,b,c):
        '''
        下载进度函数，a,b,c就是默认的，由ullib.urlretrieve(url,filepath,progress)
        progress表示一个函数，fun,只要提供即可
        '''
        per = 100.0 * a*b /c
        if per > 100:
            per = 100
        if per == 100:
            print ("dowload finished 100%")
        print ("downloading : %.2f%% " %per)
    def geturls(self):
        self.urls=[self.armpdf_url %(idx)  for idx in self.indexs]
        return  self.urls
    def is_valid(self):
        return False if self.urls == None or self.urls.__len__() <=0 else True
    def download(self):
        self.local_path = sys.path[0]+os.sep+"ARM7-TDMI-manual"
        if not os.path.isdir(self.local_path):
            os.makedirs(self.local_path)
        count =0
        for url in self.urls:
            try:
                filename = url[url.rfind('/') +1:]
                print ("downloading {}  {} file ".format(count,filename))
                filepath = self.local_path+os.sep+filename
                urllib.urlretrieve(url,filepath,self.progrss)
                count +=1
            except :
                print ("{} is invalid".format(url))
    def get_download_dir(self):
        return self.local_path       
spider = Spider()
spider.geturls()
if  spider.is_valid():
    spider.download()
print ("file has save to local :{} ".format(spider.get_download_dir()))
    