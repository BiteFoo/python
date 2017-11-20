#-*- coding:UTF-8 -*-
'''
Created on 2017年11月20日

@author: John.Lu
'''
class ProtoParameter(object):
    '''
    方法参数对象，主要保存方法的参数值
    '''
    def __init__(self):
        self.shorty_idx=0 
        self.return_type_idx=0
        self.parameter_type_offset =0
        pass
    
