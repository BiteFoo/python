# -*- coding:UTF-8 -*-
'''
Created on 2017��11��20��

@author: John.Lu
'''

# method_id_item
class DexMethodIdx(object):

    def __init__(self):
        self.class_idx = 0
        self.proto_idx = 0
        self.name_idx = 0


# encoded_method 
class DexMethod(object):

	def __init__(self):

		self.method_idx=0 #-->MethodIdx 
		self.access_flags=0  #方法额访问权限
		self.code_off=0 # 指向DexCode对象，code_item字段






