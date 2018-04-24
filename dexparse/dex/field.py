# -*- coding:UTF-8 -*-
'''
Created on 2017��11��20��

@author: John.Lu
'''


class FieldIdx(object):

    def __init__(self):
        self.class_idx = 0  # 指向了type_list的索引号
        self.type_idx = 0  # 指向了type_list的索引号
        self.name_idx = 0  # 指向了string_list的索引号

    def to_string(self):
        print('[DEBUG]:field_idx')
