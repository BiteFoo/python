# -*- coding:UTF-8 -*-

'''

 note:
 In this pattern ,all of u4 type was uleb128,so ,we had to transform it when using ClassDefs's item
'''
class ClassDefs(object):
    def __init__(self):
        self.class_idx =0 #-->type_idx
        self.access_flag =0
        self.superclass_idx=0#-->type_idx
        self.interface_offset =0 #-->type_list
        self.source_file_idx =0 #-->strin_ids_list
        self.annotation_idx_off =0 #-->
        self.class_data_off =0 #-->class_data_item
        self.static_value_offset =0
    def tostring(self):
        print('[DEBUG]:class_idx={} , access_flag = {} ,superclass_idx ={} '
              +'interface_offset = {} ,source_file_idx ={}  '
              +'class_data_off ={} , static_value_offset ={}'.format(hex(self.class_idx),hex(self.access_flag)
                                                                     ,hex(self.superclass_idx),hex(self.interface_offset),
                                                                     hex(self.source_file_idx),hex(self.class_data_off),
                                                                     hex(self.static_value_offset)
                                                                     )
              )


class DexMethod(object):
    def __init__(self):
        self.method_idx =0
        self.access_flags =0
        self.code_off =0

class DexField(object):
    def __init__(self):
        self.field_idx =0
        self.access_flags =0

class DexClassDataHeader(object):
    def __init__(self):
        self.static_fileds_size=0
        self.instance_fileds_size=0
        self.direct_methods_size =0
        self.virtual_methods_size=0

class ClassDataItem(object):
    def __init__(self):
        self.dex_class_data_header_off=0 #-->DexClassDataHeader
        self.dex_static_field_idx =0 #-->DexField
        self.dex_instance_field_idx =0 #-->DexField
        self.dex_direct_methods=0 #-->DexMethod
        self.dex_virtual_methods =0 #-->DexMethod
