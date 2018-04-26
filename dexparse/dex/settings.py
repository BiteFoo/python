# -*- coding:utf-8 -*-

# 需要配置的过滤的apk名称，后续的改进会读取xml文件，读取包名或者是入口的activity的包名
packg_name = ''#'com.fortiguard.hideandseek'

###需要过滤的累心
need_filter_classes = [
    '.R$attr',
    '.R$drawable',
    '.R$id',
    '.R$layout',
    '.R$string',
    '.R',
    '.BuildConfig'
]
