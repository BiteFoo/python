##2018-04-25
基础功能包括：
根据dexheader读取class_defs数据，输出方法和指令，如下
------------------------------------------------------
解析dex文件内容
class string  idx  b'LMyHide;'
###*******************************
method idx: 0
short_class_idx： b'LMyHide;'
name_idx b'<init>'
name_idx idx: 0
==============================
method idx: 1
short_class_idx： b'LMyHide;'
name_idx b'hello'
name_idx idx: 5
==============================
method idx: 2
short_class_idx： b'LMyHide;'
name_idx b'showMe'
name_idx idx: 6
all class: 1
cost time: 0.0005009174346923828


#2018-04-26
解析分为：
##1、实体类，具体如下。
这里测试中，方法体没有具体的指令
public class MyHide
{

public static void hello(){
	

}

private void showMe(){



}
}
解析后，程序的构造函数，hello，showMe全部本解析成了directMethod


##2、给MyHide添加方法，方法添加参数
主要添加了 public int volumes(int agrs[])，public static int getSum(int a,int b)
两个方法，其中volumes被解析为了virtualMethod，getSum被解析为了directMethod
##******************************
public class MyHide
{

public static void hello(){
	

}

private void showMe(){

}
##多参数
public int volumes(int agrs[]){
		return 20;
}
##两个参数

public static int getSum(int a,int b)
{
	return a+b;
}
}
##------------------
通过解析，发现volumes方法被编码为了virtualMethod，如下
method idx: 4
short_class_name： b'LMyHide;'
method_name b'volumes'
DexMethodProto,idx: 1
method_proto_name: b'IL'
returnty_value: b'I'



###需要注意过滤的类
com.fortiguard.hideandseek.R$attr
com.fortiguard.hideandseek.R$drawable
com.fortiguard.hideandseek.R$id
com.fortiguard.hideandseek.R$layout
com.fortiguard.hideandseek.R$string
com.fortiguard.hideandseek.R
com.fortiguard.hideandseek.BuildConfig

