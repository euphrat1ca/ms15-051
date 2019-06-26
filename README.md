# MS15-051简介
Windows 内核模式驱动程序中的漏洞可能允许特权提升 (3057191) ， 如果攻击者在本地登录并可以在内核模式下运行任意代码，最严重的漏洞可能允许特权提升。 攻击者可随后安装程序；查看、更改或删除数据；或者创建拥有完全用户权限的新帐户。 攻击者必须拥有有效的登录凭据并能本地登录才能利用此漏洞。 远程或匿名用户无法利用此漏洞。

# 官方表示该漏洞影响的操作系统有
Windows Server 2003，Windows Vista，Windows Server 2008，Windows Server 2008 R2  等

# ms15-051修正版zcgonvh
    加上了对2003的支持，又精简了部分代码，加上了ntdll.lib库，最后支持在webshell下运行。
原始代码即使编译成2003兼容的格式在03上也是不能执行的，因为win7以下的系统没有导出user32!gSharedInfo，只能解析pdb或者搜索特征码来定位；另外不同系统的EPROCESS->Token偏移也有所不同，这些修改在工程内已经添加了。
    工程是vs2010的源码，能直接编译。工程内附带两个编译好的exp，在2003 64位和32位上均测试成功。我测试用的虚拟机版本是sp2，不保证其他版本能用。如果发现某个版本不能用的话，把版本号告诉我吧，我再修改(能带着对应版本的系统镜像下载地址就最好不过了)。
这个漏洞是不影响win8及以上版本的，所以只能做到这些了。
注意：附件中的exe用菜刀执行的话取不到回显，实际上命令已经执行了（如果输出了pid的话）。

# from:91ri.org
在aspxspy中执行是没有问题的，菜刀的asp马可以用下面这个脚本：
```
set x=createobject("wscript.shell").exec("c:\inetpub\wwwroot\ms15-051.exe ""whoami /all""")
response.write (x.stdout.readall & x.stderr.readall)
```