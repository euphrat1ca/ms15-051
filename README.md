# ms15-051修正版zcgonvh

加上了对2003的支持，又精简了部分代码，加上了ntdll.lib库，最后支持在webshell下运行。
原始代码即使编译成2003兼容的格式在03上也是不能执行的，因为win7以下的系统没有导出user32!gSharedInfo，只能解析pdb或者搜索特征码来定位；另外不同系统的EPROCESS->Token偏移也有所不同，这些修改在工程内已经添加了。
工程是vs2010的源码，能直接编译。工程内附带两个编译好的exp，在2003 64位和32位上均测试成功。我测试用的虚拟机版本是sp2，不保证其他版本能用。
如果发现某个版本不能用的话，把版本号告诉我吧，我再修改(能带着对应版本的系统镜像下载地址就最好不过了)。
这个漏洞是不影响win8及以上版本的，所以只能做到这些了。

from:91ri.org
在aspxspy中执行是没有问题的，菜刀的asp马可以用下面这个脚本：
set x=createobject("wscript.shell").exec("c:\inetpub\wwwroot\ms15-051.exe ""whoami /all""")
response.write (x.stdout.readall & x.stderr.readall)