# Hephaestus-terminal-management :desktop_computer:



### :imp: A security tool for enterprise terminal management that named Hephaestus



[![GitHub License](https://camo.githubusercontent.com/121a40339f64c2ce6524c5bf411844bb4d2deb58058db72b9b25e5dab0c03410/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f6c6963656e73652f7469616e6e2f4b65726e656c53553f6c6f676f3d676e75)](https://github.com/tiann/KernelSU/blob/main/LICENSE)



## :eight_pointed_black_star: 特性

- #### 基于Windows内核框架实现核心功能

  

## :yum: 兼容状态

#### 支持Windows10 1909以上Windows 10 系统，但是需要注意，禁用调试功能由于使用硬编码（Windows 10 21H2）需要自行修改兼容



## :card_index_dividers:  目录结构

```js
├─ControlClient           通信控制端
├─FilterMessager        minifilter通信进程
├─HFTSRESETPWD      修改密码web服务
│  ├─.hbuilderx     
│  ├─node_modules
│  │  └─crypto-js
│  │      └─docs
│  ├─pages
│  │  └─index
│  ├─static
│  ├─uniCloud-aliyun
│  │  └─cloudfunctions
│  │      └─resetpwd
│  │          └─node_modules
│  │              ├─bignumber.js
│  │              │  └─doc
│  │              ├─core-util-is
│  │              │  └─lib
│  │              ├─inherits
│  │              ├─isarray
│  │              ├─jsencrypt
│  │              │  ├─bin
│  │              │  └─lib
│  │              │      └─lib
│  │              │          ├─asn1js
│  │              │          ├─jsbn
│  │              │          └─jsrsasign
│  │              ├─mysql
│  │              │  └─lib
│  │              │      └─protocol
│  │              │          ├─constants
│  │              │          ├─packets
│  │              │          └─sequences
│  │              ├─process-nextick-args
│  │              ├─readable-stream
│  │              │  ├─doc
│  │              │  │  └─wg-meetings
│  │              │  └─lib
│  │              │      └─internal
│  │              │          └─streams
│  │              ├─safe-buffer
│  │              ├─sqlstring
│  │              │  └─lib
│  │              ├─string_decoder
│  │              │  └─lib
│  │              └─util-deprecate
│  └─unpackage
│      └─dist
│          └─build
│              ├─.automator
│              │  └─h5
│              └─h5
│                  └─static
│                      ├─img
│                      └─js
├─jsoncppinclude       json库
│  └─json
├─jsoncpplib               json静态库
├─Minifiltertest           文件过滤驱动
├─MouseFlt                 鼠标过滤驱动
├─NetFlt                       网络过滤驱动
├─ProjectExe               已废弃
├─ProtecExeForE        服务端
├─RegFltMessager      注册表保护通信进程
├─RegistryFilter 	 注册表保护驱动 
├─WpdFlt                     便携式设备过滤
├─yara			 YARA扫描引擎
│  ├─bazel
│  ├─cli
│  ├─dist
│  ├─docs
│  │  └─modules
│  ├─extra
│  │  └─codemirror
│  ├─libyara
│  │  ├─include
│  │  │  ├─authenticode-parser
│  │  │  ├─tlshc
│  │  │  └─yara
│  │  ├─modules
│  │  │  ├─console
│  │  │  ├─cuckoo
│  │  │  ├─demo
│  │  │  ├─dex
│  │  │  ├─dotnet
│  │  │  ├─elf
│  │  │  ├─hash
│  │  │  ├─macho
│  │  │  ├─magic
│  │  │  ├─math
│  │  │  ├─pb_tests
│  │  │  ├─pe
│  │  │  │  └─authenticode-parser
│  │  │  ├─string
│  │  │  ├─tests
│  │  │  └─time
│  │  ├─pb
│  │  ├─proc
│  │  └─tlshc
│  ├─m4
│  ├─sandbox
│  ├─tests
│  │  ├─data
│  │  │  └─include
│  │  └─oss-fuzz
│  │      ├─dex_fuzzer_corpus
│  │      ├─dotnet_fuzzer_corpus
│  │      ├─elf_fuzzer_corpus
│  │      ├─macho_fuzzer_corpus
│  │      ├─pe_fuzzer_corpus
│  │      └─rules_fuzzer_corpus
│  └─windows
│      ├─libyara
│      │  ├─modules
│      │  │  ├─console
│      │  │  ├─cuckoo
│      │  │  ├─dex
│      │  │  ├─dotnet
│      │  │  ├─elf
│      │  │  ├─hash
│      │  │  ├─macho
│      │  │  ├─math
│      │  │  ├─pe
│      │  │  │  └─authenticode-parser
│      │  │  ├─string
│      │  │  ├─tests
│      │  │  └─time
│      │  ├─proc
│      │  └─tlshc
│      ├─vs2015
│      │  ├─libyara
│      │  ├─test-alignment
│      │  │  └─x64
│      │  │      └─Release
│      │  │          └─test-alignment.tlog
│      │  ├─yara
│      │  └─yarac
│      ├─vs2017
│      │  ├─libyara
│      │  ├─yara
│      │  └─yarac
│      └─vs2019
│          ├─libyara
│          │  ├─Debug
│          │  │  └─libyara.tlog
│          │  └─Release
│          │      └─libyara.tlog
│          ├─packages
│          │  ├─YARA.Jansson.x64.1.1.0
│          │  │  ├─include
│          │  │  └─lib
│          │  ├─YARA.Jansson.x86.1.1.0
│          │  │  ├─include
│          │  │  └─lib
│          │  ├─YARA.OpenSSL.x64.1.1.1
│          │  │  ├─include
│          │  │  │  └─openssl
│          │  │  └─lib
│          │  └─YARA.OpenSSL.x86.1.1.1
│          │      ├─include
│          │      │  └─openssl
│          │      └─lib
│          ├─Release
│          ├─yara
│          │  ├─Debug
│          │  │  └─yara.tlog
│          │  └─Release
│          │      └─yara.tlog
│          └─yarac
│              └─Release
│                  └─yarac.tlog
└─yararules                         		 	 YARA扫描规则
    ├─antidebug_antivm
    ├─capabilities
    ├─crypto
    ├─cve_rules
    ├─deprecated
    │  ├─Android
    │  └─Malware
    ├─email
    │  └─eml
    ├─exploit_kits
    ├─maldocs
    ├─malware
    │  └─Operation_Blockbuster
    ├─mobile_malware
    ├─packers
    ├─utils
    │  └─yara-forensics
    └─webshells
```



## :loudspeaker: 构建方法



### Windows 11

1. #### 下载Visual Studio 2022开发工具（[Visual Studio 2022 IDE - 适用于软件开发人员的编程工具 (microsoft.com)](https://visualstudio.microsoft.com/zh-hans/vs/)），勾选所有适用于C/C++的桌面开发开始下载

2. #### 下载WDK最新版（[以前的 WDK 版本和其他下载 - Windows drivers | Microsoft Learn](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/other-wdk-downloads)）

3. #### 使用Visual Studio 2022打开ControlClient.sln

   

### Windows 10

1. #### 下载Visual Studio 2019开发工具（[[Visual Studio 较旧的下载 - 2019、2017、2015 和以前的版本 (microsoft.com)](https://visualstudio.microsoft.com/zh-hans/vs/older-downloads/)](https://visualstudio.microsoft.com/zh-hans/vs/)），勾选所有适用于C/C++的桌面开发开始下载

2. #### 下载WDK Windows 10 版本 2004 ([以前的 WDK 版本和其他下载 - Windows drivers | Microsoft Learn](https://learn.microsoft.com/zh-cn/windows-hardware/drivers/other-wdk-downloads))

3. #### 使用Visual Studio 2019打开ControlClient.sln



### 通用

- #### 使用HBuilder X导入HFTSRESETPWD，关联阿里云开发环境

- #### 使用易语言开发工具导入ProtecExeForE

- #### 数据库`CREATE DATABASE IF NOT EXISTS userdata;`

- #### 数据库

  ```sql
  CREATE TABLE IF NOT EXISTS userdata.users (
      uname VARCHAR(128) NOT NULL,
      password VARCHAR(128) NOT NULL,
      email VARCHAR(128) NOT NULL,
      checkcode VARCHAR(128) NOT NULL,
      PRIMARY KEY (uname)
  );
  
  ```



## :kick_scooter: 使用

1. #### ControlClient.sln生成文件全部放同一目录，管理员运行HPTSCore.exe

2. #### 运行服务端



## :thinking: 讨论

#### 点击链接加入QQ频道【Hephaestus】：https://pd.qq.com/s/dvii76n34



## :shield: 安全性

- #### 服务端存在SQL漏洞，原因是在服务端中写定了sql连接和查询过程，攻击者可以利用hook等技术替换查询语句实现攻击



## :bell: 许可证

#### 所有文件均为 [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)



## :handshake: 鸣谢

#### YARA([VirusTotal/yara: The pattern matching swiss knife (github.com)](https://github.com/VirusTotal/yara)):YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples.



#### InfinityHookPro-main([[DearXiaoGui/InfinityHookPro-main (github.com)](https://github.com/DearXiaoGui/InfinityHookPro-main)):此项目基于 https://github.com/FiYHer/InfinityHookPro 原作者只支持虚拟机 在原作者的基础上新增了支持物理机 目前支持Win7-Win11 支持win11 任何版本

