﻿========================================================================
MICROSOFT 基础类库：mycrypt 项目概述
========================================================================


应用程序向导已为您创建了此 mycrypt DLL。此 DLL 不仅
演示了 Microsoft 基础类的基本使用方法，还可
作为您编写 DLL 的起点。

此文件概述了组成 mycrypt DLL 的每个文件
的内容。

mycrypt.vcproj
这是使用应用程序向导生成的 VC++ 项目的主项目文件。 
它包含有关生成该文件所使用的 Visual C++ 版本的信息，以及
有关在应用程序向导中选择的平台、配置和项目功能
的信息。

_mycrypt.h
这是 DLL 的主头文件。它声明
CmycryptApp 类。

mycrypt.cpp
这是主 DLL 源文件。它包含类 CmycryptApp。


mycryptppc.rc
这是项目使用的所有 Microsoft Windows 资源的清单
（当针对 Pocket PC 平台或
支持相同的用户界面模型的平台进行编译时）。它包括
存储在 RES 子目录中的图标、位图和光标。如果
.rc 文件保持不变，数据节中的
将作为定义将保持为它们所定义为的数值的十六进制版本，
而不是定义的友好名称。



res\mycrypt.rc2
此文件包含不由 Microsoft 
Visual C++ 编辑的资源。您应将所有无法由资源编辑器编辑的资源
放置到此文件中。

mycrypt.def
此文件包含关于在 Microsoft Windows 上运行所必需
的 DLL 的信息。它定义此 DLL 的
名称和说明等参数。它还从
此 DLL 导出函数。

/////////////////////////////////////////////////////////////////////////////
其他标准文件：

StdAfx.h，StdAfx.cpp
这些文件用于生成名为 mycrypt.pch 的预编译头 (PCH) 文件
和名为 StdAfx.obj 的预编译类型文件。


resourceppc.h
这是标准头文件，它定义新的资源 ID。
Microsoft Visual C++ 读取并更新此文件。



/////////////////////////////////////////////////////////////////////////////
其他注释：

应用程序向导使用“TODO:”指示应添加到或自定义的源代码部分。
应添加或自定义的源代码部分。

/////////////////////////////////////////////////////////////////////////////