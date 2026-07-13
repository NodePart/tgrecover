# TGRecover
---
 有人给你发了一条秘密信息，但后来又删除了？让我们恢复它！
---

一个针对于Telegram软件的信息恢复取证工具，即使内容被删除。

它仍可以在缓存中寻找到这条信息并恢复！

## 使用须知

运行 `recover.py` 前，你需要先安装必要的依赖，才能保证项目正常工作

```
python3 -m pip install -r requirements.txt
```

音/视频，图片恢复需要 `ffmpeg` 的相关支持用于转换和生成，安装命令如下

```
macOS:        brew install ffmpeg
Debian/Ubuntu: sudo apt install ffmpeg
Windows:      install ffmpeg and add its bin directory to PATH
```

这个脚本基本上是不能用于恢复 `Secret Chat（加密对话）` 的相关内容。
- 这并不是道德问题造成的，这是因为脚本只读来自 `Telegram Desktop` 下的 `tdata` 的本地缓存文件，并没有指向 `Secret Chat` 消息数据库解析器，即便是代码指向了其对应的解析器也不能绕过 `Secret Chat` 的端到端加密，是无法实现的。

这个脚本恢复 `闪照 / 阅后即焚图片视频 / 撤回的文本信息` 非常困难，但并不是不可能
- Telegram 在设计其闪照和撤回文本消息原理为自动清除其对应缓存，一旦缓存被清除将无法访问，是难以被获取的。但在特殊情况下 **Telegram 可能会意外留存**。不代表能100%恢复
- 推荐使用相关 `第三方/防撤回` 插件来替代

脚本并不能 **完全恢复** 所有命令下包含的文件。脚本在恢复某些东西的时候请确保：
- Telegram 不要退出
- 你必须读了这个文件/曾下载了这个文件（Telegram信息打勾提示/曾经下载过这个文件）
- 不要清理缓存
才能正常工作和更准确的恢复效果

## 使用方法

### 用法

基本用法通常是指定时间区域，在这一时间区域内恢复相关的信息，11:20为开始时间，11:30是结束时间。
这一时间下可能会包含没被删除的普通信息，建议设置一个精确的消息删除时刻并自行查找

message id 需要指定一个 chatid（群id或者用户id）

```
python3 recover.py --image -time 11:20-11:30
python3 recover.py --audio -time 11:20-11:30
python3 recover.py --voice -time 11:20-11:30
python3 recover.py --video -time 11:20-11:30
python3 recover.py --file -time 11:20-11:30
python3 recover.py --text --message-id 12345
python3 recover.py --sticker --gif -time 11:20-11:30
python3 recover.py --all -time 11:20-11:30
```

时间范围默认未指定日期，脚本默认使用当天日期。若需要恢复其他日期的数据，请使用：

```
python3 recover.py --audio --date 2026-07-13 -time 20:33-20:35
```

如果希望避免扫描整个本地缓存，而是通过 Telegram API 精确恢复某个聊天中的内容，可以指定聊天 ID，但是 Telegram API 恢复相关信息极其不稳定：·

```
python3 recover.py --chat-id 123456789 --image -time 20:33-20:35
python3 recover.py --chat-id -1001234567890 --voice --date 2026-07-13 -time 20:33-20:35
python3 recover.py --chat-id @username --file -time 11:20-11:30
```

###可用类型

以下是参数列表对应其可用类型

```
--image       图片
--video       视频
--audio       普通音频文件（不包含 Telegram 语音消息）
--voice       Telegram 语音消息（通常为 OGG/Opus）
--file        普通文件附件（文档、压缩包、程序、文本、字体等）
--document    --file 的别名
--sticker     贴纸（TGS、小型 WebP、贴纸式 WebM）
--gif         GIF/动画消息（包括静音短视频）
--round       圆形视频消息
--thumbnail   缩略图/缓存预览图
--text        恢复指定聊天文本信息；必须配合 --message-id，仅输出 chat_info
--all         恢复所有检测到的缓存媒体/文件类型（不包含聊天文本）
--chat-id     聊天对话使用的信息标识 ID
--peer-id     --chat-id 的别名
--tdata       指定 Tdata 目录
```

可同时恢复相关文件类型

```
python3 recover.py --image --audio --file -time 20:33-20:35
```

### 恢复聊天文本(不稳定)

聊天文本不会按照时间范围扫描，必须指定目标消息：

```
python3 recover.py --text --message-id 12345
python3 recover.py --text --message-id 12345 --peer-id 1814986730
python3 recover.py --text --chat-id 1814986730 --message-id 12345
```

### 选择本地 Telegram 用户

查看本地缓存中的所有 Telegram 用户：

```
python3 recover.py --list-users
```

恢复时，脚本会自动：
- 检测当前操作系统上的 `Telegram tdata` 路径；
- 查找所有本地 `user_data*` 文件夹；
- 显示账户相关信息；
然后询问要使用哪个账户。

例如：

```
python3 recover.py --audio -time 11:20-11:30
```

如果检测到多个本地账户，可输入：
- 1：选择第一个账户；
- 1,3：同时选择第 1 和第 3 个账户；
- A：选择所有账户。
---
为了避免误操作，不提供通过命令行参数直接指定 `user_data` 的方式，账户选择始终采用交互式进行。

### 输出目录

脚本会在自身所在目录创建 `output/` 文件夹：

```
output/
  telegram_recovered_TYPE_YYYYMMDD_HHMMSS-YYYYMMDD_HHMMSS/
    images/
    videos/
    audio/
    voice/
    files/
    stickers/
    gifs/
    round/
    thumbnails/
    chat_info/
    all/
    contact_sheet.jpg
    manifest.csv
    manifest.json
    summary.json
    README.txt
```

### 备注

如果本地 Telegram 数据启用了存储密码（Passcode），请使用：

```
--passcode "password"
```

如果 Telegram 数据目录位于其他位置，可使用：

```
--tdata /path/to/tdata
```

## 主要开源依赖

项目中使用的开源库/方法：

- [LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon) [MIT]
- [pyrogram/tgcrypto](https://github.com/pyrogram/tgcrypto) [LGPLv3+]
- [Dmeetrogon/TGArtifacts](https://github.com/Dmeetrogon/TGArtifacts) [MIT] - 借鉴其相关方法实现

间接依赖
- pyaes [MIT]
- rsa [Apache-2.0]
- pyasn1 [BSD-2-Clause]