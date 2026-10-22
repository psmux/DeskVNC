/**
 * Simplified Chinese catalog.
 *
 * Keys are the English source text, so `t("Skip")` finds this entry without an
 * extraction step. `lib/i18n` falls back to the English key for anything
 * missing, which means a partial catalog is a partially translated screen,
 * never a blank one. `i18n.test.ts` asserts the keys match the call sites, so
 * a stale key here fails the build rather than being silently ignored.
 *
 * Terms are chosen once and kept: host is 主机, session is 会话, library is
 * 资源库, tile is 卡片, group is 分组, tag is 标签, agent is 代理, keychain is
 * 钥匙串, and lease is 控制权. Sentences are rewritten to read as Chinese
 * instructions rather than translated word for word.
 */
export const zhCN: Record<string, string> = {
  "About DeskVNCViewer":
    "关于 DeskVNCViewer",
  "About":
    "关于",
  "Help":
    "帮助",
  "About sections":
    "关于页分区",
  "A fast, native remote desktop viewer for macOS, Windows and Linux.":
    "面向 macOS、Windows 和 Linux 的原生远程桌面客户端，响应迅速。",
  "Version {version}":
    "版本 {version}",
  "Build details":
    "构建信息",
  "Build":
    "构建",
  "Copied":
    "已复制",
  "Copy report for a bug ticket":
    "复制构建报告（提交问题用）",
  "Commit":
    "提交",
  "(locally modified)":
    "（本地有改动）",
  "Branch":
    "分支",
  "{branch}, committed {date}":
    "{branch}，提交于 {date}",
  "Toolchain":
    "工具链",
  "System":
    "系统",
  "Please include the copied block when reporting an issue; it identifies this exact build.":
    "提交问题时请附上这段复制的内容，它能精确定位到这个构建。",
  "Developed by":
    "开发者",
  "Contact":
    "联系方式",
  "License":
    "许可证",
  "© {year} {author}. Supports RFB 3.3-3.8 with VNC, VeNCrypt, RA2, Apple Diffie-Hellman and MS-Logon authentication, and RDP with network level authentication.":
    "© {year} {author}。支持 RFB 3.3-3.8，含 VNC、VeNCrypt、RA2、Apple Diffie-Hellman 与 MS-Logon 认证方式，并支持带网络级身份验证的 RDP。",
  "Project page":
    "项目主页",
  "Contact developer":
    "联系开发者",
  "Getting started":
    "快速上手",
  "Double-click a tile to connect. Passwords are saved to the OS keychain on first use.":
    "双击卡片即可连接。首次使用时，密码会保存到系统钥匙串。",
  "Group and tag hosts from the sidebar to keep a large library navigable.":
    "在侧边栏用分组和标签整理主机，资源库再大也能快速找到。",
  "Keyboard shortcuts":
    "键盘快捷键",
  "Troubleshooting":
    "疑难排查",
  "Full documentation":
    "完整文档",
  "Use {scan} to find computers nearby, or {newHost} to add one by address.":
    "用 {scan} 查找附近的电脑，或用 {newHost} 按地址添加。",
  "Search hosts":
    "搜索主机",
  "Search or press {modifier}K":
    "搜索，或按 {modifier}K",
  "Sort":
    "排序",
  "Sort hosts":
    "主机排序方式",
  "Name":
    "名称",
  "Last connected":
    "最近连接",
  "Most used":
    "最常使用",
  "Group":
    "分组",
  "View mode":
    "视图模式",
  "Grid view":
    "网格视图",
  "List view":
    "列表视图",
  "Where sessions open":
    "会话打开方式",
  "Open sessions in their own windows":
    "每个会话开在独立窗口",
  "Open each session in its own window":
    "每个会话开一个独立窗口",
  "Open sessions as tabs in this window":
    "会话以标签页开在此窗口",
  "Live previews, tiles with an active session show a live picture instead of the saved thumbnail":
    "实时预览：有活动会话的卡片显示实时画面，而不是已保存的缩略图",
  "Scanning…":
    "扫描中…",
  "Scan network":
    "扫描网络",
  "New Host":
    "新建主机",
  "About and help":
    "关于与帮助",
  "Hosts":
    "主机",
  "Let's find your computers":
    "来找你的电脑",
  "DeskVNCViewer can discover computers on your local network automatically, or you can add one by address.":
    "DeskVNCViewer 可以自动发现局域网中的电脑，也可以按地址手动添加。",
  "Add a computer manually":
    "手动添加电脑",
  "No computers match “{query}”":
    "没有匹配“{query}”的电脑",
  "Add “{query}” as a new host":
    "把“{query}”添加为新主机",
  "Nothing discovered yet":
    "还没有发现任何电脑",
  "Some computers don't advertise themselves on the network. You can actively scan this subnet, or add a computer by address.":
    "有些电脑不会在网络中广播自己。你可以主动扫描本网段，或按地址添加。",
  "Scan this network":
    "扫描本网段",
  "Add manually":
    "手动添加",
  "{count} hosts selected":
    "已选择 {count} 台主机",
  "{count} hosts":
    "{count} 台主机",
  "Drag onto a group or tag in the sidebar, or:":
    "拖到侧边栏的分组或标签上，或者：",
  "Move selected hosts to a group":
    "把选中的主机移到分组",
  "Move to…":
    "移动到…",
  "No group":
    "不分组",
  "Tag":
    "标签",
  "Add a tag to the selected hosts":
    "给选中的主机加标签",
  "Add tag…":
    "添加标签…",
  "Address":
    "地址",
  "Protocol":
    "协议",
  "OS":
    "系统",
  "Online":
    "在线",
  "Offline or unknown":
    "离线或未知",
  "New Group":
    "新建分组",
  "New Tag":
    "新建标签",
  "Group name":
    "分组名称",
  "Tag name":
    "标签名称",
  "Host updated":
    "主机已更新",
  "Added {name}":
    "已添加 {name}",
  "Go to {title}":
    "切换到 {title}",
  "New host…":
    "新建主机…",
  "Connect to an address…":
    "连接到地址…",
  "Switch to list view":
    "切换到列表视图",
  "Switch to grid view":
    "切换到网格视图",
  "Open Preferences":
    "打开偏好设置",
  "Refresh library":
    "刷新资源库",
  "Help & keyboard shortcuts":
    "帮助与快捷键",
  "Open a group as a grid first, then save how you arranged it":
    "先把分组以网格方式打开，再保存你的排列方式",
  "Saved this arrangement to {group}":
    "已把该排列方式保存到 {group}",
  "Open as grid (saved layout)":
    "以网格打开（使用已保存的布局）",
  "Open as grid":
    "以网格打开",
  "Save this layout to group":
    "把此布局保存到分组",
  "Forget saved layout":
    "忘记已保存的布局",
  "{group} will open as a plain grid from now on":
    "{group} 之后将以普通网格打开",
  "Could not undo: {error}":
    "撤销失败：{error}",
  "{name} is not in a group":
    "{name} 不在任何分组中",
  "{name} are not in a group":
    "{name} 不在任何分组中",
  "Removed {name} from their group":
    "已将 {name} 移出所在分组",
  "Undo":
    "撤销",
  "Could not move those hosts: {error}":
    "移动这些主机失败：{error}",
  "{name} already in {group}":
    "{name} 已经在 {group} 中",
  "Moved {name} to {group}":
    "已将 {name} 移到 {group}",
  "{name} already tagged {tag}":
    "{name} 已经带有标签 {tag}",
  "Tagged {name} with {tag}":
    "已为 {name} 加上标签 {tag}",
  "Could not tag those hosts: {error}":
    "给这些主机加标签失败：{error}",
  "Remove {count} hosts from their group":
    "把 {count} 台主机移出分组",
  "Move to {group}":
    "移到 {group}",
  "Tag with {tag}":
    "加上标签 {tag}",
  "Delete {count} hosts…":
    "删除 {count} 台主机…",
  "Deleted {count} hosts. Saved passwords are gone.":
    "已删除 {count} 台主机，保存的密码也已清除。",
  "Could not restore those hosts: {error}":
    "恢复这些主机失败：{error}",
  "Connect":
    "连接",
  "Connect in new tab":
    "在新标签页中连接",
  "Connect in new window":
    "在新窗口中连接",
  "Edit…":
    "编辑…",
  "Remove from Favorites":
    "从收藏中移除",
  "Add to Favorites":
    "加入收藏",
  "Duplicate":
    "创建副本",
  "{name} copy":
    "{name} 副本",
  "Wake (Wake-on-LAN)":
    "唤醒（网络唤醒）",
  "Magic packet sent to {host}":
    "已向 {host} 发送唤醒包",
  "Reload thumbnail":
    "重新加载缩略图",
  "Forget saved key…":
    "忘记已保存的密钥…",
  "Forgot the saved key for {host}. You will be asked to verify it on the next connection.":
    "已忘记 {host} 的密钥，下次连接时会要求你重新验证。",
  "Delete…":
    "删除…",
  "Deleted {host}":
    "已删除 {host}",
  "Created the group {name}":
    "已创建分组 {name}",
  "Created the tag {name}":
    "已创建标签 {name}",
  "Could not create the group: {error}":
    "创建分组失败：{error}",
  "Could not create the tag: {error}":
    "创建标签失败：{error}",
  "Library sections":
    "资源库分区",
  "Nearby":
    "附近",
  "All Hosts":
    "全部主机",
  "Drop here to remove these hosts from their group":
    "拖到这里可把这些主机移出分组",
  "Favorites":
    "收藏",
  "Recents":
    "最近",
  "Groups":
    "分组",
  "New group":
    "新建分组",
  "Make a group first, then drop hosts on it":
    "先建一个分组，再把主机拖上去",
  "No groups yet":
    "还没有分组",
  "Tags":
    "标签",
  "New tag":
    "新建标签",
  "Toggle whether hosts must match ALL selected tags (AND) or ANY (OR)":
    "切换多标签的匹配方式：必须同时满足全部（AND）或满足任意一个（OR）",
  "Tag filter mode: {mode}. Click to toggle.":
    "标签筛选方式：{mode}。点击切换。",
  "Make a tag first, then drop hosts on it":
    "先建一个标签，再把主机拖上去",
  "No tags yet":
    "还没有标签",
  "Drop here to tag with {tag}":
    "拖到这里可加上标签 {tag}",
  "Drop here to move these hosts into {group}":
    "拖到这里可把这些主机移入 {group}",
  "AI Agents":
    "AI 代理",
  "Authentication required":
    "需要身份验证",
  "needs your Windows sign-in before it will let you in.":
    "需要你的 Windows 登录凭据才允许进入。",
  "needs a user name and password before it will let you in.":
    "需要用户名和密码才允许进入。",
  "needs a password before it will let you in.":
    "需要密码才允许进入。",
  "Incorrect password. Try again.":
    "密码不正确，请重试。",
  "Attempt {attempt}":
    "第 {attempt} 次尝试",
  "User name":
    "用户名",
  "Domain":
    "域",
  "Leave blank for a local account, or if your user name is already an email-style name.":
    "本地账户可留空；如果用户名本身已是邮箱形式，也可留空。",
  "Password":
    "密码",
  "This server uses legacy VNC authentication, only the first {limit} characters are used.":
    "该服务器使用旧版 VNC 认证，只使用前 {limit} 个字符。",
  "Remember for this computer":
    "为这台电脑记住",
  "Stored in your system keychain, never in a file. Saved only if this password works.":
    "保存在系统钥匙串中，绝不写入文件。仅在密码验证通过后才会保存。",
  "Cancel":
    "取消",
  "Close":
    "关闭",
  "Server identity has CHANGED":
    "服务器身份已发生变化",
  "trust new identity":
    "信任新身份",
  "A Windows reinstall, or a new machine certificate after a domain change, both look exactly like this. So does an attacker. Do not continue unless you know which it is.":
    "重装 Windows、域变更后重新签发机器证书，看起来都完全一样；攻击者在中间人攻击时也一样。除非你确定是哪一种，否则不要继续。",
  "To proceed anyway, type {phrase}":
    "如仍要继续，请输入 {phrase}",
  "Cancel (recommended)":
    "取消（推荐）",
  "Trust new identity":
    "信任新身份",
  "Verify {host}":
    "验证 {host}",
  "Windows Remote Desktop normally identifies itself with a certificate it generated for itself, so on a fresh machine there is nothing to compare this against. Remembering it now means you will be told if it ever changes.":
    "Windows 远程桌面通常使用它自己生成的自签名证书，因此在一台全新的机器上你无从比对。现在记住它，日后一旦变化就会提醒你。",
  "This is the first time this computer has identified itself with the key below. Verify the fingerprint matches the one shown on the server, then choose how much to trust it.":
    "这是该电脑第一次用下面的密钥表明身份。请确认指纹与服务器上显示的相符，然后决定信任到什么程度。",
  "Connect once":
    "仅连接一次",
  "Trust this computer":
    "信任这台电脑",
  "SHA-256 certificate fingerprint":
    "SHA-256 证书指纹",
  "Fingerprint words:":
    "指纹助记词：",
  "SSH gateway identity has CHANGED":
    "SSH 网关身份已发生变化",
  "This machine's identity has CHANGED":
    "这台机器的身份已发生变化",
  "Previously trusted":
    "此前信任的",
  "Presented now":
    "本次出示的",
  "Verify SSH gateway {host}":
    "验证 SSH 网关 {host}",
  "host key":
    "主机密钥",
  "Trust and connect":
    "信任并连接",
  "{label} SSH fingerprint":
    "{label} SSH 指纹",
  "Connect to {target}":
    "连接到 {target}",
  "saved host":
    "已保存的主机",
  "port {port}":
    "端口 {port}",
  "recent":
    "最近",
  "Connect to an address, e.g. 192.168.1.20:1 or rdp://frontdesk  ({modifier}T)":
    "输入地址连接，例如 192.168.1.20:1 或 rdp://frontdesk  （{modifier}T）",
  "Address to connect to":
    "要连接的地址",
  "Connection suggestions":
    "连接建议",
  "{host} is saved as {protocol}":
    "{host} 已保存为 {protocol}",
  "Click to connect with {protocol} instead":
    "点击改用 {protocol} 连接",
  "Connects without saving anything":
    "直接连接，不保存任何内容",
  "never":
    "从未",
  "just now":
    "刚刚",
  "{n}m ago":
    "{n} 分钟前",
  "{n}h ago":
    "{n} 小时前",
  "{n}d ago":
    "{n} 天前",
  "{n}mo ago":
    "{n} 个月前",
  "{n}y ago":
    "{n} 年前",
  "Command palette":
    "命令面板",
  "Jump to the QuickConnect address bar":
    "跳到 QuickConnect 地址栏",
  "Search the library":
    "搜索资源库",
  "Preferences":
    "偏好设置",
  "Disconnect session":
    "断开当前会话",
  "Show/hide session toolbar":
    "显示/隐藏会话工具栏",
  "Toggle fullscreen":
    "切换全屏",
  "Next / previous tab":
    "下一个 / 上一个标签页",
  "Jump to a tab (1 is the library)":
    "跳到指定标签页（第 1 个是资源库）",
  "Close the current tab":
    "关闭当前标签页",
  "Back to the library":
    "返回资源库",
  "Split the pane to the right":
    "向右分屏",
  "Split the pane downwards":
    "向下分屏",
  "Move to the pane in that direction":
    "移动到该方向的分屏窗格",
  "Previous / next pane":
    "上一个 / 下一个窗格",
  "Maximise the current pane, or restore it":
    "最大化当前窗格，或还原",
  "Give every pane an equal share":
    "让所有窗格均分空间",
  "Close the current pane":
    "关闭当前窗格",
  "A host is not showing up in Scan network":
    "扫描网络时找不到某台主机",
  "Discovery uses mDNS and a subnet sweep, so it only sees hosts on the same network segment. Add it by IP with New Host instead.":
    "发现功能依赖 mDNS 和网段扫描，只能看到同一网段内的主机。请改用「新建主机」按 IP 添加。",
  "The connection drops and keeps retrying":
    "连接反复断开并不断重试",
  "Reconnect is automatic by default. Turn it off, or enable Wake-on-LAN during retry, in Preferences → Connections.":
    "默认会自动重连。可在「偏好设置 → 连接」中关闭，或开启重试期间发送网络唤醒包。",
  "Keyboard input is not reaching the remote machine":
    "键盘输入到不了远程电脑",
  "Check that View Only is off in the Session menu. On macOS, input capture also needs Accessibility permission.":
    "请确认「会话」菜单中的「仅查看」已关闭。macOS 上，输入捕获还需要「辅助功能」权限。",
  "Saved passwords are requested again every launch":
    "每次启动都要求重新输入已保存的密码",
  "The app stores credentials in the OS keychain. Preferences → Security shows which backend is active and whether it is unlocked.":
    "凭据保存在操作系统钥匙串中。「偏好设置 → 安全」会显示当前使用的后端以及它是否已解锁。",
  "Preference sections":
    "设置分区",
  "Close preferences":
    "关闭偏好设置",
  "Language":
    "语言",
  "Follow System uses the language your operating system is set to.":
    "跟随系统表示使用操作系统的语言设置。",
  "({language})":
    "（{language}）",
  "Follow System":
    "跟随系统",
  "Light":
    "浅色",
  "Dark":
    "深色",
  "Confirm before disconnecting":
    "断开前确认",
  "Ask before ending a session from the toolbar":
    "从工具栏结束会话前先询问。",
  "Capture thumbnails":
    "保存缩略图",
  "Save a small screenshot of each host after connecting, for the library grid":
    "连接后为每台主机保存一张小截图，用于资源库网格。",
  "Live previews":
    "实时预览",
  "While a session is connected, its library tile shows a live picture (about 2 frames per second) instead of the saved thumbnail":
    "会话连接期间，资源库中的卡片显示实时画面（约每秒 2 帧），而不是已保存的缩略图。",
  "Compact library density":
    "资源库紧凑排列",
  "Smaller tiles and tighter spacing for large libraries":
    "卡片更小、间距更紧，适合主机较多的资源库。",
  "Theme":
    "主题",
  "Follow System switches automatically with your OS":
    "跟随系统会随操作系统自动切换。",
  "Show sessions as tabs in one window":
    "在单个窗口中以标签页显示会话",
  "Connected computers become tabs across the top of this window, switched between like browser tabs, instead of each opening a window of its own. Sessions already running stay where they are; this decides where the next one goes.":
    "已连接的电脑变成窗口顶部的标签页，像浏览器标签一样切换，而不是各自打开一个窗口。已经在运行的会话不会移动，此设置只决定下一个会话开在哪里。",
  "Allow more than one tab per computer":
    "允许同一台电脑开多个标签页",
  "Allow more than one window per computer":
    "允许同一台电脑开多个窗口",
  "Normally, connecting to a computer you're already connected to selects the tab it is in instead of starting a second session. Turn this on to open a separate tab every time.":
    "默认情况下，连接一台已经连着的电脑会切换到它所在的标签页，而不是再开一个会话。开启后每次都会新开一个标签页。",
  "Normally, connecting to a computer you're already connected to brings that window back to the front instead of starting a second session. Turn this on to open a separate window every time.":
    "默认情况下，连接一台已经连着的电脑会把它所在的窗口调到前面，而不是再开一个会话。开启后每次都会新开一个窗口。",
  "Sharpen the picture when motion stops":
    "画面静止后恢复清晰",
  "During movement the image is compressed hard so it stays instant; a moment after things settle, the affected area is repainted at full quality. Turn this off on a metered connection to keep the saved bandwidth.":
    "画面运动时会大幅压缩以保证流畅；静止片刻后，受影响的区域会以完整画质重绘。按流量计费时关闭此项可省下这部分带宽。",
  "Remote Desktop defaults":
    "远程桌面默认值",
  "Resolution for new Remote Desktop hosts":
    "新建远程桌面主机的分辨率",
  "Matching the window when connecting is what Windows' own client does. Making it keep matching resizes the remote desktop every time you resize this one, which rearranges that machine's icons each time.":
    "连接时匹配窗口大小，与 Windows 自带客户端的行为一致。让它持续匹配，则每次调整本地窗口大小都会改变远程桌面的分辨率，那台电脑上的图标也会跟着重排。",
  "Match the window when connecting":
    "连接时匹配窗口",
  "Match the window, and keep matching":
    "匹配窗口，并持续匹配",
  "Use all my monitors for new Remote Desktop connections":
    "新建远程桌面连接时使用我的全部显示器",
  "New hosts start with every local monitor attached. Existing hosts keep whatever you set on them.":
    "新主机默认挂载全部本地显示器。已有主机保持各自原来的设置。",
  "Play remote sound on this computer":
    "在本机播放远程声音",
  "Sound from the remote computer is redirected here rather than left playing there.":
    "远程电脑的声音转发到本机播放，而不是留在那台机器上。",
  "Share my clipboard with Remote Desktop connections":
    "与远程桌面连接共享剪贴板",
  "Copy and paste text in both directions.":
    "双向复制粘贴文本。",
  "Reconnect until I close the window":
    "一直重连到窗口关闭",
  "Keep retrying dropped sessions with exponential backoff":
    "断开的会话按指数退避持续重试。",
  "Send Wake-on-LAN during retries":
    "重试期间发送网络唤醒包",
  "If a host with a saved MAC address looks down, send a magic packet while reconnecting":
    "如果保存了 MAC 地址的主机看起来离线，重连时发送幻数据包唤醒它。",
  "Hide the floating toolbar":
    "隐藏浮动工具栏",
  "Leave nothing on top of the remote desktop. Everything the toolbar does stays available from the View and Session menus, which show what each session is set to.":
    "让远程桌面之上不留任何遮挡。工具栏的所有功能仍可从「显示」和「会话」菜单使用，菜单也会显示当前会话的各项设置。",
  "Lock zoom":
    "锁定缩放",
  "Ignore pinch-to-zoom, which is easy to trigger by accident mid-scroll on a trackpad. The zoom controls still work.":
    "忽略双指捏合缩放，这一手势在触控板滚动时很容易误触。缩放控件仍然可用。",
  "Pan by moving to the edges":
    "移到边缘时平移画面",
  "Scroll the view when the pointer reaches an edge, for a desktop larger than the window. With this off, the part of the screen past the edge can only be reached by space-dragging.":
    "当远程桌面大于窗口时，指针到达边缘即滚动视图。关闭后，边缘之外的部分只能用空格键拖动到达。",
  "Defaults for new computers":
    "新电脑的默认值",
  "Where a computer starts before you have adjusted anything on it. Change one of these while connected, from the toolbar or the menus, and it is remembered against that computer from then on, including which monitor you picked.":
    "一台尚未单独调整过的电脑使用这里的初始值。连接时从工具栏或菜单修改其中一项，之后会一直记在那台电脑名下，包括你选了哪个显示器。",
  "Scaling":
    "缩放方式",
  "How the remote desktop is fitted into the window":
    "远程桌面如何适配到窗口中。",
  "Aspect fit":
    "保持比例",
  "Fit":
    "拉伸填满",
  "1:1":
    "1:1 原始大小",
  "Remote":
    "由远端调整",
  "Quality":
    "画质",
  "Auto infers the link from throughput; the others say what the link is and stop it adapting":
    "自动会根据实际吞吐量推断链路状况；其余选项直接指定链路类型，不再自适应。",
  "Auto":
    "自动",
  "High":
    "高",
  "Medium":
    "中",
  "Low":
    "低",
  "B&W":
    "黑白",
  "Gray levels":
    "灰度级数",
  "How many shades the black-and-white preset keeps":
    "黑白预设保留多少级灰度。",
  "1-bit":
    "1 位",
  "Start in view only":
    "以仅查看模式启动",
  "Watch without sending any input. Nothing you type or click reaches the remote computer until you turn it off.":
    "只观看，不发送任何输入。关闭此模式之前，你键入或点击的任何操作都不会到达远程电脑。",
  "Always request fresh frames":
    "始终请求完整画面",
  "Re-fetch the whole screen every second instead of trusting the server to report what changed. Fixes a picture that stays stale or smeared; uses more bandwidth.":
    "每秒重新获取整屏，而不依赖服务器报告变化。可解决画面停滞或拖影，代价是占用更多带宽。",
  "Pass system shortcuts to the remote":
    "把系统快捷键传给远端",
  "Send Cmd/Alt+Tab, Cmd+Space and the Windows key to the remote computer instead of this one. Needs Accessibility permission on macOS, and grabs your keyboard while a session is focused; release it at any time with Ctrl+Alt+Shift+Esc.":
    "把 Cmd/Alt+Tab、Cmd+Space 和 Windows 键发送给远程电脑，而不是本机。macOS 上需要「辅助功能」权限；会话获得焦点时会接管键盘，可随时按 Ctrl+Alt+Shift+Esc 释放。",
  "Match my scroll direction":
    "跟随我的滚动方向",
  "Scroll the remote desktop the way this computer scrolls, whatever your trackpad and mouse settings say. Turn it off to reverse the direction on the remote only.":
    "远程桌面的滚动方向与本机一致，不受触控板或鼠标设置影响。关闭后只在远端反向。",
  "Match my local keyboard layout":
    "使用本机键盘布局",
  "Keys type what they type on this keyboard, instead of what the remote machine's layout assigns to the same physical key. Only matters when the two layouts differ.":
    "按键打出的是本机布局上的字符，而不是远程电脑为同一物理按键分配的字符。仅当两边布局不同时才有影响。",
  "Type text inserted by dictation tools":
    "输入听写工具插入的文本",
  "Text that dictation and automation software inserts without pressing keys is typed into the remote desktop. Accents and CJK input methods work either way, those are you typing.":
    "听写和自动化软件不按键、直接插入的文本会键入远程桌面。变音符号和中文输入法两种情况都正常，那属于你在实际打字。",
  "Type a paste that stays on this Mac into the remote":
    "把留在这台 Mac 上的粘贴动作敲进远端",
  "When Cmd+V is left to macOS (system shortcuts not passed through) or you pick Edit ▸ Paste, the clipboard text is typed into the remote desktop key by key. Dictation tools that paste, such as Wispr Flow, need this on.":
    "当 Cmd+V 交给 macOS 处理（系统快捷键未透传）或你选择「编辑 ▸ 粘贴」时，剪贴板文本会逐键敲入远程桌面。Wispr Flow 之类靠粘贴的听写工具需要开启此项。",
  "Show the remote pointer":
    "显示远程指针",
  "Draw the remote machine's own mouse cursor. Turn this off if two pointers feel distracting, your input is sent either way.":
    "绘制远程电脑自己的鼠标指针。若觉得两个指针干扰可以关闭，输入照常发送。",
  "My pointer":
    "我的指针",
  "The system arrow covers the pixels under its own tip, which is where the remote pointer sits, so with both drawn they crowd each other. Dot is a ring centred on the hotspot; Hidden leaves only the remote pointer.":
    "系统箭头会遮住箭头尖端下方的像素，而那正是远程指针所在的位置，两个都画会互相干扰。「圆点」是在热区中心的圆环；「隐藏」只保留远程指针。",
  "Standard arrow":
    "标准箭头",
  "Dot":
    "圆点",
  "Hidden":
    "隐藏",
  "Sync clipboard automatically":
    "自动同步剪贴板",
  "Text copied on either side is available on the other":
    "在任一侧复制的文本，另一侧都能直接使用。",
  "Push clipboard when the window gains focus":
    "窗口获得焦点时推送剪贴板",
  "Send your local clipboard to the remote when you switch back to the session":
    "切回会话窗口时，把本机剪贴板发送到远端。",
  "Push clipboard when pasting into the remote":
    "向远端粘贴时先推送剪贴板",
  "Cmd/Ctrl+V sends your local clipboard first, so the remote pastes what you copied most recently":
    "Cmd/Ctrl+V 会先发送本机剪贴板，这样远端粘贴的就是你最近复制的内容。",
  "Confirm before overwriting files":
    "覆盖文件前确认",
  "Ask when a transfer would replace an existing file":
    "传输会替换已有文件时先询问。",
  "Credential storage":
    "凭据存储",
  "Passwords are stored in: {backend}":
    "密码存储在：{backend}",
  "Passwords are stored in your operating system keychain, never in a file.":
    "密码存储在操作系统的钥匙串中，绝不写入文件。",
  "Strict certificate pinning":
    "严格证书锁定",
  "Refuse to connect when a server's certificate changes, until you explicitly re-trust it":
    "服务器证书发生变化时拒绝连接，直到你明确重新信任它。",
  "Look up names from other services":
    "从其他服务查询主机名",
  "Some Windows machines block every name service. Reading the name they publish on RDP or RPC names them anyway, but it means connecting briefly to ports you are not connecting through, which strict network monitoring may flag. Turn off to use name services only.":
    "有些 Windows 电脑屏蔽了所有名称服务。读取它们在 RDP 或 RPC 上公布的名字仍可完成命名，但这意味着会短暂连接一些你并未使用的端口，严格的网络监控可能会标记这一行为。关闭后只使用名称服务。",
  "Look for Remote Desktop while scanning":
    "扫描时同时查找远程桌面",
  "Also tries port 3389 on each address, so a Windows machine that runs no VNC server still appears. One extra connection per address, at the same polite rate as the rest of the scan.":
    "对每个地址额外尝试 3389 端口，这样没装 VNC 服务端的 Windows 电脑也能被发现。每个地址多一次连接，速率与扫描其余部分同样克制。",
  "Discover computers automatically (mDNS/Bonjour)":
    "自动发现电脑（mDNS/Bonjour）",
  "Listen for VNC servers advertising themselves on your local network":
    "监听局域网中主动广播自己的 VNC 服务器。",
  "Probe saved hosts for online status":
    "探测已保存主机的在线状态",
  "A lightweight, throttled TCP check that powers the green dot on tiles":
    "一次轻量、限速的 TCP 探测，卡片上的绿点由它决定。",
  "Hide the agent counts":
    "隐藏代理数量",
  "Take the line reading how many agents are connected, and how much of this computer they are driving, off the activity strip. The strip itself still appears while an agent is driving something, with a card per machine, and this switch stays here.":
    "从活动栏中移除显示「已连接多少代理、占用了这台电脑多少」的那一行。代理正在操作某台机器时，活动栏本身仍会出现，每台机器一张卡片，此开关也仍在原处。",
  "Right now":
    "当前状态",
  "Driving means an agent holds the lease on that machine. An agent that is connected but holds nothing is driving nothing, and is counted only in the first number.":
    "操作中表示某个代理持有那台机器的控制权。只连接、未持有的代理没有在操作任何东西，只计入第一个数字。",
  "AI Agents, in the library sidebar, has the lines to paste, the check to run, and the switch that turns all of this off again.":
    "资源库侧边栏里的「AI 代理」提供了可粘贴的命令行、用来验证的检查，以及把这一整套再关掉的开关。",
  "General":
    "常规",
  "Appearance":
    "外观",
  "Connections":
    "连接",
  "Session":
    "会话",
  "Input":
    "输入",
  "Clipboard":
    "剪贴板",
  "Files":
    "文件",
  "Security":
    "安全",
  "Network":
    "网络",
  "Agents":
    "代理",
  "Step {step} of 3":
    "第 {step} 步，共 3 步",
  "Welcome to DeskVNCViewer":
    "欢迎使用 DeskVNCViewer",
  "See and control your other computers, fast, secure, and entirely yours. No account, ever.":
    "看到并操作你的其他电脑，快速、安全，数据完全属于你自己。无需任何账号。",
  "Find your computers":
    "找到你的电脑",
  "DeskVNCViewer listens for computers advertising screen sharing on your local network. Your OS may ask permission to access the local network, that's this feature.":
    "DeskVNCViewer 会监听局域网中广播屏幕共享服务的电脑。操作系统可能会请求访问本地网络的权限，那正是为了这个功能。",
  "Find computers on my network":
    "查找我网络中的电脑",
  "Scanning your network…":
    "正在扫描网络…",
  "Nothing found yet, some computers don't advertise themselves. You can add one manually later.":
    "暂时没有找到。有些电脑不会主动广播自己，稍后可以手动添加。",
  "Save your first computer":
    "保存你的第一台电脑",
  "Give it a friendly name and, if you save a password, it's stored in your system keychain, never in a file.":
    "给它起个好记的名字。如果保存密码，密码会存进系统钥匙串，绝不写入文件。",
  "Save…":
    "保存…",
  "No discovered computers to pre-fill, use “+ New Host” in the library instead.":
    "没有可用于预填的已发现电脑，请在资源库中使用「+ 新建主机」。",
  "Skip":
    "跳过",
  "Back":
    "上一步",
  "Continue":
    "继续",
  "Open my library":
    "打开我的资源库",
  "The SSH server at {endpoint} is presenting a different host key than the one you trusted before. This can mean the machine was reinstalled, or that someone is intercepting your connection. The connection was refused. If you know the key legitimately changed, remove the saved key for this machine and connect again.":
    "位于 {endpoint} 的 SSH 服务器出示的主机密钥与你之前信任的不一致。这可能意味着机器被重装过，也可能有人在中间人攻击你的连接。连接已被拒绝。如果你确认密钥是正常更换的，请删除这台机器已保存的密钥后重新连接。",
  "Your connection will be tunnelled through the SSH server at {endpoint}, and this is the first time it has identified itself.":
    "你的连接将通过位于 {endpoint} 的 SSH 服务器隧道转发，这是它第一次表明自己的身份。",
  "This is the first time {endpoint} has identified itself, so there is nothing saved to compare it against yet.":
    "这是 {endpoint} 第一次表明身份，因此还没有已保存的密钥可供比对。",
  "Verify the fingerprint below matches the server's ({command}) before trusting it.":
    "在信任之前，请确认下面的指纹与服务器上的相符（{command}）。",
  "{host} is presenting a different certificate than the one you trusted before. This can mean the server was reinstalled, or that someone is intercepting your connection. <em>Do not continue unless you know why this changed.</em>":
    "{host} 出示的证书与你之前信任的不一致。这可能意味着服务器被重装过，也可能有人在中间人攻击你的连接。<em>除非你清楚变化的原因，否则不要继续。</em>",
  "Edit Host":
    "编辑主机",
  "Add Host":
    "添加主机",
  "Save Changes":
    "保存更改",
  "Connection protocol":
    "连接协议",
  "64 character machine ID":
    "64 位机器码",
  "Friendly name":
    "名称",
  "How this computer appears in your library":
    "这台电脑在资源库中显示的名字",
  "Living Room Mac":
    "客厅 Mac",
  "Connect using":
    "连接方式",
  "Port":
    "端口",
  "Leave blank for a local account, or if your user name is already an email-style name like you@company.com.":
    "本地账户可留空；如果用户名本身已是 you@company.com 这类邮箱形式，也可留空。",
  "Optional":
    "可选",
  "Sign in with":
    "登录方式",
  "SSH authentication":
    "SSH 认证",
  "Operating system":
    "操作系统",
  "Unknown":
    "未知",
  "Security type":
    "安全类型",
  "Auto negotiates the strongest supported":
    "自动协商双方都支持的最强方式",
  "VeNCrypt (TLS + X.509)":
    "VeNCrypt（TLS + X.509）",
  "RSA-AES (RA2)":
    "RSA-AES（RA2）",
  "Apple Screen Sharing":
    "Apple 屏幕共享",
  "VNC password only":
    "仅 VNC 密码",
  "None":
    "无",
  "Black & White":
    "黑白",
  "How the remote screen fits the window":
    "远程画面如何适配到窗口",
  "Fit to window":
    "拉伸填满窗口",
  "Actual size (1:1)":
    "原始大小（1:1）",
  "Remote resize":
    "由远端调整",
  "Keyboard mode":
    "键盘模式",
  "How keystrokes are translated":
    "按键如何转换",
  "Scancode":
    "扫描码",
  "MAC address (for Wake-on-LAN)":
    "MAC 地址（用于网络唤醒）",
  "Filled in automatically, this is the address we saw when we found this machine on your network. Lets you wake it from the library.":
    "自动填写，这是当初在网络中发现这台机器时看到的地址。有了它就能从资源库直接唤醒这台电脑。",
  "Filled in automatically when the machine was discovered on your network. Lets you wake this computer from the library.":
    "在网络中发现这台机器时会自动填写。有了它就能从资源库直接唤醒这台电脑。",
  "MAC address for Wake-on-LAN":
    "用于网络唤醒的 MAC 地址",
  "Sends shortcuts like Alt+Tab and the Windows key to the remote computer":
    "把 Alt+Tab、Windows 键等快捷键发送给远程电脑",
  "Sends shortcuts like Cmd+Tab / Alt+Tab to the remote computer":
    "把 Cmd+Tab / Alt+Tab 等快捷键发送给远程电脑",
  "Colour depth":
    "色深",
  "Auto follows the quality setting":
    "自动：跟随画质设置",
  "Sound":
    "声音",
  "Play here":
    "在本机播放",
  "Play there":
    "在远端播放",
  "Do not play":
    "不播放",
  "Use all of my monitors":
    "使用我的全部显示器",
  "Makes the Displays menu list the remote monitors instead of just the one.":
    "让「显示器」菜单列出远端的所有显示器，而不只是当前这一个。",
  "Share my clipboard":
    "共享剪贴板",
  "Connect to the console session":
    "连接到控制台会话",
  "Required":
    "必填",
  "Only letters, numbers, underscore and hyphen":
    "只能包含字母、数字、下划线和连字符",
  "Only letters, numbers, dot, underscore and hyphen":
    "只能包含字母、数字、点、下划线和连字符",
  "Connect inside WSL":
    "连接到 WSL 内部",
  "On a Windows host, land inside the Windows Subsystem for Linux instead of PowerShell, and look for the multiplexer there instead of on Windows.":
    "在 Windows 主机上，直接落到 Linux 子系统（WSL）里而不是 PowerShell，并在其中查找终端复用器，而不是在 Windows 上查找。",
  "Distribution":
    "发行版",
  "The list of installed distributions could not be read, so type a name instead. Leave blank for the default distribution.":
    "读不到已安装的发行版列表，请直接输入名称。留空表示使用默认发行版。",
  "Leave blank for the default distribution.":
    "留空表示使用默认发行版。",
  "Default distribution":
    "默认发行版",
  "Detecting…":
    "检测中…",
  "Detect":
    "检测",
  "Terminal multiplexer":
    "终端复用器",
  "Auto finds tmux or psmux on the remote machine, so your work survives a dropped connection. Without one, a disconnect ends your session.":
    "自动在远端查找 tmux 或 psmux，这样即使连接中断，你的工作也能保留下来。不使用的话，一旦断线会话就结束了。",
  "Auto (recommended)":
    "自动（推荐）",
  "None, always a plain shell":
    "不使用，始终是普通 shell",
  "Custom command":
    "自定义命令",
  "Session name":
    "会话名称",
  "This is placed on the remote command line to attach or create the session, so only letters, numbers, underscore and hyphen are accepted, up to 64 characters.":
    "这一名称会出现在远端的命令行上，用于接入或新建会话，因此只接受字母、数字、下划线和连字符，最长 64 个字符。",
  "Runs on the remote machine instead of attaching to tmux, psmux or another multiplexer. {session} is replaced with the session name above.":
    "在远端执行这条命令，而不是接入 tmux、psmux 或其他复用器。其中的 {session} 会替换为上面的会话名称。",
  "Startup command":
    "启动命令",
  "Runs once connected, instead of your login shell. Leave blank to sign in normally.":
    "连接后执行，替代你的登录 shell。留空表示正常登录。",
  "Fall back to a plain shell":
    "回退到普通 shell",
  "If the chosen multiplexer is not installed on the remote machine, connect with an ordinary shell instead of refusing to connect.":
    "如果远端没有安装所选的复用器，就用普通 shell 连接，而不是直接拒绝连接。",
  "Font size":
    "字号",
  "Scrollback":
    "回滚行数",
  "Lines kept for scrolling back":
    "保留多少行历史以便回滚",
  "Allow connecting without network level authentication":
    "允许在无网络级身份验证的情况下连接",
  "Some older or misconfigured servers refuse network level authentication. Without it your password is sent to a computer whose identity has not been checked yet.":
    "一些较旧或配置有误的服务器会拒绝网络级身份验证。关闭它之后，你的密码会发送给一台身份尚未经过校验的电脑。",
  "Allow legacy TLS (1.0 and 1.1)":
    "允许旧版 TLS（1.0 和 1.1）",
  "For Windows 7 and Server 2008 R2 era computers that were never updated. Those machines offer only TLS 1.0 or 1.1, which this app normally refuses. Leave this off unless a connection has already failed for that reason.":
    "适用于从未更新过的 Windows 7 和 Server 2008 R2 时代的电脑。那些机器只支持 TLS 1.0 或 1.1，本应用默认拒绝。除非连接已经因此失败，否则请保持关闭。",
  "Private key":
    "私钥",
  "This key is protected by a passphrase. Put the passphrase in the box below and it is kept in your system keychain.":
    "该私钥受口令保护。在下面的框中填入口令，它会保存到系统钥匙串。",
  "An OpenSSH or PuTTY (.ppk) private key on this computer.":
    "本机上的 OpenSSH 或 PuTTY（.ppk）私钥。",
  "Keys found in your .ssh folder, or browse for one somewhere else.":
    "在 .ssh 目录中找到的密钥，也可以浏览其他位置。",
  "Choose a key...":
    "选择密钥…",
  "Another file...":
    "其他文件…",
  "Browse...":
    "浏览…",
  "Private key path":
    "私钥路径",
  "SSH host":
    "SSH 主机",
  "Leave blank to SSH to the address above":
    "留空表示 SSH 到上面的地址",
  "Same as the address above":
    "与上面的地址相同",
  "SSH port":
    "SSH 端口",
  "User":
    "用户",
  "Leave blank to use your local username":
    "留空表示使用本机用户名",
  "Same as this computer":
    "与本机相同",
  "Authentication":
    "认证方式",
  "Secrets stay in your keychain / agent":
    "密钥材料只保存在钥匙串或代理中",
  "Saved passphrase (or agent)":
    "已保存的口令（或代理）",
  "SSH agent":
    "SSH 代理",
  "Private key file":
    "私钥文件",
  "Stored in your system keychain, shared with the Files panel. Leave blank to keep what is already saved.":
    "保存在系统钥匙串中，与文件面板共用。留空表示保留已保存的内容。",
  "Resolution":
    "分辨率",
  "The remote desktop resizes as you resize this window. Windows rearranges its icons each time.":
    "远程桌面会随本窗口缩放，因此每次都会让 Windows 重排图标。",
  "The remote desktop is sized to this window when you connect, then left alone.":
    "连接时按本窗口尺寸设置远程桌面，之后不再改变。",
  "The remote desktop is always this size. This window scales it to fit.":
    "远程桌面始终保持这个尺寸，由本窗口缩放显示。",
  "Match this window when connecting":
    "连接时匹配本窗口",
  "Match this window, and keep matching":
    "匹配本窗口，并持续匹配",
  "Custom...":
    "自定义…",
  "Width in pixels":
    "宽度（像素）",
  "Height in pixels":
    "高度（像素）",
  "Key file":
    "密钥文件",
  "The password for your account on that computer, kept in your system keychain.":
    "你在那台电脑上的账户密码，保存在系统钥匙串中。",
  "A private key on this computer. It is read when you connect and never leaves this machine.":
    "本机上的私钥。连接时读取，绝不离开这台机器。",
  "Uses your running ssh-agent, Pageant, or the Windows OpenSSH pipe. Stores nothing.":
    "使用正在运行的 ssh-agent、Pageant 或 Windows OpenSSH 管道，不存储任何内容。",
  "Leave blank to keep the saved one.":
    "留空表示保留已保存的。",
  "Leave blank to be asked when you connect":
    "留空表示连接时再询问",
  "Your account on that Mac":
    "你在那台 Mac 上的账户",
  "The account to sign in with":
    "用于登录的账户",
  "Leave blank to sign in as the same user as this computer":
    "留空表示以与本机相同的用户登录",
  "I use a key for this box":
    "这台机器我使用密钥登录",
  "Key passphrase":
    "密钥口令",
  "Unattended password":
    "无人值守密码",
  "A secret is saved in your system keychain. Leave blank to keep it.":
    "已有密钥材料保存在系统钥匙串中。留空表示保留。",
  "Only needed if the key itself is protected. Stored in your system keychain, never in a file.":
    "仅在私钥本身受保护时才需要。保存在系统钥匙串中，绝不写入文件。",
  "Stored in your system keychain, never in a file":
    "保存在系统钥匙串中，绝不写入文件",
  "SSH tunnel":
    "SSH 隧道",
  "A compatible iroh relay. The invitation carries it to your helper.":
    "兼容的 iroh 中继。邀请码里会带上它，传给帮你的人。",
  "A helper enters it as the computer ID, with the unattended password unless they were paired here.":
    "帮你的人把它当作电脑 ID 输入，除非之前在这台电脑上配过对，否则还需要输入无人值守密码。",
  "A short code is easier to read out than a full invitation. Both people must use the same code service, and it can read the invitations it is given, so use one you trust.":
    "短码比完整邀请更好念。双方必须使用同一个短码服务，而该服务能读取收到的邀请内容，所以请使用你信任的服务。",
  "Accessibility permission is needed for a helper to control this computer. Viewing works without it.":
    "要让对方控制这台电脑，需要「辅助功能」权限。仅查看则不需要。",
  "After granting it, quit and reopen DeskVNC if sharing still fails.":
    "授权之后如果仍然无法共享，请退出并重新打开 DeskVNC。",
  "Allow remote control":
    "允许远程控制",
  "Allow screen recording":
    "允许屏幕录制",
  "Allow the helper to control my mouse and keyboard":
    "允许对方控制我的鼠标和键盘",
  "Allow the helper's tools to run commands and copy files":
    "允许对方的工具在这台电脑上执行命令和复制文件",
  "Allow unattended access to this computer":
    "允许无人值守访问这台电脑",
  "Automatic (recommended for a support call)":
    "自动（支持通话时推荐）",
  "Connection":
    "连接",
  "Control needs Accessibility permission. Viewing works without it.":
    "远程控制需要「辅助功能」权限，仅查看则不需要。",
  "Copy ID":
    "复制 ID",
  "Copy code":
    "复制短码",
  "Copy invitation":
    "复制邀请",
  "Copy the full invitation instead":
    "改为复制完整邀请",
  "Create invitation":
    "创建邀请",
  "Creating your code…":
    "正在生成短码…",
  "End session":
    "结束会话",
  "End the session to change this.":
    "请先结束当前会话再修改。",
  "For a helper whose tools, such as DeskVNC's agents, work on this computer while you are away. Commands run as you.":
    "适用于那些在你离开时仍会用工具（例如 DeskVNC 的代理）在这台电脑上工作的对象。命令以你的身份运行。",
  "For an existing Headscale, WireGuard, Cloudflare private network or other routed network. Both machines need a permitted route. Entering an IP does not enroll either device.":
    "用于已有的 Headscale、WireGuard、Cloudflare 私有网络或其他路由网络。两台机器之间需要已放行的路由。仅填写 IP 不会把任何一台设备加入网络。",
  "Get a code":
    "获取短码",
  "Get help":
    "请求协助",
  "Getting your code…":
    "正在获取短码…",
  "Give the person helping you {what}. They see nothing until you approve them.":
    "把{what}交给帮你的人。在你批准之前，对方看不到任何内容。",
  "If this network is unavailable or the address changes, connecting fails instead of using a public relay.":
    "如果该网络不可用或地址发生变化，连接会直接失败，而不会退回到公共中继。",
  "Install and connect this computer to your own provider account. Run setup on the helper's device too.":
    "把这台电脑安装并连接到你的服务商账号。对方那台设备上也要运行一次同样的设置。",
  "Leave empty for the shared Boundary service. Private infrastructure needs its own service here.":
    "留空表示使用共享的 Boundary 服务。自建基础设施需要在这里填写自己的服务地址。",
  "Let people you trust connect to this computer when nobody is here to approve. Off unless you switch it on. DeskVNC must be running for it to work.":
    "允许你信任的人在本机无人批准时连接进来。默认关闭。此功能需要 DeskVNC 正在运行。",
  "Let someone you trust see or control this computer":
    "让你信任的人查看或控制这台电脑",
  "Let someone you trust see or control this computer. They see nothing until you approve them.":
    "让你信任的人查看或控制这台电脑。在你批准之前，对方看不到任何内容。",
  "Let {name} connect any time, even when I am away":
    "允许 {name} 随时连接，即使我不在",
  "Local interface IP address":
    "本机网卡 IP 地址",
  "New password":
    "新密码",
  "No display found to share.":
    "没有找到可共享的显示器。",
  "No display found.":
    "没有找到显示器。",
  "None yet. During a support session, choose Let them connect any time to pair the helper.":
    "还没有。在协助会话中选「允许对方随时连接」，即可完成配对。",
  "Now: {label}":
    "当前：{label}",
  "Off. Change it under Settings.":
    "已关闭。可在「设置」中更改。",
  "On":
    "已开启",
  "One code per session. It expires after 10 minutes if nobody connects.":
    "每个会话一个短码。如果 10 分钟内没人连接，短码会过期。",
  "Open Accessibility settings":
    "打开「辅助功能」设置",
  "Optional. Lets a helper who was never paired connect with this computer's ID and the password. At least {min} characters. Five wrong tries pause it for 15 minutes.":
    "可选。让从未配对过的人用这台电脑的 ID 加密码连接。至少 {min} 个字符。连续输错 5 次会暂停 15 分钟。",
  "Paired helpers":
    "已配对的协助者",
  "Read it out or send it. Your helper enters it, and you approve them here.":
    "念给对方或直接发送。对方输入后，由你在这里批准。",
  "Refresh":
    "刷新",
  "Relay URL":
    "中继地址",
  "Remove":
    "移除",
  "Remove the password":
    "移除密码",
  "Repeat it":
    "再输一遍",
  "Save":
    "保存",
  "Save connection settings":
    "保存连接设置",
  "Saved":
    "已保存",
  "Saved. Get a code to try it with your helper.":
    "已保存。获取一个短码，和对方试一下。",
  "Screen Recording permission is needed to share.":
    "共享屏幕需要「屏幕录制」权限。",
  "Screen to share":
    "要共享的画面",
  "Send it in any chat and keep it private. It is valid for one session.":
    "通过任意聊天工具发送，并注意保密。仅对一次会话有效。",
  "Set password":
    "设置密码",
  "Set up my Tailscale or Cloudflare network":
    "设置我自己的 Tailscale 或 Cloudflare 网络",
  "Settings":
    "设置",
  "Sharing":
    "共享中",
  "Short codes":
    "短码",
  "Start DeskVNC when I sign in, so it is ready":
    "登录时启动 DeskVNC，随时待命",
  "Starting":
    "启动中",
  "The helper can see the selected display, including notifications and this window.":
    "对方可以看到所选显示器上的内容，包括通知和这个窗口。",
  "The two passwords differ":
    "两次输入的密码不一致",
  "They are remembered by their connection's key. You can remove them later under Settings.":
    "系统通过对方的连接密钥来记住他们，之后可在「设置」中移除。",
  "This computer's ID":
    "本机 ID",
  "This computer's ID, reachable now":
    "本机 ID，当前可连接",
  "This computer's address on that network: {address}":
    "本机在该网络中的地址：{address}",
  "Tries a direct connection with encrypted relay fallback. No provider account is needed. Public relays have capacity limits and no uptime guarantee.":
    "优先尝试直连，失败时退回加密中继。无需服务商账号。公共中继有容量限制，也不保证可用性。",
  "Unattended access":
    "无人值守访问",
  "Unattended access:":
    "无人值守访问：",
  "Use another existing private network":
    "使用其他已有的私有网络",
  "Use my compatible relay server":
    "使用我自己的兼容中继服务器",
  "Use the full invitation instead":
    "改用完整邀请",
  "What their tools did":
    "对方的工具做了什么",
  "Your screen is being shared":
    "你的屏幕正在被共享",
  "may control":
    "可以控制",
  "may run commands and copy files":
    "可以执行命令和复制文件",
  "this code":
    "这个短码",
  "this invitation":
    "这份邀请",
  "{name} can connect to this computer any time. Remove them under Settings, Unattended access, to stop it.":
    "{name} 可以随时连接这台电脑。若要停止，请在「设置 → 无人值守访问」中移除。",
  "A number needs the same code service the person used. Otherwise ask them for the invitation text.":
    "纯数字短码需要与对方使用同一个短码服务。否则请让对方直接给你邀请文本。",
  "Boundary computer":
    "Boundary 电脑",
  "Code service URL":
    "短码服务地址",
  "Computer ID":
    "电脑 ID",
  "Connect to a computer":
    "连接到一台电脑",
  "Connect to someone who asked you for help":
    "连接到向你求助的人",
  "During the session they can choose to let you connect any time. The computer is then saved to your Library and opens unattended.":
    "会话期间，对方可以选择允许你随时连接。之后这台电脑会保存到你的资源库，并可无人值守直接打开。",
  "For a computer with unattended access switched on in DeskVNC or DeskVNC Support. A computer that paired you is already in your Library. Otherwise the person there approves you on their screen, and can pair you so you connect without asking next time.":
    "用于已在 DeskVNC 或 DeskVNC Support 中开启无人值守访问的电脑。已经与你配对过的电脑会自动出现在你的资源库里。否则需要对方在屏幕上批准你，并可以完成配对，之后连接就不再需要询问。",
  "Help someone":
    "帮助他人",
  "Help someone now":
    "立即帮助他人",
  "Help someone over the internet, with nothing to set up on either network.":
    "通过互联网帮助他人，双方网络都无需做任何配置。",
  "Kept in your system keychain, never in the Library file.":
    "保存在系统钥匙串中，绝不写入资源库文件。",
  "Name in your Library":
    "在资源库中的名称",
  "Opening…":
    "正在打开…",
  "Pasted from your clipboard.":
    "已从剪贴板粘贴。",
  "Save and connect":
    "保存并连接",
  "That is not a computer ID. Use Copy ID on that computer.":
    "这不是电脑 ID。请在那台电脑上使用「复制 ID」。",
  "The computer could not be saved to the Library":
    "无法把这台电脑保存到资源库",
  "Their code or invitation":
    "对方的短码或邀请",
  "Unattended password, if nobody is there to approve you":
    "无人值守密码（如果那边没人批准你）",
  "You copy it and open this window. It is pasted for you. They approve you on their screen.":
    "你复制它并打开这个窗口，系统会自动为你粘贴。对方在屏幕上批准后即可连接。",
  "Your name, shown to the person":
    "你的名字（对方能看到）",
  "A local connection check is followed by an actual Boundary session to verify the complete route. Private invitations disable public relay fallback.":
    "先做一次本地连通性检查，再用一次真实的 Boundary 会话验证完整链路。使用私有网络的邀请不会退回公共中继。",
  "Account ID":
    "账号 ID",
  "Cancel setup":
    "取消设置",
  "Cloudflare team name":
    "Cloudflare 团队名称",
  "Configure my account through the Cloudflare API":
    "通过 Cloudflare API 配置我的账号",
  "Could not read setup status. Reopen this dialog to reconnect.":
    "读取不到设置状态。请关闭后重新打开此对话框。",
  "Creates an email enrollment policy and private Mesh device profile, and enables device connectivity for the account. Existing access policies still apply.":
    "会创建一条邮箱注册策略和一个私有 Mesh 设备配置，并为该账号启用设备互联。已有的访问策略仍然有效。",
  "Device auth key (optional, leave empty for browser login)":
    "设备授权密钥（可选，留空则通过浏览器登录）",
  "Enrollment emails, separated by commas":
    "注册邮箱，用英文逗号分隔",
  "Install and connect":
    "安装并连接",
  "Install and connect this helper device to your own provider account. Run setup in Boundary on the recipient device as well, then create a new invitation.":
    "把这台协助设备安装并连接到你的服务商账号。在对方那台设备上也要运行一次 Boundary 的相同设置，然后重新创建邀请。",
  "Install the client and apply the setup described above":
    "安装客户端并应用上述设置",
  "Provider":
    "服务商",
  "Remove Boundary account resources":
    "移除 Boundary 账号资源",
  "Remove this deployment's Cloudflare enrollment policy and device profile. This can interrupt access.":
    "移除此部署创建的 Cloudflare 注册策略和设备配置。这可能导致连接中断。",
  "Scoped Cloudflare API token":
    "限定权限的 Cloudflare API 令牌",
  "Set up my private infrastructure":
    "设置我自己的私有网络",
  "The official client is installed if missing. Complete provider login and operating system permission prompts when they appear. Windows setup adds a UDP firewall rule limited to this app and the private provider network.":
    "如缺少官方客户端会先安装。请在弹窗出现时完成服务商登录和系统权限确认。Windows 上会添加一条仅限本应用和该私有网络的 UDP 防火墙规则。",
  "The name is supplied by the helper. Confirm it with the person you invited.":
    "这个名称由对方提供。请与你邀请的人核实。",
  "They are connecting with this computer's ID and are not paired with it. The name is supplied by the helper, so only allow someone you expect.":
    "对方正使用本机 ID 连接，且未与这台电脑配对。名称由对方提供，因此只应允许你预期之中的人。",
  "Approve this helper?":
    "允许这次协助吗？",
  "{name} wants to see your screen.":
    "{name} 请求查看你的屏幕。",
  "Helper connection identity":
    "对方连接的标识",
  "Also let their tools run commands and copy files on this computer":
    "同时允许对方的工具在这台电脑上执行命令和复制文件",
  "Their tools act as you, outside what the screen shows. Leave this off unless you asked for it. You can turn it off at any time, and each command shows here as it runs.":
    "对方的工具会以你的身份运行，屏幕上看不到它们做了什么。除非是你主动要求的，否则不要开启。你可以随时关闭，每条命令执行时都会显示在这里。",
  "Let them connect any time without asking me again":
    "允许对方随时连接，不再询问",
  "Allow viewing and control":
    "允许查看并控制",
  "Allow viewing":
    "仅允许查看",
  "Decline":
    "拒绝",
  "Accessibility permission is needed for control. You can allow viewing now.":
    "远程控制需要「辅助功能」权限。现在可以先允许查看。",
  "Your helper":
    "协助者",
  "{name} can see your screen.":
    "{name} 可以看到你的屏幕。",
  "{name} can see your screen and use your mouse and keyboard.":
    "{name} 可以看到你的屏幕，并能使用鼠标和键盘。",
  "Stop control":
    "停止控制",
  "Stop their commands":
    "停止对方的命令执行",
  "Their tools can run commands and copy files on this computer.":
    "对方的工具可以在这台电脑上执行命令和复制文件。",
  "{name} is connected to this computer and can use the mouse and keyboard":
    "{name} 已连接到这台电脑，并能使用鼠标和键盘",
  "{name} is connected to this computer, watching":
    "{name} 已连接到这台电脑，仅查看",
  "End their session":
    "结束对方的会话",
  "1-bit (dithered)":
    "1 位（抖动）",
  "Active only while this window is focused.":
    "仅在这个窗口获得焦点时生效。",
  "Auto, sharp when idle, faster under load":
    "自动：空闲时清晰，负载高时更快",
  "Balanced":
    "均衡",
  "Captured":
    "已接管键盘",
  "Captured. Press":
    "已接管键盘。按",
  "Checking whether SSH is available on this computer…":
    "正在检查远端是否支持 SSH…",
  "Collapse toolbar ({modifier}⇧M)":
    "收起工具栏（{modifier}⇧M）",
  "Connection status":
    "连接状态",
  "Decode":
    "解码",
  "Detect displays again":
    "重新检测显示器",
  "Disconnect (leaves the remote machine running)":
    "断开（远程机器继续运行）",
  "Displays":
    "显示器",
  "Drag to move toolbar":
    "拖动以移动工具栏",
  "Encoding":
    "编码",
  "Escape":
    "Esc 键",
  "Frame rate":
    "帧率",
  "Fullscreen ({hint})":
    "全屏（{hint}）",
  "How to enable it":
    "如何开启",
  "Keyboard":
    "键盘",
  "Keyboard captured, system shortcuts go to the remote (release: Ctrl+Alt+Shift+Esc)":
    "键盘已接管，系统快捷键发送到远端（释放：Ctrl+Alt+Shift+Esc）",
  "Keyboard: pass-through needs permission":
    "键盘：透传需要权限",
  "Keyboard: pass-through unavailable, {reason}":
    "键盘：无法透传，{reason}",
  "Keyboard: pass-through waiting for focus":
    "键盘：透传等待窗口获得焦点",
  "Latency":
    "延迟",
  "Needs Accessibility permission to intercept system shortcuts.":
    "拦截系统快捷键需要「辅助功能」权限。",
  "Pass system shortcuts to remote":
    "把系统快捷键传给远端",
  "Picture vs response":
    "画质与响应速度",
  "Pin toolbar (stay visible)":
    "固定工具栏（保持可见）",
  "Pointers":
    "指针",
  "Re-fetches the whole screen every second instead of trusting the server to report what changed. Fixes a picture that stays stale or smeared; uses more bandwidth.":
    "每秒重新获取整屏，而不依赖服务器报告变化。可解决画面停滞或拖影，代价是占用更多带宽。",
  "Received":
    "已接收",
  "Remote pointer":
    "远程指针",
  "Request full screen refresh":
    "请求整屏刷新",
  "Responsive, softer picture, lowest lag":
    "响应优先：画质略降，延迟最低",
  "Save screenshot":
    "保存截图",
  "Send clipboard to remote":
    "把剪贴板发送到远端",
  "Send to remote":
    "发送到远端",
  "Sends Alt+Tab, the Windows key and other system shortcuts to the remote instead of this computer.":
    "把 Alt+Tab、Windows 键等系统快捷键发送给远程电脑，而不是本机。",
  "Sends Cmd+Tab, Cmd+Space and other system shortcuts to the remote instead of this computer.":
    "把 Cmd+Tab、Cmd+Space 等系统快捷键发送给远程电脑，而不是本机。",
  "Session controls":
    "会话控制",
  "Sharp, best picture, never adapts":
    "清晰优先：最佳画质，不做自适应",
  "Show session toolbar ({modifier}⇧M), drag to move":
    "显示会话工具栏（{modifier}⇧M），可拖动",
  "Split down ({modifier}⌥⇧D)":
    "向下分屏（{modifier}⌥⇧D）",
  "Split right ({modifier}⌥D)":
    "向右分屏（{modifier}⌥D）",
  "Statistics arrive once the session reports them.":
    "会话开始上报后才会显示统计数据。",
  "System shortcuts are going to the remote. Press Ctrl+Alt+Shift+Esc to release.":
    "系统快捷键正在发送到远端。按 Ctrl+Alt+Shift+Esc 释放。",
  "Terminal (SSH)":
    "终端（SSH）",
  "Terminal needs SSH on the remote computer, and it isn't reachable on this one":
    "终端需要远端开启 SSH，而当前无法连通",
  "This server does not say where its monitors meet: detection reads the picture, the other cuts are guesses by width.":
    "该服务器没有说明显示器如何拼接：检测会读取画面，其余切分只是按宽度猜的。",
  "This server has not described its monitors, so the whole desktop is one display.":
    "该服务器没有描述自己的显示器，因此整个桌面视为一块屏幕。",
  "This session is using a single display. Turn on “Use all of my monitors” in this computer's settings to use more.":
    "当前会话只有一块屏幕。要使用更多屏幕，请在那台电脑的设置中开启「使用我的全部显示器」。",
  "Throughput":
    "吞吐量",
  "Unpin toolbar (allow auto-hide)":
    "取消固定工具栏（允许自动隐藏）",
  "View only: off, click to block input":
    "仅查看：已关闭，点击可禁止输入",
  "View only: on, click to allow input":
    "仅查看：已开启，点击可允许输入",
  "Windows/Super key":
    "Windows/Super 键",
  "Zoom":
    "缩放",
  "Zoom percentage":
    "缩放百分比",
  "to release.":
    "释放。",
  "{n} levels":
    "{n} 级",
  "Resolving":
    "正在解析地址",
  "Connecting":
    "正在连接",
  "Authenticating ({method})":
    "正在认证（{method}）",
  "Negotiating":
    "正在协商参数",
  "Preparing":
    "正在准备",
  "Connecting to {name}":
    "正在连接到 {name}",
  "Disconnected from {name}":
    "与 {name} 的连接已断开",
  "Reconnecting asks for the password again instead of reusing the saved one.":
    "重新连接时会重新询问密码，而不是复用已保存的那个。",
  "Open this computer's security settings":
    "打开这台电脑的安全设置",
  "Save this computer to your library first, then change the setting in its settings.":
    "请先把这台电脑保存到资源库，再在它的设置中修改该项。",
  "Reconnect":
    "重新连接",
  "Press Esc to close this window":
    "按 Esc 关闭此窗口",
  "Reconnecting to {name}… attempt {attempt} · retrying in {secs}s":
    "正在重新连接 {name}…第 {attempt} 次 · {secs} 秒后重试",
  "Reconnecting to {name}… attempt {attempt} · retrying now":
    "正在重新连接 {name}…第 {attempt} 次 · 正在重试",
  "Disconnect":
    "断开连接",
  "Retry now":
    "立即重试",
  "Connection failed":
    "连接失败",
  "Verifying host key":
    "正在验证主机密钥",
  "Host key changed":
    "主机密钥已变化",
  "Connecting…":
    "正在连接…",
  "Connected":
    "已连接",
  "Reconnecting (attempt {n})":
    "正在重连（第 {n} 次）",
  "Disconnected":
    "已断开",
  "Terminal, {host}":
    "终端：{host}",
  "Close terminal":
    "关闭终端",
  "Reconnecting… attempt {attempt} · retrying in {secs}s":
    "正在重连…第 {attempt} 次 · {secs} 秒后重试",
  "Reconnecting… attempt {attempt} · retrying now":
    "正在重连…第 {attempt} 次 · 正在重试",
  "Reconnect now":
    "立即重连",
  "The connection was closed.":
    "连接已关闭。",
  "Couldn't open a terminal":
    "无法打开终端",
  "Try again":
    "重试",
  "Reattached to your tmux session":
    "已重新接上你的 tmux 会话",
  "A name cannot be empty, contain a slash, or be “.” or “..”.":
    "名称不能为空，不能包含斜杠，也不能是「.」或「..」。",
  "Cancel transfer of {name}":
    "取消 {name} 的传输",
  "Cancelled":
    "已取消",
  "Close files":
    "关闭文件面板",
  "Connect the file-transfer channel first":
    "请先建立文件传输通道",
  "Create":
    "创建",
  "Delete":
    "删除",
  "Delete {count} items on {where}?":
    "要删除{where}上的 {count} 个项目吗？",
  "Done":
    "完成",
  "Download":
    "下载",
  "Download the selected remote files into the local folder":
    "把选中的远端文件下载到本地文件夹",
  "Drop to send {count} files to {host}":
    "松开即把 {count} 个文件发送到 {host}",
  "Enter opens · Backspace goes up · Ctrl/⌘+A selects all · F2 renames · Del removes":
    "Enter 打开 · Backspace 上一层 · Ctrl/⌘+A 全选 · F2 重命名 · Del 删除",
  "Failed":
    "失败",
  "File transfer is blocked. This is either a reinstalled server or someone intercepting the connection, there is no “continue anyway”. Verify the new key out of band and remove the stored pin before reconnecting.":
    "文件传输已被阻止。这要么是服务器被重装了，要么是有人在中间人攻击这个连接，这里没有「仍然继续」这个选项。请通过其他渠道核实新密钥，并删除已保存的指纹后再重新连接。",
  "Files, {host}":
    "文件：{host}",
  "First connection to {host}:{port}":
    "首次连接到 {host}:{port}",
  "Folders are removed with everything inside them. This cannot be undone.":
    "文件夹会连同里面的所有内容一起删除，且无法撤销。",
  "Local":
    "本地",
  "Modified":
    "修改时间",
  "New folder":
    "新建文件夹",
  "New folder in the local folder":
    "在本地文件夹中新建文件夹",
  "New folder in the remote folder":
    "在远端文件夹中新建文件夹",
  "Remote, {host}":
    "远端：{host}",
  "Rename":
    "重命名",
  "Rename (F2)":
    "重命名（F2）",
  "Size":
    "大小",
  "The SSH identity of {host}:{port} has changed":
    "{host}:{port} 的 SSH 身份已发生变化",
  "This computer's SSH identity has not been seen before. Check the fingerprint against the server before trusting it.":
    "此前没见过这台电脑的 SSH 身份。请在信任之前，把指纹与服务器上的核对一下。",
  "Upload":
    "上传",
  "Upload the selected local files (or choose files) to the remote folder":
    "把选中的本地文件（或另选文件）上传到远端文件夹",
  "expected":
    "预期",
  "received":
    "实际收到",
  "this computer":
    "这台电脑",
  "{count} items":
    "{count} 个项目",
  "{count} selected":
    "已选 {count} 个",
  "Hide dot-files":
    "隐藏以点开头的文件",
  "Show hidden files":
    "显示隐藏文件",
  "Copy this line":
    "复制这一行",
  "Copy":
    "复制",
  "The token goes straight to the clipboard. It is never shown here.":
    "令牌会直接放进剪贴板，界面上不会显示。",
  "Copy the token":
    "复制令牌",
  "On the clipboard. Paste it into the prompt above.":
    "已复制到剪贴板。请粘贴到上面的提示里。",
  "This build will not hand it over. Read it from dvv doctor instead.":
    "此版本不会交出该令牌。请改用 dvv doctor 读取。",
  "It is never shown here, only copied.":
    "这里只负责复制，从不显示。",
  "Connect Claude Code":
    "连接 Claude Code",
  "This registers the server for you. No terminal, nothing to copy.":
    "自动为你注册服务器，无需打开终端，也无需复制任何内容。",
  "This build cannot run setup. Run dvv setup in a terminal instead.":
    "此版本无法执行自动设置。请在终端中运行 dvv setup。",
  "OpenCode, Pi, Claude Code and Codex":
    "OpenCode、Pi、Claude Code 和 Codex",
  "Connected automatically each time DeskVNC starts. Installed a new agent just now? Connect it without restarting.":
    "每次 DeskVNC 启动时会自动连接。刚刚装了新的代理？不用重启也能连上。",
  "Connect now":
    "立即连接",
  "What an agent can do":
    "代理能做什么",
  "Open one of your saved machines. The credential comes from the keychain, and the agent neither supplies it nor sees it.":
    "打开你已保存的某台机器。凭据从钥匙串读取，代理既不提供也看不到它。",
  "Drive it and watch itself work: pointer, keyboard, clipboard, and the screen.":
    "操作它并观察自己的动作：指针、键盘、剪贴板和屏幕。",
  "Run a command over SSH and read the output back, with the exit code it really got.":
    "通过 SSH 执行命令并读回输出，包括真实的退出码。",
  "Hand control back the instant you want it. Clicking a pane, or pressing stop, takes the lease.":
    "你随时可以收回控制权。点击窗格或按下停止，就会夺取控制权。",
  "Answer a password or a certificate prompt. Those stay yours.":
    "替你回答密码或证书提示。这些始终由你本人处理。",
  "That one is deliberate and it is not going to change. An agent that could type a secret it read off a screen would leave a record saying you approved it, and a record that says the wrong thing is worse than none.":
    "这一条是刻意设定的，不会改变。如果代理能替你输入从屏幕上读到的密钥，就会留下一条「你批准过」的记录，而记录写错了比没有记录更糟。",
  "Do it by hand, or connect a different agent":
    "手动配置，或连接其他代理",
  "Register it yourself":
    "自行注册",
  "Or reach it over HTTP":
    "或者通过 HTTP 访问",
  "Starts a listener on {url} and prints the line below with your token already in it. Loopback only, and it needs the token even there, because any page your browser has open can reach a port on this machine.":
    "在 {url} 上启动一个监听，并打印下面那行（已带上你的令牌）。仅监听本机回环地址；即使如此也需要令牌，因为浏览器里打开的任何页面都能访问本机端口。",
  "Check it":
    "验证一下",
  "It prints the socket path and whether it is present. Present means this application is running with the plane on, which is what an agent needs.":
    "它会打印套接字路径以及是否存在。存在即表示本应用正在运行且代理平面已开启，这正是代理所需要的。",
  "AI agents":
    "AI 代理",
  "Then ask your agent to open one of your machines by name. It reads the same library you see here.":
    "然后让你的代理按名字打开某台机器。它读取的就是你在这里看到的同一个资源库。",
  "The plane is on.":
    "代理平面已开启。",
  "Close the socket and unlink it. Every agent loses its connection at once.":
    "关闭套接字并删除它，所有代理会同时断开连接。",
  "Turn it off":
    "关闭",
  "An agent can open your machines, drive them and read the screen, while you watch and take over whenever you want.":
    "代理可以打开你的机器、操作它们并读取屏幕，而你随时可以查看并接手。",
  "It is off because it was switched off on this computer. While it is off there is no socket, nothing is listening, and your agents cannot reach your machines.":
    "它在这台电脑上被关闭了。关闭期间不存在套接字，也没有任何监听，代理无法访问你的机器。",
  "The last attempt to start it failed: {error}":
    "上次尝试启动失败：{error}",
  "Turn it back on":
    "重新开启",
  "One socket, on this computer only. Nothing opens on the network.":
    "仅在本机上一个套接字，不在网络上开放任何端口。",
  "Nobody":
    "无",
  "Agent {name}":
    "代理 {name}",
  "Service {name}":
    "服务 {name}",
  "Driver {name}":
    "驱动方 {name}",
  "1 agent":
    "1 个代理",
  "{n} agents":
    "{n} 个代理",
  "No agent connected":
    "没有已连接的代理",
  "{agents} connected, none driving":
    "已连接 {agents}，均未操作",
  "{agents} driving {driving} of {sessions}":
    "{agents} 正在操作 {driving}/{sessions}",
  "{agents} driving {driving}":
    "{agents} 正在操作 {driving} 台",
  "No agent is attached to this computer.":
    "这台电脑上没有已连接的代理。",
  "1 session is live in all.":
    "共有 1 个会话在运行。",
  "{n} sessions are live in all.":
    "共有 {n} 个会话在运行。",
  "None of them holds a lease, so nothing is being driven":
    "它们都没有持有控制权，因此没有在操作任何机器",
  "1 machine is being driven":
    "1 台机器正在被操作",
  "{n} machines are being driven":
    "{n} 台机器正在被操作",
  "{agents} attached.":
    "已连接 {agents}。",
  "Driving means an agent holds the lease; an attached agent that holds none is driving nothing.":
    "「正在操作」表示代理持有了那台机器的控制权；只连接而未持有的代理并没有在操作任何东西。",
  "remote terminal":
    "远端终端",
  "remote screen":
    "远端屏幕",
  "Holding the lease, nothing in flight":
    "持有控制权，当前无进行中的操作",
  "Show this machine":
    "定位到这台机器",
  "Stop the agent driving {machine}, and take control":
    "停止正在操作 {machine} 的代理并接管",
  "Stop {holder} and take control":
    "停止 {holder} 并接管",
  "Capability: {capability}":
    "权限：{capability}",
  "You took the wheel from {agent}":
    "你已从 {agent} 手中接管",
  "Input is yours, the agent was stopped":
    "输入已归你，代理已停止",
  "Agent activity":
    "代理活动",
  "Take every lease back from every agent, at once":
    "一次性收回所有代理的控制权",
  "Stop all":
    "全部停止",
  "Remote desktop: {name}":
    "远程桌面：{name}",
  "Shortcut pass-through isn't available here":
    "此环境不支持快捷键透传",
  "Everything the browser engine can see still reaches the remote. For the shortcuts it can't, use {send} in the keyboard menu, Ctrl+Alt+Del, Cmd/Alt+Tab and the Windows key are all deliverable that way.":
    "浏览器引擎能看到的所有按键仍会发到远端。对于它看不到的快捷键，可以用键盘菜单里的{send}：Ctrl+Alt+Del、Cmd/Alt+Tab 和 Windows 键都能这样发送。",
  "Got it":
    "知道了",
  "Let this app capture system shortcuts":
    "允许本应用截获系统快捷键",
  "To send ⌘Tab, ⌘Space and ⌘Q to the remote computer instead of this one, macOS has to let this app see keys before the window server does.":
    "要把 ⌘Tab、⌘Space 和 ⌘Q 发送给远程电脑而不是本机，macOS 必须允许本应用在窗口服务器之前看到按键。",
  "To send Alt+Tab and the Windows key to the remote computer instead of this one, the system has to let this app see keys before the shell does.":
    "要把 Alt+Tab 和 Windows 键发送给远程电脑而不是本机，系统必须允许本应用在 shell 之前看到按键。",
  "macOS calls this <strong>Accessibility</strong>. It is only used while a session window is focused and pass-through is switched on. Keys are forwarded to the remote computer you are connected to and are never stored or sent anywhere else.":
    "macOS 称这项权限为<strong>辅助功能</strong>。仅在会话窗口获得焦点且已开启透传时使用。按键只会转发给你当前连接的远程电脑，绝不存储，也不会发往别处。",
  "You can release the keyboard at any time with {chord}, and it releases automatically when this window loses focus or closes.":
    "随时可以按 {chord} 释放键盘；窗口失焦或关闭时也会自动释放。",
  "Not now":
    "暂不",
  "Open System Settings":
    "打开系统设置",
  "Turn pass-through on":
    "开启透传",
  "Allow…":
    "允许…",
  "Already allowed but still not working? A macOS update or a new build can silently invalidate the grant, remove the app from the Accessibility list and add it again.":
    "已经允许了却仍然无效？macOS 更新或新的构建版本可能会悄悄让授权失效，请在「辅助功能」列表中移除本应用后重新添加。",
  "This session ran into a problem":
    "这个会话出了问题",
  "The connection has been closed. Nothing was saved from this session.":
    "连接已关闭。本次会话的内容没有被保存。",
  "Close tab":
    "关闭标签页",
  "Close window":
    "关闭窗口",
  "Connection info":
    "连接信息",
  "{count} files to {target}":
    "正在把 {count} 个文件发送到 {target}",
  "Screenshot saved":
    "截图已保存",
  "Could not read the local clipboard":
    "无法读取本机剪贴板",
  "Clipboard sent to remote":
    "剪贴板已发送到远端",
  "Reconnected":
    "已重新连接",
  "Authentication was cancelled. Reconnect to try again.":
    "身份验证已取消，重新连接即可再试。",
  "This computer's domain does not accept the sign-in method this version uses. An administrator has set “Restrict NTLM: Incoming NTLM traffic” or raised “LAN Manager authentication level” on the remote computer, so it will only accept Kerberos. Kerberos sign-in is coming in a later release. Until then this computer can be reached from a client that speaks Kerberos, or an administrator can allow NTLM for it.":
    "这台电脑所在的域不接受本版本使用的登录方式。管理员在远程电脑上设置了「限制 NTLM：传入 NTLM 流量」或调高了「LAN Manager 身份验证级别」，因此它只接受 Kerberos。Kerberos 登录会在后续版本中支持。在此之前，可以用支持 Kerberos 的客户端连接，或请管理员为它放开 NTLM。",
  "The computer refused network level authentication. If it is an older or non-Windows server, turn on “Allow connecting without network level authentication” in this computer's settings.":
    "这台电脑拒绝了网络级身份验证。如果它是较旧的服务器或非 Windows 服务器，请在它的设置中开启「允许在无网络级身份验证的情况下连接」。",
  "This computer only offers TLS 1.0 or 1.1 to encrypt the connection, and this app does not use those versions unless you say so. That is normal for a Windows 7 or Server 2008 R2 machine that was never updated. To connect anyway, edit this computer, open Advanced, then Security, and tick “Allow legacy TLS (1.0 and 1.1)”. Read what it says there first: those versions are weak, and that is the reason it is off by default.":
    "这台电脑只提供 TLS 1.0 或 1.1 来加密连接，而本应用除非你明确允许，否则不会使用这两个版本。对于从未更新过的 Windows 7 或 Server 2008 R2 机器，这是正常现象。如果确实要连接，请编辑这台电脑，打开「高级」，再进入「安全」，勾选「允许旧版 TLS（1.0 和 1.1）」。请先看看那里的说明：这两个版本本身很弱，这也是它们默认关闭的原因。",
  "This computer only offers TLS 1.0 or 1.1, and this copy of the app was built without support for them, so the setting you turned on cannot be used. A build that includes legacy TLS support will connect. Nothing you change here will help, and nothing is wrong with the computer you are connecting to.":
    "这台电脑只提供 TLS 1.0 或 1.1，而当前这个构建版本没有编译进对它们的支持，所以即使你打开了那个设置也无法生效。改用包含旧版 TLS 支持的构建版本即可连接。在这里做任何改动都没用，你要连接的那台电脑本身也没有问题。",
  "This machine has not been trusted yet, so the connection stopped rather than trusting it silently. Reconnect to see its fingerprint and decide.":
    "这台机器尚未被信任，因此连接直接中止，而不是默默信任它。重新连接即可看到它的指纹并作出决定。",
  "This machine is presenting a different SSH identity than the one you trusted before. That can mean it was reinstalled, or that something is sitting in the middle of the connection, and there is no way to tell which from here, so the connection was refused. If you know the key legitimately changed, forget the saved key for this machine and connect again.":
    "这台机器出示的 SSH 身份与你之前信任的不一致。这可能是机器被重装过，也可能有第三方处在连接中间，从这边无法分辨，因此连接被拒绝。如果你确认密钥是正常更换的，请忘记这台机器已保存的密钥后重新连接。",
  "Connection refused, nothing is listening on that port.":
    "连接被拒绝，该端口上没有服务在监听。",
  "The computer didn't respond, it may be asleep, off, or unreachable from this network.":
    "对方没有响应。它可能处于睡眠、已关机，或从这个网络访问不到。",
  "Incorrect password, the server did not accept it.":
    "密码不正确，服务器没有接受。",
  "The secure connection could not be verified.":
    "无法验证这条安全连接。",
  "The connection was closed by the other side.":
    "连接被对方关闭。",
  "The connection ended.":
    "连接已结束。",
  "Enter an address before the colon":
    "请在冒号前填写地址",
  "Port must be between 1 and 65535":
    "端口必须在 1 到 65535 之间",
  "Enter an address":
    "请输入地址",
  "Enter the 64 character ID shown under Unattended access in DeskVNC Support":
    "请输入 DeskVNC Support 中「无人值守访问」下显示的 64 位 ID",
  "An address cannot contain spaces":
    "地址中不能包含空格",
  "An address cannot contain / ? # or @":
    "地址中不能包含 / ? # 或 @",
  "Write an IPv6 address as [::1] or [::1]:5901":
    "IPv6 地址请写成 [::1] 或 [::1]:5901",
  "Add a port or display number after the colon":
    "请在冒号后补上端口或显示编号",
  "This folder is empty.":
    "这个文件夹是空的。",
};
