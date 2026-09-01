# AdGuard-Rules

AdGuard 广告过滤规则合集，每日自动更新。

> 本项目仅作个人学习存档使用，无开源许可证，禁止二次分发、爬取、转载。



## 规则统计

| 规则文件 | 说明 | 规则数量 | 下载链接 |
| :--- | :--- | :--- | :--- |
| adguard_rules.txt | AdGuard DNS 格式完整规则集，适用于 AGHForRoot / AdGuard Home | 1092302 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/adguard_rules.txt) |
| hosts_rules.txt | Hosts 格式，适用于 bindhosts 等 Magisk 模块 | 257678 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/hosts_rules.txt) |
| hosts_rules_dedup.txt | 去重版，去掉 AdGuard 已覆盖域名，可搭配 adguard_rules.txt 使用 | 10193 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/hosts_rules_dedup.txt) |
| adguard_lite.txt | AdGuard 格式精简版（仅广告过滤） | 213743 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/adguard_lite.txt) |
| hosts_lite.txt | Hosts 格式精简版（仅广告过滤） | 111312 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/hosts_lite.txt) |
| hosts_lite_dedup.txt | 去重版精简 Hosts，可搭配 adguard_lite.txt 使用 | 10168 | [点击下载](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/hosts_lite_dedup.txt) |

⏰ 最后更新: 2026-09-01 17:05:54

## 白名单规则

> 当前收录白名单 **152** 条域名（含自定义与远程订阅源提取），已单独整理为 [whitelist.txt](https://github.com/Wuming155/AdGuard-Rules/releases/latest/download/whitelist.txt)，可按需导入以放行下列域名。

### 📱 手机系统与厂商基础服务

**Vivo / 小V助手**

- `sysupgrade.vivo.com.cn` — Vivo 系统升级检测
- `update.appstore.vivo.com.cn` — 应用商店更新服务
- `isecure.vivo.com.cn` — 小V电话助手 - 摘要功能

**小米 / MIUI / HyperOS**

- `resolver.msg.xiaomi.net` — 小米推送通道（系统级推送唤醒）
- `resolver.msg.global.xiaomi.net`
- `resolver.mi.xiaomi.com`
- `resolver.gslb.mi-idc.com`
- `api.xmpush.xiaomi.com`
- `micloud.xiaomi.net` — 小米云服务（相册/状态/API）
- `api.device.xiaomi.net`
- `a0.app.xiaomi.com`
- `thm.market.xiaomi.com`
- `t1.market.xiaomi.com`
- `t2.market.xiaomi.com`
- `t2.a.market.xiaomi.com`
- `t3.market.xiaomi.com`
- `t3.a.market.xiaomi.com`
- `t4.market.xiaomi.com`
- `t5.market.xiaomi.com`
- `a.market.xiaomi.com`
- `connect.rom.miui.com` — 小米 rom
- `browser.miui.com` — 小米浏览器服务
- `api.browser.miui.com`
- `testit.miui.com` — 小米安全与通信服务
- `api.comm.miui.com`
- `api.developer.xiaomi.com`
- `api.vip.miui.com`
- `i.xiaomi.com` — 小米其他服务
- `cnbj1.fds.api.xiaomi.com`
- `cn.app.chat.xiaomi.net`
- `app.chat.xiaomi.net`
- `mdap.alipay.com` — 支付宝安全账户

**OPPO / ColorOS / HeyTap**

- `apps.coloros.com` — OPPO 应用商店及推送通道
- `conn1.coloros.com`
- `conn2.coloros.com`
- `conn3.coloros.com`
- `conn4.coloros.com`
- `conn5.coloros.com`
- `client-uc.heytapmobi.com`
- `i6.weather.oppomobile.com` — OPPO 天气服务

### 💬 社交、即时通讯与账号登录

**微软邮箱**

- `outlook.office.com` — Outlook / Office 365 邮箱服务

**腾讯 / 微信 / QQ**

- `szlong.weixin.qq.com` — 微信长连接（即时通讯推送保障）
- `wximg.wxs.qq.com` — 微信图片/素材 CDN
- `cgi.connect.qq.com` — QQ 连接 & 登录服务
- `c.pc.qq.com`
- `q2.qlogo.cn`
- `msdk.qq.com` — 腾讯移动 SDK（MSDK）
- `ssl.msdk.qq.com`
- `ap6.ssl.msdk.qq.com`

**安全验证与风险控制**

- `ac.dun.163.com` — 网易易盾 - 验证码/风控
- `castatic.fengkongcloud.com` — 数美科技 - 风控 SDK

**其他社交与社区**

- `tantanapp.com`
- `vk.com`

### 🎬 视频、音乐与娱乐

**B站 / 腾讯视频 / 爱奇艺 / 喜马拉雅 / 网易云**

- `api.live.bilibili.com` — B站直播 API
- `chat.bilibili.com` — B站弹幕服务
- `biligame.com` — B站游戏
- `lllocation.ximalaya.com` — 喜马拉雅音频播放（注意：lllocation 为双 l 开头）
- `vv.video.qq.com` — 腾讯视频
- `vmat.gtimg.com`
- `cmts.iqiyi.com` — 爱奇艺弹幕服务

### 🛒 电商、金融与支付

**淘宝 / 阿里 / 搜狗**

- `amdc.m.taobao.com` — 淘宝移动网络调度
- `appdownload.alicdn.com` — 阿里 CDN 应用下载

**京东 / 唯品会 / 一号店**

- `gia.jd.com` — 京东服务（物流/广告/统计）
- `wl.jd.com`
- `ccc-x.jd.com`
- `knicks.jd.com`

### 🤖 人工智能（AI）服务

- `api.trae.cn` — Trae AI 编程助手
- `chat.z.ai` — Chat Z AI
- `sider.ai` — Sider AI 浏览器助手

### ☁️ 云存储、CDN 与开发者服务

**华为云 OBS**

- `obs.cn-east-2.myhuaweicloud.com`
- `obs.cn-east-3.myhuaweicloud.com`
- `obs.cn-north-1.myhuaweicloud.com`
- `obs.cn-north-2.myhuaweicloud.com`
- `obs.cn-north-4.myhuaweicloud.com`
- `obs.cn-south-1.myhuaweicloud.com`
- `file-contents-abc.obs.cn-north-4.myhuaweicloud.com`

**百度云 / 百度 CDN**

- `bce.baidu.com`
- `ms.bdstatic.com`
- `staticsns.cdn.bcebos.com`

**myhkw.cn 云服务**

- `myhkw.cn`

**CDN、网络节点与诊断工具**

- `lf6-cdn-tos.bytecdntp.com` — 字节跳动 CDN
- `lf3-data.volccdn.com`
- `tnc3-alisc1.bytedance.com`
- `testingcf.jsdelivr.net` — jsDelivr CDN
- `testingcf.jsdelivr.net.cdn.cloudflare.net`
- `conn-service-cn-03.allawntech.com` — Allawntech 连接服务
- `conn-service-cn-04.allawntech.com`
- `conn-service-cn-05.allawntech.com`
- `natfrp.cloud` — SakuraFrp 内网穿透
- `nstool.netease.com` — 网易网络诊断
- `sentry.io` — Sentry 错误日志收集

### 🌐 常用网站与应用

- `statics.123pan.com` — 123云盘

**门户、资讯与生活服务**

- `erebor.douban.com` — 豆瓣
- `simg.sinajs.cn` — 新浪微博 CDN
- `edith.xiaohongshu.com` — 小红书
- `duiba.com.cn` — 兑吧（积分兑换）
- `dui88.com`
- `17u.cn` — 同程旅游
- `nisportal.10010.com` — 联通营业厅

**开发者工具与在线服务**

- `online-metrix.net` — Online Metrix 反欺诈
- `ynuf.aliapp.org` — 阿里云推送

**其他网站与工具**

- `360.cn` — 360.cn 安全服务
- `www.360.cn`
- `jiagu.360.cn`

### 🌐 远程订阅源提取

- `ad-block.dns.adguard.com`
- `ad-gone.com`
- `ad-putting.gw.zt-express.com`
- `ad.azure.com`
- `ad.cityu.edu.hk`
- `ad.jp`
- `ad.siemens.com.cn`
- `ads.privacy.qq.com`
- `ads.taboola.com`
- `advertisement.taobao.com`
- `analysis.chess.com`
- `analysis.windows.net`
- `api.huangye.miui.com`
- `app.adjust.com`
- `app.powerbi.com`
- `autocomplete.clearbit.com`
- `baozhang.baidu.com`
- `center-h5api.m.taobao.com`
- `chart-embed.service.newrelic.com`
- `counter-strike.net`
- `dxcloud.episerver.net`
- `edge-enterprise.activity.windows.com`
- `edge.activity.windows.com`
- `ftp.bmp.ovh`
- `future.biz.weibo.com`
- `insideruser.microsoft.com`
- `log.mmstat.com`
- `meizu.coapi.moji.com`
- `news-app.abumedia.yql.yahoo.com`
- `passport.bobo.com`
- `profile*.se.360.cn`
- `s.mvconf.f.360.cn`
- `sdkapi.sms.mob.com`
- `settings-win.data.microsoft.com`
- `skyapi.onedrive.live.com`
- `skydrivesync.policies.live.net`
- `stat.jseea.cn`
- `stats.gov.cn`
- `stats.uptimerobot.com`
- `storage.live.com`
- `tj.gov.cn`
- `tongji.cn`
- `tongji.edu.cn`
- `tracker.eu.org`
- `tube.e.kuaishou.com`
- `uland.taobao.com`
- `widget.intercom.io`
- `www.msftconnecttest.com`
