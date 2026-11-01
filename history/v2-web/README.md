# 网站登录版管理入口 / 2.0.1

正式入口：[https://relay.example.invalid/relay-admin/](https://relay.example.invalid/relay-admin/)。
不再需要本机 SSH 打开器；原私有127.0.0.1:18780面板和打开器仍保留。
使用既有家宽管理口令，与网站会员账号、1Panel、SSH密码分开。不修改原账号数据库。
朋友出口端和消费者连接器完全不变，无需升级或重新登记现有节点。

## 独立边界
- 新增 `home-relay-web.service`，只绑定127.0.0.1:18782；新进程通过固定loopback HTTP地址调用原管理控制器。
- 原V1/V2转发服务、SSH和网站业务容器不重启，不修改原控制器、代理配置或节点库结构。
- 网站公共路由只在末尾追加独立include；原首页/JS/CSS、原路由字节、业务数据库、WAF/Fail2ban、防火墙与FlClash均保留。
- 仅使用既有HTTPS443，不开放新公网端口，不公开127.0.0.1:18780、18781、18782或数据端口。
- 网关无管理员SSH私钥、无网站/节点库/原代理配置读取权限，只能连接loopback；CPU10%、内存80MiB、12工作线程。
- 只允许登录、查询节点、已知节点的状态/备注/检测/连接配置下载和退出；私有一次性登录链接接口不公开。

## 登录与会话
HTTPS终止于现有OpenResty，内部请求由固定Host/Proto及独立随机代理上下文标记校验。
该内部标记不是登录凭据；认证仍由原控制器验证现有管理口令。
浏览器会话与原控制器会话分离，后端Cookie/CSRF仅保留网关内存，不发给浏览器。
网站Cookie为Secure、HttpOnly、SameSite=Strict，host-only，Path限定/relay-admin/；2小时绝对有效期，空闲30分钟过期。
所有写操作要求同源Origin、JSON及会话CSRF；登录每IP4次/分钟、总计6次/分钟，认证串行，避免口令哈希并发挤占原服务内存。
原后台还保留自身限流；网关限制8个活跃网站会话，不为公共访问放宽原控制器权限。
管理路由不记录请求访问日志，响应no-store、禁止iframe，无外部脚本/CDN。节点使用配置仅授权管理员登录后可下载。
同一域名路径不是独立安全来源；原站本身的脚本与账号防护仍需保持。不能把隐藏路径当鉴权。

## 服务器文件
- `/opt/home-relay-web/`：root-owned只读源码和独立静态页面。
- `/etc/home-relay-web/web.json`：root-only内部代理上下文标记，由systemd LoadCredential读取；不在发行包。
- `/etc/systemd/system/home-relay-web.service`：独立受限单元。
- `/opt/1panel/www/sites/example-site/home-relay-admin.conf`：独立HTTPS location，含内部上下文标记，root0600。
- `/opt/1panel/www/conf.d/00-home-relay-web-limits.conf`：仅供新管理路由使用的独立限流/连接zone。
- `/var/backups/home-relay-web/20261031-191451/`：本次定向前像，不可覆盖后来的并发站点修改。

源码中的Nginx文件为脱敏模板，不含运行标记、管理密码、Cookie、节点凭据或任何SSH私钥。
部署为已执行的一次性变更，不要重跑历史脚本覆盖现有生产。

## 只回退网站管理入口
读取当前配置前像并定向备份；从最新公共路由移除本次home-relay-admin.conf include，移除本次独立location/zone文件引用。
nginx -t通过后仅优雅reload OpenResty，再单独停止/禁用home-relay-web.service。
不停止原home-relay-v2-controller/proxy或V1服务，不改SSH/云防火墙/网站数据库，不删除节点/凭据。

## 依据
- [Nginx官方proxy_pass及代理头文档](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)
- [OWASP会话管理文档](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
