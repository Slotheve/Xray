# Xray内核搭建VMESS/VLESS/TROJAN/SHADOWSOCKS

- 自用Xray,此脚本只为隧道或IPLC/IEPL中转而生,无任何伪装
- vless/Trojan的tls除非自定义证书路径,否则也是本地生成的无效证书
- vless/Trojan非自定义证书路径请务必开启: skip-cert-verify: true

## 一键脚本
```yaml
bash <(curl -fsSL https://raw.githubusercontent.com/Slotheve/Xray-proxy/main/xray.sh)
```
