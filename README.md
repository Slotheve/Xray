# Xray内核搭建SS,VMESS,TROJAN(非自定义证书路径请务必开启: skip-cert-verify: true)
- 自用Xray,此脚本只为隧道或IPLC/IEPL中转而生,无任何伪装
- Trojan的tls除非自定义证书路径,否则也是本地生成的无效证书

```yaml
bash <(curl -fsSL https://raw.githubusercontent.com/Slotheve/Xray-proxy/main/xray.sh)
  ```
