# Environment

## VPN

<https://github.com/v2fly/fhs-install-v2ray>

### server

```bash
sudo firewall-cmd --zone=public --add-port=1194/tcp --permanent
sudo firewall-cmd --zone=public --add-port=1194/udp --permanent
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports

/usr/local/etc/v2ray
systemctl start v2ray@offsec_server
```

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 1194,
      "protocol": "shadowsocks",
      "settings": {
        "method": "aes-256-gcm",
        "password": "password",
        "network": "tcp,udp",
        "level": 0
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
```

### client

<https://gist.githubusercontent.com/glzjin/e287bd66d6dc0cbaf61dd5998ad24f66/raw/fed0ea7b0f7365a4d04708880a6c25bc7545dde0/v2-for-offsec-config.json>

```bash
systemctl start v2ray@offsec_client
```

```json
// Config file of V2Ray. This file follows standard JSON format, with comments support.
// Uncomment entries below to satisfy your needs. Also read our manual for more detail at
// https://www.v2fly.org/
{
    "log": {
      // By default, V2Ray writes access log to stdout.
      // "access": "/path/to/access/log/file",
  
      // By default, V2Ray write error log to stdout.
      // "error": "/path/to/error/log/file",
  
      // Log level, one of "debug", "info", "warning", "error", "none"
      "loglevel": "warning"
    },
    // List of inbound proxy configurations.
    "inbounds": [{
        "port": 1194,
        "listen": "127.0.0.1",
        "protocol": "dokodemo-door",
        "settings": 
        {
          "address": "vpn-pool1.offseclabs.com",
              "port": 1194,
              "network": "udp",
              "protocol": "",
              "followRedirect": false
        }
      }
      ],
    // List of outbound proxy configurations.
    "outbounds": [{
    "protocol": "shadowsocks",
        "settings": {
          "servers": [
              {
                "address": "server ip",
                "port": 1194,
                "method": "aes-256-gcm",
                "password": "password"
              }
            ]
        }
        
      }],
  
    // Transport is for global transport settings. If you have multiple transports with same settings
    // (say mKCP), you may put it here, instead of in each individual inbound/outbounds.
    //"transport": {},
  
    // Routing controls how traffic from inbounds are sent to outbounds.
    "routing": {
      "domainStrategy": "IPOnDemand",
      "rules":[
        {
          // Blocks access to private IPs. Remove this if you want to access your router.
          "type": "field",
          "ip": ["geoip:private"],
          "outboundTag": "blocked"
        },
        {
          // Blocks major ads.
          "type": "field",
          "domain": ["geosite:category-ads"],
          "outboundTag": "blocked"
        }
      ]
    },
  
    // Dns settings for domain resolution.
    "dns": {
      // Static hosts, similar to hosts file.
      "hosts": {
        // Match v2fly.org to another domain on CloudFlare. This domain will be used when querying IPs for v2fly.org.
        "domain:v2fly.org": "www.vicemc.net",
  
        // The following settings help to eliminate DNS poisoning in mainland China.
        // It is safe to comment these out if this is not the case for you.
        "domain:github.io": "pages.github.com",
        "domain:wikipedia.org": "www.wikimedia.org",
        "domain:shadowsocks.org": "electronicsrealm.com"
      },
      "servers": [
        "1.1.1.1",
        {
          "address": "114.114.114.114",
          "port": 53,
          // List of domains that use this DNS first.
          "domains": [
            "geosite:cn"
          ]
        },
        "8.8.8.8",
        "localhost"
      ]
    },
  
    // Policy controls some internal behavior of how V2Ray handles connections.
    // It may be on connection level by user levels in 'levels', or global settings in 'system.'
    "policy": {
      // Connection policys by user levels
      "levels": {
        "0": {
          "uplinkOnly": 0,
          "downlinkOnly": 0
        }
      },
      "system": {
        "statsInboundUplink": false,
        "statsInboundDownlink": false,
        "statsOutboundUplink": false,
        "statsOutboundDownlink": false
      }
    },
  
    // Stats enables internal stats counter.
    // This setting can be used together with Policy and Api. 
    //"stats":{},
  
    // Api enables gRPC APIs for external programs to communicate with V2Ray instance.
    //"api": {
      //"tag": "api",
      //"services": [
      //  "HandlerService",
      //  "LoggerService",
      //  "StatsService"
      //]
    //},
  
    // You may add other entries to the configuration, but they will not be recognized by V2Ray.
    "other": {}
  }
```

### openvpn

```bash
/etc/openvpn/client
#remote vpn-pool1.offseclabs.com 1194 udp
remote 127.0.0.1 1194

systemctl start openvpn-client@oscp_lab.service
```

## Tools

### information gathering

nmap, dirsearch, gobuster, burpsuite,

### vulnerability scanning

Nessus，nikto, wpscan

### exploit framework

metasploit, BeEF,

### reverse shell

rsg

### privilege escalation

mingw-w64, x86_64-linux-gnu-gcc,

### AV_Evasion

wine, shellter, hoaxshell

### general

oletools
wsgidav
swaks

vuvps tcvps
v2ray
Parallels: Lock screen time
