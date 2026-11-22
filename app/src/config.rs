use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

pub const DEFAULT_DOMAINS: &[&str] = &[
    // Discord (All API, Media, Voice RTC, CDN, Gateway)
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "discord.co",
    "discord.app",
    "discord.dev",
    "discord.new",
    "discord.gift",
    "discord.gifts",
    "discord.status",
    "discordstatus.com",
    "dis.gd",
    "discordcdn.com",
    "discordmerch.com",
    "discordpartygames.com",
    "discordsays.com",
    "discordsez.com",
    "discord-activities.com",
    "discordactivities.com",
    "discord-attachments-uploads-prd.storage.googleapis.com",
    "stable.dl2.discordapp.net",
    // YouTube & Google Video
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtubei.googleapis.com",
    "youtubeembeddedplayer.googleapis.com",
    "youtubekids.com",
    "yt3.ggpht.com",
    "yt4.ggpht.com",
    // Spotify & Audio
    "spotify.com",
    "scdn.co",
    "spotifycdn.com",
    // Common blocked
    "rutracker.org",
    "rutracker.net",
    "rutracker.cc",
    "nnmclub.to",
    "notion.so",
];
const DEFAULT_APPS: &[&str] = &[
    "Discord",
    "discord",
    "DiscordCanary",
    "discordcanary",
    "DiscordPTB",
    "discordptb",
    "Discord.exe",
    "DiscordCanary.exe",
    "DiscordPTB.exe",
    "spotify",
    "Spotify",
    "Spotify.exe",
];

#[derive(Debug)]
pub struct SplitTunnel {
    pub domains: BTreeSet<String>,
    pub applications: BTreeSet<String>,
    pub proxy_server: String,
    pub proxy_port: u16,
}

impl SplitTunnel {
    pub fn whitelist(domains: BTreeSet<String>, proxy_server: String, proxy_port: u16) -> Self {
        let mut domains = domains;
        domains.extend(DEFAULT_DOMAINS.iter().map(|domain| (*domain).to_owned()));
        Self {
            domains,
            applications: DEFAULT_APPS.iter().map(|app| (*app).to_owned()).collect(),
            proxy_server,
            proxy_port,
        }
    }

    pub fn generate(&self) -> SingBoxConfig {
        let domains: Vec<_> = self.domains.iter().collect();
        let applications: Vec<_> = self.applications.iter().collect();
        let outbounds = vec![
            json!({"type": "direct", "tag": "direct"}),
            json!({"type": "socks", "tag": "proxy", "server": self.proxy_server, "server_port": self.proxy_port, "version": "5"}),
        ];

        let rules = vec![
            json!({"action": "sniff"}),
            json!({"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}], "action": "hijack-dns"}),
            json!({"domain_suffix": domains, "action": "route", "outbound": "proxy"}),
            json!({"process_name": applications, "action": "route", "outbound": "proxy"}),
        ];
        SingBoxConfig {
            log: json!({"level": "info", "timestamp": true}),
            dns: json!({
                "servers": [
                    {"type": "local", "tag": "local-dns"},
                    {"type": "fakeip", "tag": "fake-dns", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
                ],
                "rules": [{"domain_suffix": domains, "query_type": ["A", "AAAA"], "action": "route", "server": "fake-dns"}],
                "final": "local-dns",
                "reverse_mapping": true
            }),
            inbounds: vec![json!({
                "type": "tun", "tag": "tun-in", "interface_name": "kasper-tun",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": true, "strict_route": true, "stack": "mixed"
            })],
            outbounds,
            route: json!({
                "auto_detect_interface": true,
                "default_domain_resolver": "local-dns",
                "rules": rules,
                "final": "direct"
            }),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SingBoxConfig {
    log: Value,
    dns: Value,
    inbounds: Vec<Value>,
    outbounds: Vec<Value>,
    route: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_has_independent_domain_and_process_rules_and_direct_default() {
        let policy = SplitTunnel::whitelist(
            BTreeSet::from(["example.com".into()]),
            "127.0.0.1".into(),
            1080,
        );
        let config = serde_json::to_value(policy.generate()).unwrap();
        assert_eq!(config["route"]["final"], "direct");
        let rules = config["route"]["rules"].as_array().unwrap();
        let domains = rules
            .iter()
            .find(|r| r.get("domain_suffix").is_some())
            .unwrap();
        let apps = rules
            .iter()
            .find(|r| r.get("process_name").is_some())
            .unwrap();
        for domain in ["example.com", "discord.com", "spotify.com", "rutracker.org"] {
            assert!(
                domains["domain_suffix"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(domain))
            );
        }
        assert_eq!(domains["outbound"], "proxy");
        assert_eq!(apps["outbound"], "proxy");
        assert!(apps.get("domain_suffix").is_none());
        assert!(
            apps["process_name"]
                .as_array()
                .unwrap()
                .contains(&json!("Discord"))
        );
        assert!(
            apps["process_name"]
                .as_array()
                .unwrap()
                .contains(&json!("spotify"))
        );
        assert!(
            !domains["domain_suffix"]
                .as_array()
                .unwrap()
                .contains(&json!("unselected.example"))
        );
        assert_eq!(config["outbounds"][1]["server_port"], 1080);
    }

    #[test]
    fn dns_preserves_whitelisted_domains_and_captures_both_dns_transports() {
        let policy = SplitTunnel::whitelist(BTreeSet::new(), "proxy.example.com".into(), 1081);
        let config = serde_json::to_value(policy.generate()).unwrap();
        assert_eq!(
            config["dns"]["rules"][0]["domain_suffix"],
            config["route"]["rules"][2]["domain_suffix"]
        );
        assert_eq!(config["dns"]["final"], "local-dns");
        assert_eq!(config["route"]["rules"][1]["action"], "hijack-dns");
        assert_eq!(config["route"]["rules"][1]["rules"][1]["port"], 53);
        assert_eq!(config["route"]["default_domain_resolver"], "local-dns");
        assert_eq!(config["inbounds"][0]["auto_route"], true);
    }
}
