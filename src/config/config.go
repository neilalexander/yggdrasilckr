package config

import "github.com/yggdrasil-network/yggdrasil-go/src/config"

type NodeConfig struct {
	*config.NodeConfig
	TunnelRoutingConfig `json:"TunnelRouting"`
}

// TunnelRoutingConfig contains the crypto-key routing tables for tunneling regular
// IPv4 or IPv6 subnets across the Yggdrasil network.
type TunnelRoutingConfig struct {
	Enable            bool              `comment:"Enable or disable tunnel routing."`
	IPv6RemoteSubnets map[string]string `comment:"IPv6 subnets belonging to remote nodes, mapped to the node's public\nkey, e.g. { \"aaaa:bbbb:cccc::/e\": \"boxpubkey\", ... }"`
	IPv4RemoteSubnets map[string]string `comment:"IPv4 subnets belonging to remote nodes, mapped to the node's public\nkey, e.g. { \"a.b.c.d/e\": \"boxpubkey\", ... }"`
}
