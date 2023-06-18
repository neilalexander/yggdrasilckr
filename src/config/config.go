package config

import (
	"bytes"
	"io"

	"github.com/hjson/hjson-go/v4"
	yggcfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	"golang.org/x/text/encoding/unicode"
)

type NodeConfig struct {
	*yggcfg.NodeConfig
	TunnelRoutingConfig `json:"TunnelRouting"`
}

// TunnelRoutingConfig contains the crypto-key routing tables for tunneling regular
// IPv4 or IPv6 subnets across the Yggdrasil network.
type TunnelRoutingConfig struct {
	Enable            bool              `comment:"Enable or disable tunnel routing."`
	IPv6RemoteSubnets map[string]string `comment:"IPv6 subnets belonging to remote nodes, mapped to the node's public\nkey, e.g. { \"aaaa:bbbb:cccc::/e\": \"boxpubkey\", ... }"`
	IPv4RemoteSubnets map[string]string `comment:"IPv4 subnets belonging to remote nodes, mapped to the node's public\nkey, e.g. { \"a.b.c.d/e\": \"boxpubkey\", ... }"`
}

func (cfg *NodeConfig) ReadFrom(r io.Reader) (int64, error) {
	conf, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	n := int64(len(conf))
	// If there's a byte order mark - which Windows 10 is now incredibly fond of
	// throwing everywhere when it's converting things into UTF-16 for the hell
	// of it - remove it and decode back down into UTF-8. This is necessary
	// because hjson doesn't know what to do with UTF-16 and will panic
	if bytes.Equal(conf[0:2], []byte{0xFF, 0xFE}) ||
		bytes.Equal(conf[0:2], []byte{0xFE, 0xFF}) {
		utf := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
		decoder := utf.NewDecoder()
		conf, err = decoder.Bytes(conf)
		if err != nil {
			return n, err
		}
	}
	// Generate a new configuration - this gives us a set of sane defaults -
	// then parse the configuration we loaded above on top of it. The effect
	// of this is that any configuration item that is missing from the provided
	// configuration will use a sane default.
	var tunnelCfg struct {
		TunnelRoutingConfig `json:"TunnelRouting"`
	}
	if err := hjson.Unmarshal(conf, &tunnelCfg); err != nil {
		return n, err
	}
	*cfg.NodeConfig = *yggcfg.GenerateConfig()
	if err := cfg.UnmarshalHJSON(conf); err != nil {
		return n, err
	}
	cfg.TunnelRoutingConfig = tunnelCfg.TunnelRoutingConfig
	return n, nil
}
