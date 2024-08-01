# yggdrasilckr

This is a special Yggdrasil build that re-adds tunnel routing/crypto-key routing (CKR) support. This allows you to build one or more point-to-point VPNs over the Yggdrasil Network and route normal IPv4 or IPv6 traffic to other `yggdrasilckr` nodes, without having to use higher-level VPN tools.

To configure, add a section to your `yggdrasil.conf` like this:

```
  TunnelRouting: {
    Enable: true
    RemoteSubnets: {
      "remotepublickey": [
        "a.a.a.a/a",
        "b::b/b"
      ]
    }
  }
```

If you are using an operating system other than Linux, you will need to add routing table entries for these routes to the TUN adapter manually.

Then use Go 1.21 to build and run:

```
go build -o yggdrasilckr ./cmd/yggdrasilckr
./yggdrasilckr -useconffile ...
```

... or generate an iOS framework with:

```
gomobile bind -target ios -tags mobile -o Yggdrasil.framework \
  github.com/neilalexander/yggdrasilckr/src/mobile \
  github.com/neilalexander/yggdrasilckr/src/config
```

... or generate an Android AAR bundle with:

```
gomobile bind -target android -tags mobile -o yggdrasil.aar \
  github.com/neilalexander/yggdrasilckr/src/mobile \
  github.com/neilalexander/yggdrasilckr/src/config
```

The main change from the old tunnel routing/CKR support in v0.3 is that you don't need to specify source subnets. Filtering will automatically be applied based on your remote subnets, therefore you'll need to specify the correct remote subnets on both sides.

## Warning

This is provided without any warranty whatsoever and should be considered to be completely unsupported. Don't yell at me if it doesn't work.
