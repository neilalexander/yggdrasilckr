# yggdrasilckr

This is an Yggdrasil v0.4 build that re-adds tunnel routing/crypto-key routing (CKR) support. Add a section to your `yggdrasil.conf` like this:

```
  TunnelRouting: {
    Enable: true
    IPv4RemoteSubnets: {
      "a.a.a.a/a": remotepublickey
    }
    IPv6RemoteSubnets: {
      "b::b/b": remotepublickey
    }
  }
```

Then use Go 1.16 to build and run:
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