# yggdrasilckr

This is an Yggdrasil build that re-adds CKR support. Add a section to your `yggdrasil.conf` like this:

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

The main change from CKR support in v0.3 is that you don't need to specify source subnets. Filtering will automatically be applied based on your remote subnets.

## Warning

This is unsupported. Don't yell at me if it doesn't work.