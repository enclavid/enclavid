# What deploy/ has to be told about one host. Everything else has a default,
# listed with its option in fleet.nix.
{
  enclavid = {
    names = {
      verify = "verify.example.com";
      api = "api.example.com";
    };
    # The hook that says who may call api as a consumer, listening on this
    # host: crates/hatch/hooks.openapi.yaml. "none" lets anyone who reaches api.
    hatch.authorize = "tcp:127.0.0.1:9100";
  };
}
