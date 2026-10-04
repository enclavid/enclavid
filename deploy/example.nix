# What deploy/ has to be told about one host. Everything else has a default,
# listed with its option in fleet.nix.
{
  enclavid = {
    names = {
      verify = "verify.example.com";
      api = "api.example.com";
    };
    hatch = {
      auth = "oidc";
      issuer = "https://auth.example.com";
      audience = "https://api.example.com";
      principalClaim = "org_id";
    };
  };
}
