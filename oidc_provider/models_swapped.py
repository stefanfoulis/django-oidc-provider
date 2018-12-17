import swapper

Client = swapper.load_model("oidc_provider", "Client")
Code = swapper.load_model("oidc_provider", "Code")
Token = swapper.load_model("oidc_provider", "Token")
UserConsent = swapper.load_model("oidc_provider", "UserConsent")
RSAKey = swapper.load_model("oidc_provider", "RSAKey")
