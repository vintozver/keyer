import yaml


with open("config.yaml", "rt", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

title1 = cfg["title1"]
title2 = cfg["title2"]

validate_sig_mifare_classic_ev1 = cfg.get("validate_sig_mifare_classic_ev1", False)
local_storage = cfg.get("local_storage", False)
for name in ("validate_sig_mifare_classic_ev1", "local_storage"):
    if not isinstance(cfg.get(name, False), bool):
        raise ValueError("%s must be a YAML boolean" % name)

unit_id = cfg["unit_id"]
kid = cfg["kid"]
if not isinstance(unit_id, str) or not isinstance(kid, str) or not unit_id or not kid:
    raise ValueError("unit_id and kid must be non-empty strings")

control_endpoint = cfg["control"]["endpoint"]
control_certificate = cfg["control"]["certificate"]
control_privatekey = cfg["control"]["privatekey"]
control_algorithm = cfg["control"].get("algorithm", "RS256")
if control_algorithm not in (
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512", "EdDSA"):
    raise ValueError("control.algorithm must be a supported asymmetric JWT algorithm")
