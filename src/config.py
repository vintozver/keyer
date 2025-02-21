import configparser


cfg = configparser.ConfigParser()
with open("config.txt", "rt") as f: 
    cfg.read_file(f)

title1 = cfg["DEFAULT"]["title1"]
title2 = cfg["DEFAULT"]["title2"]

validate_sig_mifare_classic_ev1 = cfg.getboolean("DEFAULT", "validate_sig_mifare_classic_ev1", fallback=False)
local_storage = cfg.getboolean("DEFAULT", "local_storage", fallback=False)

control_endpoint = cfg.get("control", "endpoint")
control_certificate = cfg.get("control", "certificate")
control_privatekey = cfg.get("control", "privatekey")

