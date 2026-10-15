from vlan_tool.models import SwitchRecord
from vlan_tool.naming import description_without_id, extract_id_token, strip_optical_link_noise
from vlan_tool.provisioning.neighbor import score_neighbor_match


assert strip_optical_link_noise("SNR-S2970G-24S.site_id1012_1550nm") == (
    "SNR-S2970G-24S.site_id1012"
)
assert description_without_id("SNR-S2970G-24S.site_id1012") == "SNR-S2970G-24S.site"
assert extract_id_token("SNR-S2970G-24S.site_id1012_1550nm") == "id1012"

target = SwitchRecord(name="SNR-S2970G-24S.site", host="10.20.34.26", vendor="snr")
l3 = SwitchRecord(name="c4900.Area56_site.example.net", host="10.30.1.34", vendor="cisco_ios")
wrong = SwitchRecord(name="c4900.Area56_site.example.net", host="10.30.1.34", vendor="cisco_ios")

desc = "SNR-S2970G-24S.site_id1012"
assert score_neighbor_match(description=desc, switch=target, source_switch=None) >= 100
assert score_neighbor_match(description=desc, switch=target, source_switch=l3) >= 100

# Short/fuzzy location hit against L3 must stay weak.
assert score_neighbor_match(
    description="site_id1012",
    switch=wrong,
    source_switch=l3,
) < 100
