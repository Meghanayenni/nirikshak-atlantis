"""Who may vet a remediation snippet (Rule 4).

An allowlist, not a denylist. A list of words that look automated can only
refuse the spellings somebody thought of; naming the people who vet commands
refuses everything else. A teammate who vets a snippet is added here by name,
in the same change, so the diff shows who took responsibility for it.
"""

TEAM_VETTERS: frozenset[str] = frozenset({"Meghana Yenni"})
