# Requirement source families

The primary runtime contains **735 requirements** in physically separate catalogues: **110 Magebean**, **345 OWASP ASVS 5.0.0** and **280 PCI DSS 4.0.1**. internal-catalog.json is a compatibility aggregate mirroring those catalogues. A profile cannot mix families.

Magebean criteria describe bounded Magento technical conditions and explicit policies. OWASP Top 10 supplies taxonomy for the Magebean owasp profile; it does not turn those rules into ASVS clauses. ASVS and PCI retain their version-qualified official criteria and independent human evidence obligations.

All 11 Magebean profiles contain automated predicates and no required human checklist. The evidence profile performs informational document/record lint only. Default LOCAL counts and context are in [profiles](../guides/profiles.md). The [baseline v1](../magebean-baseline-v1.md) mirrors every active Magebean criterion and membership directly from runtime data.

The historical retirement archive has 60 original criteria and remains immutable. Ten scoped automated revisions have been restored as active definitions; 50 references remain inactive under evidence-based classifications. This is not a claim that all inactive criteria inherently require manual review or can never be automated. Original criterion histories and assessment identities remain preserved.

Normative source documents and workflows are in [standards](../standards/README.md). The catalogue, criterion history and observed evidence govern current semantics; superseded proposals and old profile counts under [archive](../archive/README.md) do not override them.
