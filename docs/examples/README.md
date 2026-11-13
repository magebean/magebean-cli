# Configuration and evidence examples

These are illustrative templates, not observed project facts or automatically generated prerequisites. Replace IDs, PIDs, paths and evidence with actual applicable deployment values.

- [Production policy](production-checks.example.json): typed expected inputs for selected worker/Admin/integration/record checks. [Guide](../guides/production-context.md).
- [PCI context](pci-dss-context.example.json): applicability context for the separate PCI profile.
- [PCI external evidence](pci-dss-external-evidence.example.json): structured external evidence template.
- [PCI 2.2.2 evidence](pci-dss-2.2.2-evidence.example.json): scoped evidence for the implemented workflow. [Guide](../standards/pci-workflow.md).

Keep credentials and actual private evidence out of version control. Supplying a policy or document does not prove that its corresponding control works.
