# PCI DSS v4.0.1 Requirement 2 criterion review

This review covers criteria 2.2.2 through 2.2.7. It evaluates Magebean evidence capability, not PCI DSS compliance. Human verification remains mandatory.

| Requirement | Decision | Existing rules | Maximum coverage |
|---|---|---|---|
| 2.2.2 | Implemented hybrid rule | MB-R371 | Partial |
| 2.2.3 | External-system evidence | None | Supporting |
| 2.2.4 | External-system evidence | None | Supporting |
| 2.2.5 | External-system and human evidence | None | Supporting |
| 2.2.6 | Reuse existing rules | MB-R031, MB-R032, MB-R033, MB-R036 | Partial |
| 2.2.7 | Reuse existing rules | MB-R026, MB-R027, MB-R028 | Partial |

MB-R371 validates a credential-free component/account inventory and evidence references. Explicit unsafe account states fail. Complete evidence remains `HUMAN VERIFICATION REQUIRED` because Magebean cannot establish the full component inventory or attest the observed system state.

Requirements 2.2.3 through 2.2.5 depend on infrastructure inventory, running services, isolation, business justification, and risk-reduction controls, so they remain external or human evidence work. Existing Magento/PHP and transport rules provide bounded partial evidence for 2.2.6 and 2.2.7.