# Review Basic / Magento Best Practices theo Adobe

Ngày2026-10-17. Phạm vi:20 requirements Basic hiện tại, thuộc Magebean; tài liệu Adobe và implementation tương ứng. Không sửa catalog/check behavior, không scan production, không chứng nhận Adobe compliance.

## Kết luận

**Chưa đủ để gọi là bao phủ đầy đủ Magento best practices theo Adobe.** Basic có nền tảng kỹ thuật hữu ích nhưng thiếu một số nhóm khuyến nghị quan trọng và có binding không phù hợp mô hình Magento. Cần sửa độ đúng trước khi tăng số requirements.

Yêu cầu mới là best practices gồm cả security và operations. Do đó **giữ cache/FPC, static deployment và cron trong Basic**, ở readiness lane có scope/exception riêng. Đề xuất security-only trước đây chuyển chúng khỏi mặc định không phải quyết định áp dụng cho mục tiêu mới.

## Đã kiểm tra và giới hạn

- Đối chiếu toàn bộ20 membership/check recipes; snapshot criterion/args/variants và quyết định từng ID nằm trong `requirements-review.json`.
- Recommendation matrix theo chủ đề trong `source-mapping.md`, kèm nguồnAdobe. Không dùng số requirements để tính phần trăm Adobe coverage.
- Chạy6 artificial input fixtures trong `probe-basic.php`; kết quả ở `observations.json`. Không phải full Magento integration, không chạy auth flow hoặc external requests.
- Review hiện tại đọc lại source mới: password/login/debug resolver đã có locked config/database/module-default handling. Không lặp kết luận cũ rằng chỉ đọc config.php.
- Hai nhánh agent gặp usage limit; người điều phối trực tiếp hoàn tất implementation/operations review và probes. Không trình bày kết quả như ba independent completed reviews.

## Những phát hiện có bằng chứng cụ thể

1. **P0 — MFA binding không đúng provider model.** MB-0007 yêu cầu moduleMagento_TwoFactorAuth cộng một moduleprovider trong danh sách. Fixture native Google provider representation trả FAIL; thêm entry giả địnhMagento_GoogleAuthenticator trả PASS. Magento upstream khai báo Google/Duo/Authy/U2F như provider engines trong TwoFactorAuth DI. Cần đọc provider config/version/auth mode và tách enrollment/enforcement; không suy ra MFA hoạt động từ module flag.
2. **P0 — IMS applicability.** Fixture có IMS module indication và native2FA disabled vẫn FAIL. Adobe mô tả ngoại lệ native2FA disabled dưới IMS. Chỉ có IMS module chưa chứng minh IMS hoạt động; vì vậy cần context/evidence, không tự PASS hoặc FAIL native policy cho mọi deployment.
3. **P1 — Admin route scope.** backend được check hiện tại cho PASS, vì criterion chỉ khácadmin. Đây không phải lỗi đối với criterion hẹp, nhưng thiếu uncommon-route guidance. Không quảng bá thay URL là access control.
4. **P1 — REMOTE HTTPS.** Recipe include_admin đòi backend.frontName local; URL-only thiếuenv.php trả UNKNOWN trước HTTP. Tách storefront và Admin hoặc nhận explicit admin endpoint/context; không bỏ mất storefront evidence vì admin không quan sát được.
5. **P1 — Cron claim quá hẹp cho readiness.** Fixture@yearly vẫn PASS vì check chỉ xác nhận entry tồn tại. Cần thêm schedule phù hợp và recent successful execution/backlog evidence; dùng scheduler adapter cho cloud/container. Đây là thiếu coverage, không phải parser vi phạm criterion hiện tại.
6. **P1 — Cache/static scope.** MB-0037 xác minh declaration, không current cache status/hit behavior; REMOTE dùng heuristic khác claim. MB-0035 chỉ cần một artifact. Giữ topics nhưng làm rõ current/deployed/observed scope, theme/locale và deployment model.
7. **P1 — Policy provenance.** Minimum8, session900,HSTS1year và mode0640 là ngưỡng Magebean lựa chọn. Adobe Admin guide hiện mô tả default/minimum7 và cho cấu hình theo tổ chức. Không gắn nhãn Adobe violation chỉ vì khác policy Magebean; phải hiển thị policy source/version/applicability.

Đã tái hiện1–5 ở cấp input check; chưa xác minh MFA enrollment trên các Magento release thực, WAF effectiveness hay toàn bộ detector accuracy.

## Rà từng requirement đang có

| ID | Topic | Quyết định chính |
|---|---|---|
| MB-0001 | World-write | Giữ; báo traversal gaps/scope. |
| MB-0002 | env.php | Giữ protection, cấu hình policy ownership/ACL theo deployment. |
| MB-0003 | Public artifacts | Mở rộng effective docroot và HTTP exposure evidence. |
| MB-0005 | Directory index | Giữ bounded runtime probes, không tuyên bố toàn site. |
| MB-0006 | Admin route | Sửa common-name/effective-route scope. |
| MB-0007 | MFA | Thay provider-module binding; xử lý native/IMS/context. |
| MB-0011 | Login protection | Báo CAPTCHA/lockout riêng; bổ sung reset protections. |
| MB-0728 | Password minimum | Giữ installed-config/validator observation, gắn policy và version. |
| MB-0026 | HTTPS | Tách storefront/Admin và local/remote scope. |
| MB-0028 | TLS | Giữ, bổ sung certificate/hostname evidence riêng. |
| MB-0029 | Mixed content | Giữ scoped source/runtime observation và gaps. |
| MB-0030 | Cookies | Mở rộng authenticated/context coverage, exception rõ ràng. |
| MB-0031 | Production mode | Giữ declaration, tách effective runtime override. |
| MB-0729 | Debug | Giữ default-scope checks; không suy ra mọi worker/store an toàn. |
| MB-0035 | Static deployment | Giữ readiness, tăng kiểm active theme/locale/assets. |
| MB-0037 | FPC/cache | Giữ readiness, tách declaration/status/runtime/mode. |
| MB-0046 | Scheduler | Giữ readiness, thêm schedule/last-success/context. |
| MB-0049 | Dependency advisories | Giữ inventory/hotfix/freshness scope. |
| MB-0050 | Adobe patches | Giữ, phân biệt release line/edition/support/isolated patches. |
| MB-0730 | Deployed secrets | Giữ redacted findings và collection completeness; thêm env exposure/VCS tracking checks riêng. |

## Coverage cần bổ sung

| Nhóm còn thiếu/partial | Thực hiện phù hợp |
|---|---|
| Admin secret-key URL, case sensitivity, account sharing, recovery/reset safeguards | Scoped resolved configuration checks với native/IMS/version applicability. |
| Admin session và least privilege | Dùng Magebean MB-0009,MB-0100/0101 sau review; role integrity không phải least-privilege proof. |
| Production code write restriction | MB-0004 cần effective web identity/ACL/mount scope; không chỉ so mode với deployment owner. |
| pub docroot, sensitive routes, executable media, exposed logs | Bổ sung scoped predicates từ Magebean candidates; HTTP signatures/status và redaction, không tải toàn bộsecret. |
| HSTS/clickjacking, certificate và multistore URLs | MB-0027/MB-0096 và appropriate runtime observations; thresholds/policies có nguồn. |
| Locked sensitive configuration và env.php source-control exposure | Phân biệt declared lock/effective precedence/tracked-files; existenceenv.php không chứng minh đã khóa. |
| Scheduler execution, cache state, deployment coherence | Giữ readiness; đọc evidence có timestamp và context, không thay deployment hoặc flush cache trong scan. |
| WAF/Admin ACL, SSH MFA, scheduled scans/notifications, backups/restore | External/manual evidence hoặc connectors; không suy ra từ source và không ép Fastly/Cloud-only model lên on-premise/OpenSource. |

Các candidate trên vẫn phải là **requirements Magebean**, có Adobe provenance khi phù hợp. Không lấy ASVS/PCI clause làm Basic identity; reused check không chứng minh cùng obligation.

## Đề xuất hợp đồng profile

Ba lane trong cùng Basic:

1. **Security:** cấu hình/exposure/advisory findings có scope và confidence.
2. **Readiness:** production/deployment/cache/scheduler trạng thái quan sát được; không coi mọi readiness failure là vulnerability.
3. **Evidence còn thiếu:** các khuyến nghị Adobe cần quyền/context/external verification; không làm chúng biến mất khỏi coverage summary và không tính như PASS.

Giữ default technical scan nhanh, bounded. External checklist không tự biến tất cả Basic thành human-required và không chặn mọi check như ASVS/PCI hiện tại. Kết quả hiển thị inventory, applicable, executed, evidence missing và action; không hứa passiveCLI xác minh toàn bộ operations.

## Thứ tự triển khai

- P0: MFA/provider/IMS binding và fixtures theo Magento versions; policy source/applicability rõ.
- P1: Admin config gaps, code/webroot exposure, safe media detector, HSTS/header scopes và REMOTE split.
- P1: strengthen cron/cache/static readiness; test alternate deployment architectures.
- P2: connector/evidence workflow cho hosting/monitoring/recovery controls.

Chưa chốt số lượng Basic mới; bổ sung predicates chỉ sau safe/violating/missing/version-specific/alternate-architecture fixtures và CLI/Console parity tests.

## Nguồn kiểm chứng

- [Adobe priority/security guidance](https://experienceleague.adobe.com/en/docs/commerce-operations/implementation-playbook/best-practices/launch/security-best-practices)
- [Admin settings và applicability](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/security-admin)
- [Native2FA và IMS](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/tfa/security-two-factor-authentication)
- [Magento provider DI upstream](https://raw.githubusercontent.com/magento/security-package/develop/TwoFactorAuth/etc/di.xml) — develop snapshot, không thay fixture của installedrelease.
- [Permissions models](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/deployment/file-system-permissions)
- [Production modes](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/set-mode)
- [Static files](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/static-view/static-view-file-deployment)
- [Cache management](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/tools/cache-management)
- [Cron](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/cli/configure-cron-jobs)
- [Configuration deployment](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/deployment/overview)
- [Security Scan](https://experienceleague.adobe.com/en/docs/commerce-admin/systems/security/security-scan)

Tài liệu pub-docroot URL trong nguồn mapping không fetch lại thành công ở lượt điều phối; candidate này cần đối chiếu installed web config/official sample trước implementation, không coi là verified runtime failure. Tài liệu Adobe hiện hành có phần Cloud/on-premise/OpenSource khác nhau; SaaS không thuộc local Magento scan này. Review không khẳng định các lời khuyên cũ còn là nghĩa vụ PCI hiện hành.
