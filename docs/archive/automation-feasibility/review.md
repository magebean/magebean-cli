# Rà khả năng tự động hóa 50 Magebean backlog requirements

Review ngày 2026-10-17 do ba nhánh chuyên môn thực hiện: runtime/configuration (17 mục), source security (23 mục), dependency/integration (10 mục). Người điều phối đối chiếu đủ50 ID, nguyên criterion, bằng chứng source/test và fixtures. Đây là đánh giá khả thi kỹ thuật, **chưa phải triển khai hoặc xác nhận các check đã an toàn để bật**.

## Kết quả

| Phân loại | Số requirements | Ý nghĩa |
|---|---:|---|
| FULL_AUTOMATION | 11 | Có thể tự động đánh giá criterion hiện tại sau khi xây collector/adapter, policy và coverage đầy đủ theo deployment scope. Không có nghĩa hiện đã đủ dữ liệu hoặc đã viết xong. |
| SCOPED_AUTOMATION | 36 | Có thể viết một predicate kỹ thuật hữu ích với phạm vi hẹp, rõ ràng; cần criterion/ID mới hoặc mở rộng check hẹp đang active. Không được giữ criterion rộng rồi chỉ bỏ cờ human. |
| SIGNAL_ONLY | 1 | MB-0077: tìm dấu hiệu dữ liệu cá nhân trong luồng third-party; chưa chứng minh business minimization. |
| NOT_AUTOMATABLE | 2 | MB-0095: mức API exposure cần thiết phụ thuộc nghiệp vụ; MB-0102: PCI vendor-default-account evidence assessment không phù hợp profile Magebean tự động. |
| Sẵn sàng khôi phục ngay | **0** | Không mục nào đủ điều kiện đưa lại profile hiện tại mà không sửa implementation/binding và kiểm thử. |

**47/50 mục có hướng thiết kế check tự động**, nhưng đây là số yêu cầu ứng viên, không phải47 check mới độc lập hay47 năng lực đã hoàn thành. Toàn bộ50 mục đã có function; chúng sử dụng52 tên function khác nhau. Có23 mục liên quan đến check đang active, phần lớn chỉ trùng một phần scope, dữ liệu hoặc detector. Không cộng thẳng57+47 thành production coverage.

SCOPED bao gồm cả check với adapter/endpoint contract cụ thể: CSRF, SSRF, upload, authorization và webhook có thể được kiểm tra tự động trên flow được khai báo và môi trường test thích hợp. Generic source regex hiện tại vẫn chỉ là tín hiệu. Không nhận một manifest tự khai “đã review” làm bằng chứng bảo vệ; manifest chỉ mô tả input/policy/target cho phép kiểm tra bằng máy. Thiếu adapter, quyền truy cập, trust/freshness hoặc scope phải UNKNOWN.

## 11 ứng viên giữ criterion gốc

| ID | Khả năng cần xây |
|---|---|
| MB-0004 | Quyền ghi thực tế của đúng PHP/web identity, namespace, ACL và mount |
| MB-0043 | Cấu hình rotation/retention đã cài và gắn đúng scheduler/managed logging target |
| MB-0064 | Mapping fork/replacement/source override đầy đủ và policy repository/revision cụ thể |
| MB-0101 | So actual Admin ACL/grants với allowlist role/account có version |
| MB-0731 | Password-validation policy được bind với native/IMS mode và validator/runtime thực |
| MB-0738 | Xdebug state của đúng production web worker/pool |
| MB-0739 | display_errors của đúng web worker/pool và runtime overrides |
| MB-0740 | Template hints ở đủ active store scopes |
| MB-0741 | Effective cache backend inventory và declared production backend policy |
| MB-0742 | Debug/template hint settings ở đúng runtime/store scopes |
| MB-0744 | Abandonment status đầy đủ cho library inventory trong scope |

FULL là **có điều kiện vào machine inputs**, không là đảm bảo toàn bộ deployment bất kỳ đều tự đánh giá được. Ví dụ MB-0064 chỉ kết luận theo policy fork-risk cụ thể; không tự phát hiện mọi malicious commit. MB-0744 cần đủ library inventory, không được bỏ qua thư viện ngoài Composer hay trạng thái upstream thiếu/stale.

MB-0731 liên quan MB-0728; MB-0740/0742 liên quan MB-0729; MB-0741 liên quan MB-0038; MB-0744 liên quan MB-0061. Ưu tiên sửa/mở rộng collector và tái sử dụng predicate trước khi tăng inventory. Các check active hẹp hiện tại không tự chứng minh criterion rộng của backlog.

## Vì sao không chỉ bật lại check hiện tại

Root tái chạy32 fixture observations trên8 detector source: scope thiếu, rỗng và file quá1MiB bị bỏ qua đều cho8/8 PASS; fixture readable có mẫu nguy hiểm cho8/8 FAIL. Payload chỉ được đọc, không thực thi. Kết quả ở [root-probes.json](root-probes.json).

Nhánh source chạy13 case bổ sung: một `escapeshellarg()` không liên quan có thể làm command sink nguy hiểm PASS; form_key rỗng có thể PASS; missing/unreadable/oversized command scope có thể PASS. `unserialize()` với untrusted input và allowed_classes=false cũng bị detector coi PASS, trong khi [PHP manual](https://www.php.net/manual/en/function.unserialize.php) cảnh báo không nhận untrusted input bất kể tùy chọn này. Đây là bằng chứng thiếu detector sufficiency, không phải chứng minh một Magento production cụ thể đã bị khai thác. Xem [source-probes.json](source-probes.json).

Nhánh runtime còn ghi nhận source/ACL hints và header literals không chứng minh đúng virtual host hoặc response thực thi policy. Unix mode bits không đủ chứng minh quyền của runtime identity; cần đúng identity/ACL/mount context, phù hợp với các deployment models trong [Adobe permissions guidance](https://experienceleague.adobe.com/en/docs/commerce-operations/configuration-guide/deployment/file-system-permissions). Repository overrides/forks phải kiểm tra cả root configuration và lock/source mapping theo [Composer repository model](https://getcomposer.org/doc/05-repositories.md).

## Thứ tự triển khai đề xuất

1. **Collection completeness trước:** scope/file thiếu, unreadable, oversized, symlink ngoài scope, budget/deadline, dữ liệu stale/partial phải rõ. Không dùng “không thấy match” để tạo PASS khi collection thiếu.
2. **11 FULL candidates:** đối chiếu các overlap, định nghĩa trust/freshness và release binding, rồi xây read-only collectors, policy inputs và fixtures. Không sửa DB/production để thu bằng chứng.
3. **Source policy và runtime checks hẹp:** SQL bindings, escaping context, eval/unserialize/shell/XML, secret patterns, checkout headers, media, endpoints. Mỗi predicate cần safe/unsafe/missing/benign-comment/string tests và remediation file:line cụ thể.
4. **Adapter-specific integration checks:** CSRF/SSRF/path/upload/authorization/webhook/logging theo named workflow, sandbox hoặc CI contract. Không probe mutating production flows hoặc giả định một adapter bao phủ mọi extension.

Mỗi scoped criterion mới cần identity mới nếu nghĩa khác requirement cũ; không tái sử dụng ID để đánh tráo coverage. Vẫn giữ cả ba profile Magebean automated-only và không đưa human evidence trở lại.

## Artifacts và giới hạn

- [Bảng50 mục CSV](review.csv): verdict, effort, predicate, inputs, overlap và limitations.
- [Review JSON đầy đủ](review.json): exact criterion, source/test pointers và safe/fail/missing cases cho từng ID.
- [Runtime17](runtime.json), [source23](source.json), [dependency10](dependencies.json).
- `build-review.py` kiểm tra đủ50 ID không trùng, criterion khớp catalog, verdict/schema, source-line references và SHA256 inputs.

Không sửa runtime/catalog/profile, không import/deploy production trong lượt review này. Chưa chạy Magento release/edition integration matrix; 47 candidates không phải47 completed tests hay một assurance percentage. Các case runtime có thể cần collector/adapters mới và nhiều mục source cần criterion mới; readiness của tất cả mục hiện là false.
