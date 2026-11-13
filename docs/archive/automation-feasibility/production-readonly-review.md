# Rà lại backlog theo phạm vi production read-only

Ngày 2026-10-18. Đối chiếu đủ 16 mục `ADAPTER_PENDING` trong implementation manifest và các collector/check hiện có. Đây là review repository; không truy cập hoặc scan production, không thêm check, không thay membership hay bật lại requirement cũ. Chi tiết từng mục nằm trong [JSON](production-readonly-review.json).

Kết luận sửa lại nhận định trước: không cần chuyển cả 16 mục sang staging. **11 mục có hướng đọc trạng thái/metadata production; 5 mục có hướng phân tích ngữ nghĩa source đang deploy.** Đây là khả năng thiết kế các predicate có phạm vi rõ ràng, không phải 16 requirement đã tự động được hoặc đã chứng minh đủ criterion cũ. Nhiều mục vẫn cần ID mới khi đổi nghĩa/phạm vi.

## 11 mục theo trạng thái hoặc metadata

| ID | Có thể quan sát trên production | Cần bổ sung và giới hạn |
|---|---|---|
| MB-0010 Admin exposure | Route Admin thật và effective WAF/gateway/ingress policy | Adapter gắn policy với đúng origin, proxy và các đường truy cập. Một 403/404 không chứng minh Admin được bảo vệ. |
| MB-0043 Log rotation | Logging sinks, cấu hình rotation/retention đang cài, timer/cron và lần chạy gần nhất | Adapter host/container/managed logging. Không chạy force rotation; trạng thái hiện tại không chứng minh các lần chạy tương lai. |
| MB-0051 Remediation khả thi | Package graph, platform/repository constraints và fixed releases | Solver không chạy script/plugin, không sửa lock/vendor. Chỉ chứng minh candidate tương thích với constraints thu thập được; không chứng minh nâng cấp sẽ chạy đúng hoặc mitigation có hiệu lực. |
| MB-0052 Module được duy trì | Module đang bật → package/version → maintenance status | Mapping đủ cả app/code, provider dữ liệu mới và policy xác định high-risk. Không suy ra risk từ tên module. |
| MB-0054 KEV | Package/CVE/advisory đang deploy → feed KEV có provenance và freshness | Mapping CVE aliases và version đầy đủ. Detector hiện tại dựa vào known_exploited chưa đủ để kết luận không có KEV. Muốn đánh giá ưu tiên cần policy SLA riêng. |
| MB-0058 Marketplace | Extension identity, installed version, release và compatibility | Provider Marketplace/vendor có dữ liệu tương thích Magento/PHP. Latest không đồng nghĩa an toàn hoặc phù hợp. |
| MB-0060 Vendor support | Lifecycle/entitlement của đúng product, account và version | API read-only thật của vendor nếu có. Vendor không có nguồn máy đọc được thì adapter đó chưa hỗ trợ; không thay bằng giấy xác nhận/self-attestation. |
| MB-0076 Egress | Rules thực của namespace ứng dụng, firewall/CNI/cloud/gateway, IPv4/IPv6 | Đọc đủ rule ordering, exceptions và đường đi mạng. SystemCheck hiện chỉ quan sát UFW/default OUTPUT và vài bypass; default DROP chưa chứng minh allow-list. |
| MB-0078 Gateway TLS | Effective TLS policy/config hoặc TLS handshakes có giới hạn | Đúng endpoint/SNI, phân biệt TLS 1.2/1.3, biết khả năng client enumerator. Một cipher mạnh được negotiate không chứng minh không còn cipher yếu. |
| MB-0079 Credential storage | Nguồn cấu hình hiệu lực và metadata nơi lưu credential | Inventory credential, precedence và secret-manager adapter; không xuất giá trị. Đổi yêu cầu env.php-only thành protected approved storage: vị trí file đơn lẻ không đủ chứng minh an toàn. |
| MB-0081 Integration ACL | Integration đang active, effective grants, token status và network policy | So sánh với resource/destination allow-list kỹ thuật. Không suy ra nhu cầu nghiệp vụ từ ACL hoặc lưu token thô vào evidence. |

## 5 mục cần phân tích source sâu hơn, vẫn read-only

| ID | Predicate có thể xây dựng | Điều chưa được kết luận |
|---|---|---|
| MB-0733 HTML escaping | Parse PHP/PHTML, theo dõi dữ liệu đến output đúng ngữ cảnh HTML/attribute/URL và escaper semantics | Không có XSS trên mọi template/plugin. Dynamic hoặc unresolved path giữ UNKNOWN. |
| MB-0736 JS escaping | Parse lồng PHP/HTML/JS và serializer theo version | Có tên escapeJs hoặc json_encode chưa chứng minh encoding đúng ngữ cảnh. |
| MB-0094 Controller/API authorization | Resolve enabled routes, merged declarations, DI/plugins và guard trước protected action | Khai báo ACL chưa chứng minh mọi nhánh/custom authorization; không bootstrap project PHP hoặc chạy controller trên production để lấy kết quả. |
| MB-0099 Download/export authorization | Theo dõi identity/object ID → ownership/resource guard → protected output | Chỉ có authenticated route chưa chứng minh object-level access. Không tải invoice/tài liệu thật của khách hàng để thử. |
| MB-0075 Webhook | Resolve provider/module/version, raw-body/header/secret binding và guard trước side effects | SDK call/negative diagnostics chưa chứng minh enforcement, replay hoặc tất cả nhánh xử lý. Không gửi fake webhook, tạo order/refund hoặc gọi payment action. |

Đây không phải lý do bỏ cả năm chủ đề khỏi production scan: cần chọn các cấu trúc/framework/version có thể chứng minh và trả UNKNOWN cho phần chưa hỗ trợ. Việc chứng minh hành vi toàn cục bằng phân tích static tổng quát không được hứa trước.

## Contract thực thi

- Chỉ đọc source, database SELECT, process/config và API metadata được cấp quyền thích hợp. Quyền đọc là technical capability, không phải human evidence; không yêu cầu full root hoặc credential có quyền ghi chỉ để scan.
- Không thực thi project PHP, Composer scripts/plugins hoặc controller; không sửa config, gọi force rotation, đổi firewall hay tạo dữ liệu nghiệp vụ.
- Tách chế độ quan sát thụ động với probe không thay đổi nghiệp vụ. HTTP GET/TLS handshake vẫn là traffic chủ động, có thể tạo access log/session/metric; nếu yêu cầu tuyệt đối không ghi gì thì chỉ dùng config/metadata, và không tuyên bố đã quan sát response thực tế. Mọi probe phải có budget/rate limit.
- Bind observation với release, namespace/process/endpoint và thời điểm thu thập. Không ghép file staging hoặc policy không gắn đúng deployment để kết luận production PASS.
- PASS chỉ cho predicate đã chứng minh trên phạm vi đầy đủ; FAIL khi có violation xác định; UNKNOWN khi thiếu quyền, mapping, provider, freshness hoặc semantics. Thiếu dữ liệu không tự thành violation hoặc PASS.
- Không gửi credential, request body, source snippets nhạy cảm hoặc protected customer data vào report. Chỉ lưu metadata tối thiểu và relative locations.

## Thứ tự triển khai đề xuất

1. KEV provenance/mapping và effective log rotation: có thể bổ sung bằng collector read-only; không cần nền tảng phân tích source tổng quát.
2. Admin/gateway TLS và integration ACL: định nghĩa adapter theo stack production; không giả định một policy format chung cho mọi host/cloud.
3. Egress và credential provenance: giải quyết namespace/precedence/secret-store completeness trước khi có PASS.
4. Module/vendor/Marketplace và dependency solver: nguồn dữ liệu thực, compatibility và constraint coverage quyết định phạm vi hỗ trợ.
5. Authorization, webhook và contextual escaping: đầu tư route resolver/parser/dataflow; thêm supported subsets từng bước, không dùng keyword để bù coverage.

Các mục khác trong backlog cũng không được hiểu là đã hoàn tất: 24 mục cũ chỉ được bao phủ một phần bởi 22 predicate mới; 7 mục reuse coverage từng phần. PII minimization và API business necessity cần policy nghiệp vụ rõ ràng để chuyển thành phép so sánh máy đọc được; PCI vendor-account assessment vẫn thuộc catalog riêng. Không mở human workflow trong Magebean profiles.

Validation của review: script [build-production-readonly-review.py](build-production-readonly-review.py) đối chiếu exact 16 ID với manifest, kiểm tra uniqueness và tồn tại source references; tạo JSON có ranh giới kết luận cho từng mục. Không thay code thực thi nên không chạy lại full regression suite cho review tài liệu này.
