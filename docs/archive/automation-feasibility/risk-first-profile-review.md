# Review ba Magebean profiles theo mục tiêu phát hiện risk để triage

Ngày 2026-10-18. **Kết luận: đáp ứng một phần, chưa khớp hoàn toàn mục tiêu risk-first.** Giữ lại các detector hữu ích, kể cả chỉ phát hiện một phần vấn đề; cần sửa cách phân loại, tổng hợp và trình bày kết quả trước khi mở rộng các detector dạng tín hiệu.

Phạm vi: đủ 37 Basic, 79 Hardening và 51 OWASP members; hợp nhất thành **79 ID duy nhất**, vì Hardening chứa Basic/OWASP. Review định nghĩa, check bindings, severity/lane, capability, guidance và shared CLI/agent/Console result pipeline. Không scan production; không tuyên bố đã kiểm chứng độ chính xác mọi detector. Có ghi chú theo từng ID trong [JSON](risk-first-profile-review.json) và [CSV](risk-first-profile-review.csv).

## Phân loại phục vụ triage, không phải count vulnerability

Các nhóm dưới đây là đề xuất review, chưa được áp dụng vào sản phẩm.

| Profile | Runtime/config risk observations | Source risk candidates | Maintenance/priority signals | Policy/record deviations | Readiness | Tổng |
|---|---:|---:|---:|---:|---:|---:|
| Basic | 27 | 2 | 0 | 1 | 7 | 37 |
| Hardening | 37 | 17 | 6 | 6 | 13 | 79 |
| OWASP | 22 | 16 | 4 | 5 | 4 | 51 |

Một runtime/config observation xác định được cũng không đồng nghĩa exploit đã xác định. Severity là tác động có thể xảy ra; confidence là độ chắc của quan sát/kết luận. Không gộp hai khái niệm này hoặc đặt phần trăm confidence thiếu calibration.

Đủ 79/79 có remediation từ ba mục trở lên và structured triage/verification guidance. Đây là kiểm tra cấu trúc nội dung, không phải chứng nhận mọi remediation phù hợp với mọi deployment. Toàn bộ không yêu cầu human evidence. Hardening có 12 capability-bound members, OWASP có 10; cần hiển thị omission rõ ràng và đánh giá lại những gate chỉ phục vụ coding policy so với gate thật sự cần dữ liệu runtime.

## Các vấn đề cần sửa trước

### P1 — Chưa có đường kết quả riêng cho risk candidate

`RequirementOutcome` chỉ có PASS/FAIL/UNKNOWN/MANUAL_REVIEW. Trong `RequirementAssessmentEvaluator`, obligation có proof=heuristic trả UNKNOWN dù check bên trong phát hiện FAIL; candidate detail còn trong evidence nhưng không trở thành risk signal riêng. Probe in-memory [kết quả](risk-first-pipeline-probe.json) xác nhận điều này; không sửa catalog để thực hiện probe.

`ScanReportAssembler` đánh dấu mọi UNKNOWN/MANUAL_REVIEW của automated Magebean thành execution_error. `AgentResultMapper` ánh xạ ngoài PASS/FAIL thành error. Console `ApplyScanObservationToItem` đưa error sang NeedsAttention qua `ApplyScanAttention`; path này phù hợp cho thiếu dữ liệu, nhưng chưa phân biệt **có bằng chứng đáng điều tra** với **không thu thập được dữ liệu**. Console error path này không đi qua ApplyAssessmentResult cho fail trong service được đọc; cần xác minh/tạo finding và ticket flow cho signal bằng integration test riêng.

Ngược lại, obligation verified_predicate của coding policy trả FAIL và renderer gọi tất cả FAIL là Confirmed findings. Nó có thể xác định chính xác một cú pháp tồn tại mà chưa xác định một vulnerability. Không cần đổi detector thành human/manual để giải quyết việc này.

Đề xuất product contract:
- Confirmed risk/policy deviation: bằng chứng xác định đúng điều mô tả, không hứa exploit nếu chưa chứng minh.
- Risk candidate / Needs attention: có observation cụ thể, actionable; có triage/ticket/risk acceptance/false positive/defer, không auto-approve requirement compliance.
- Collection gap: thiếu quyền/input/runtime access hoặc lỗi tool; hiển thị riêng và không tạo security claim.
- No risk detected in inspected scope: không quan sát thấy risk trong phạm vi đã chạy; không khẳng định requirement được đáp ứng toàn bộ.

Cần giữ assessment conclusion và risk observation là hai chiều riêng. Một scan có collection gap vẫn có thể tìm được risk xác định/candidate ở phần đã đọc; không bỏ observation đó và cũng không đánh dấu scan là đọc đầy đủ. Không tái sử dụng MANUAL_REVIEW để giả lập signal trong Magebean.

### P1 — Severity và lời kết luận có thể mạnh hơn bằng chứng

Ví dụ cần sửa binding/presentation:
- **MB-0014 High:** direct PHP superglobal là candidate; không tự chứng minh injection. SERVER/context reads có thể hợp lệ.
- **MB-0006 High:** Admin route phổ biến là exposure/hygiene signal, không phải authorization bypass.
- **MB-0007 Critical:** native MFA declaration hữu ích, nhưng chưa chứng minh enforcement trên mọi login path.
- **MB-0065/0066/0067 High:** wildcard/dev/prefer-stable là dependency-resolution policy; không tự chứng minh production đang có vulnerability.
- **MB-0072/0730 Critical:** secret regex phải giữ redacted location/type, phân biệt token thật/example/historical và trạng thái còn hiệu lực nếu có dữ liệu; không xuất raw values.
- **MB-0049/0050/0055 Critical:** ưu tiên severity theo advisory/bulletin cụ thể và affected version, không chỉ severity tĩnh của requirement.
- **MB-0786–0798:** useful source candidates nhưng nhiều API có legitimate use. Chỉ rõ sink/call/file/line, thiếu dataflow/reachability thì nói rõ. Không ép đổi API để làm finding biến mất.
- **MB-0800:** PHP/handler signature là suspicious-file evidence, không tự chứng minh server thực thi được file.

Không cần bỏ các check này. Giữ observations, phân loại chính xác và bổ sung remediation hướng đến xác minh nguyên nhân/impact thay vì sửa cú pháp một cách máy móc.

### P1 — Các detector bị loại cần được đánh giá lại như detector tìm risk

Các chủ đề authorization, escaping, webhook, secret storage, outbound policy và integration scope vẫn hữu ích ngay cả khi chỉ tìm được subset. Diagnostics Stripe/Adyen/legacy PayPal hiện chạy riêng ngoài profile; đã có evidence hữu ích nhưng chưa có native risk-candidate route để đưa vào triage đúng nghĩa.

Không bật lại nguyên 50 requirement cũ bằng cách bỏ human flag hoặc gán proof=verified_predicate. Detector cũ từng PASS khi inventory thiếu/empty hoặc dùng keyword làm guard; đó vẫn là lỗi cần sửa dù mục tiêu không yêu cầu coverage100%. Điều kiện đưa detector trở lại:
1. Observation cụ thể còn nguyên khi phần khác thiếu dữ liệu.
2. Không finding thì chỉ nói không phát hiện trong inspected scope; collection gap được giữ riêng.
3. Evidence có relative location/target/config key, redaction, bounded collection và reason rõ ràng.
4. Mô tả confidence và limitation, remediation/verification cụ thể; không cần human evidence trước khi scan.
5. Integration test chứng minh signal tới được Console finding và action flow, không biến thành error/support ticket hoặc normative FAIL ngoài ý muốn.

### P2 — Dễ tạo ticket trùng và noise

- MB-0049 và MB-0055: correlate package/version/advisory; retain nhiều requirement mappings nhưng không tạo hai ticket độc lập cho một risk.
- MB-0072 và MB-0730: correlate secret type/location/fingerprint không chứa raw secret; giữ khác biệt historical/deployed scope.
- MB-0780 và MB-0800: correlate theo file, giữ riêng filename và content signature evidence.
- MB-0014 và MB-0795: cùng location có thể mô tả superglobal access và request logging; liên kết evidence thay vì tăng issue count mù.
- MB-0059 tuổi advisory, MB-0062 release recency, MB-0063 repository activity, MB-0069 not-latest: hữu ích để ưu tiên/maintenance, không trình bày như bằng chứng vulnerability độc lập. Advisory mới cũng có thể cần xử lý ngay.
- MB-0806 record expiry/schema nên là readiness hoặc supplementary context của vulnerability, không chứng minh mitigation không hiệu lực.

Correlation phải bảo toàn scope/instance/release: không gộp hai advisory khác nhau hoặc hai endpoint khác nhau chỉ vì cùng requirement.

## Nhận xét từng profile

**Basic — nền tảng phù hợp nhất.** Có nhiều observation production trực tiếp và 7 readiness checks hữu ích cho vận hành. Cần điều chỉnh severity/wording của Admin route, MFA declaration và source/secret candidates. Giữ operational readiness riêng để người dùng không hiểu mọi failed item là security vulnerability.

**Hardening — phạm vi tốt, cách triage chưa đúng hẳn.** Bao gồm toàn bộ Basic/OWASP và bổ sung runtime/ACL/dependency; có 23 source/maintenance candidates theo review và 6 policy/record deviations. Cần route candidate riêng, correlation và context-sensitive guidance. Các gate runtime vẫn cần thiết; strict native API policy nên là optional coding policy, không được dùng như đại diện duy nhất cho SSRF/traversal/crypto risk detection.

**OWASP — có ích để nhóm risk, chưa cân bằng.** Nhiều source observations được đóng thành exact coding bans để thỏa verified-predicate model; các authorization/webhook/escaping detector sâu vẫn thiếu đường vào. Nên thêm detectors subset hữu ích theo risk category qua candidate contract; 4 readiness members cần hiển thị lane riêng hoặc đánh giá lại membership. Không trộn ASVS/PCI và không quảng cáo full OWASP coverage.

## Hướng thay đổi tiếp theo

1. Thêm risk-observation kind và confidence/limitation/coverage metadata bên cạnh assessment outcome; giữ tương thích CLI → agent → Console và không đổi ASVS/PCI semantics.
2. Cho candidate đi vào finding và Needs attention, đủ ticket/defer/false positive/risk-acceptance actions; collection gap đi riêng. Kiểm chứng rerun lifecycle: absence trong collection thiếu không được tự close finding.
3. Chuyển presentation/severity của các IDs nêu trên, đồng bộ catalog/import guidance rồi mới mở lại detector subset từ backlog.
4. Thêm dedup/correlation dựa trên target/asset/location/advisory và phân loại security/readiness/policy; báo scope đã đọc, không lấy requirement pass-rate làm thước đo duy nhất.

Review này không thay code thực thi, catalog, membership, production hoặc PHAR. Validation: exact79 unique membership, profile counts/lane/gate/guidance metadata reconciled; synthetic evaluator probe passed. Không chạy lại full CLI/Console suites vì không đổi behavior. Những đề xuất về lifecycle/ticket cần triển khai và kiểm thử riêng, chưa được coi đã hoàn thành.
