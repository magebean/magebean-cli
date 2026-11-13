# QA Magebean theo mục tiêu quét trạng thái hiện tại

Ngày báo cáo: 2026-11-11, múi giờ người dùng America/Vancouver.

## Kết luận

Hướng cốt lõi phù hợp với Magebean: đọc trạng thái có thể thu thập, chỉ ra vấn đề kỹ thuật quan sát được và hướng xử lý có thể kiểm tra lại. Catalog hiện tại chưa hoàn toàn thống nhất với hướng đó. Các điểm chính là phạm vi dependency chưa phân biệt lock/install, policy được trình bày gần giống security defect, nhiều projection cho cùng một vấn đề và vài kết luận sạch sai có thể tái hiện.

Khả năng automation không phải điều kiện đủ để một rule thuộc core current-state audit. Một phép kiểm tra có thể đúng về cú pháp nhưng chỉ đo policy, checklist hoặc mong muốn kiến trúc. Không có đề xuất retirement đồng loạt dựa vào metadata trong báo cáo này.

## Phạm vi và bằng chứng

- Đã đối chiếu đủ **110 rule active** thuộc family Magebean: criterion, check/args, profile/capability, scope bằng chứng và chất lượng finding. [Inventory máy đọc được](qa-inventory.json) được kiểm tra đủ 110 ID.
- [Nhóm 1: 38 rule](qa-part1.md), [nhóm 2: 38 rule](qa-part2.md), [nhóm 3: 34 rule](qa-part3.md) có nhận xét từng rule. Mức độ kiểm chứng được ghi riêng: review predicate/binding, đọc implementation, regression có sẵn hoặc fixture thực thi; không giả định mọi trường hợp của 110 rule đã được thực nghiệm.
- **49 quan sát fixture**: 23 dependency/deployment, 15 source/config và 5 DI/policy, cộng 6 projection kiểm chứng overlap. Chúng là dữ liệu tổng hợp, SQLite/injected API/loopback và code không được thực thi khi source scanning. PHP constructor fixture được thực thi có chủ ý để đối chiếu cơ chế khởi tạo.
- Kết quả thô: [nhóm 1](qa-part1-probes.json), [nhóm 2](qa-part2-probes.json), [nhóm 3](qa-part3-probes.json), [overlap](qa-overlap-probes.json). [12 lệnh test nhóm 3](qa-part3-tests.json) đều exit 0; test pass không loại trừ các lỗi phản ví dụ bên dưới.
- ASVS/PCI không nằm trong vòng QA này. 50 ID inactive được giữ làm phụ lục tham chiếu trong inventory; không được tính như 50 rule đang scan hay chứng nhận lại toàn bộ detector của chúng.
- Không sửa production code, catalog, profile hoặc PHAR trong lượt QA này. Không audit store/staging thật.

## 1. Những phần lệch core hoặc cần baseline riêng

| Nhóm / rule | Vấn đề với mục tiêu hiện tại | Đề xuất |
|---|---|---|
| MB-0093 | Đếm topic trong checklist không chứng minh điểm yếu kỹ thuật của store hay chất lượng evidence PCI. | Giữ như document/evidence lint tùy chọn, ngoài core technical findings. Hiện chưa nằm trong built-in profile. |
| MB-0806 | Kiểm tra structure/expiry của record mitigation; không kiểm tra mitigation còn chạy, hiệu quả hay đầy đủ. | Governance lint có context; đính kèm advisory/mitigation thực tế, không biến lỗi schema record thành lỗ hổng độc lập. Đã có prerequisite/capability. |
| MB-0069 | Không ở latest stable không đồng nghĩa đang có lỗ hổng hoặc đã hết hỗ trợ. Có cả require-dev. | Maintenance/update opportunity; ưu tiên advisory và support status đã xác minh. |
| MB-0062, MB-0063 | Release cũ hoặc repo archived là tín hiệu bảo trì; riêng chúng không chứng minh EOL, exploitability hay chưa có vendor support. | Ghi facts/provenance và confidence phù hợp; không đồng nhất freshness với support lifecycle. |
| MB-0059 | Tuổi advisory 30 ngày là ngưỡng ưu tiên/policy; không phải thời gian tổ chức phát hiện hay remediation SLA. | Metadata/priority trong finding advisory gốc, có policy nguồn rõ ràng. |
| MB-0065–MB-0067 | Wildcard, dev branch và prefer-stable là policy resolver/build. Probe cho thấy thiếu prefer-stable FAIL, nhưng true vẫn có thể cùng tồn tại với dev branch. | Optional build hygiene; không mặc định High security chỉ từ các khai báo này. Lock hiện tại và installed component phải được xét riêng. |
| MB-0038, MB-0040 | Backend Redis/Varnish hoặc session bắt buộc Redis là lựa chọn kiến trúc. Probe file sessions tạo FAIL “not hardened” dù chưa chứng minh quyền file/rò rỉ. | Baseline vận hành tùy chọn; core đánh giá protection của backend thực tế, không chỉ việc không dùng Redis. |
| MB-0006, MB-0014 | Admin route tên thường và truy cập superglobal không tự chứng minh truy cập trái phép/input không được kiểm tra. | Policy/advisory hoặc thêm context; không gộp với lỗi authentication/validation đã xác minh. |
| MB-0786, MB-0788–MB-0790, MB-0792–MB-0794, MB-0796, MB-0798 | Ban syntax/API có thể bắt cả operation hợp lệ: local file read, fixed process command, non-security randomness/checksum hoặc HTTP string không phải endpoint. | Giữ policy rõ ràng hoặc dùng source-to-sink/context để tạo suspected issue. Các rule strict native đã có capability gate; không cáo buộc chúng chạy mặc định khi chưa opt-in. |

MB-0791/0787/0797 và các pattern có khả năng nguy hiểm vẫn hữu ích, nhưng occurrence, risk và exploitability là các tầng bằng chứng khác nhau. Không có kết luận rằng nên xóa mọi rule syntax hoặc đổi mọi kết quả thành thông tin vô hại.

## 2. Trùng lắp và quan hệ bổ sung

| Rule | Bằng chứng | Đề xuất |
|---|---|---|
| MB-0728 / MB-0731 | Exact duplicate check `magento_admin_password_minimum_configured`, min_length=8, LOCAL; cùng fixture min 7 tạo hai High/confirmed. | Một canonical predicate và alias/migration cho ID còn lại. MB-0731 hiện không trong built-in profile, nên chưa nhân count mặc định. Cặp này được tạo lại sau đợt khôi phục. |
| MB-0038 / MB-0741 | MB-0038 chứa nguyên check/args no-file-backend của MB-0741, kèm policy Redis mạnh hơn. | Một evidence source, tách policy level; không đồng nhất hai criterion. MB-0741 chưa nằm trong profile. |
| MB-0061 / MB-0744 | MB-0061 chứa nguyên strict library maintenance check/args của MB-0744, cộng inventory rộng hơn. | Chuẩn hóa inventory/evidence; không báo cùng library abandonment hai lần. MB-0744 chưa trong profile. |
| MB-0049 / MB-0055 / MB-0056 / MB-0059 | Cùng transitive package/advisory tạo FAIL ở 0049, 0055 và age rule; 0056 mô tả khả năng cập nhật. | Một finding theo package/version/advisory/scope; transitive chain, fix constraints và tuổi advisory là supporting context. |
| MB-0049 / MB-0828 | Cùng mục tiêu advisory nhưng nguồn online/local khác nhau và hiện ở profile khác. | Dataset/provenance rõ ràng. Khác kết quả có thể do dataset; không tự gọi là conflict hoặc dedupe khi scope/dataset khác. |
| MB-0733 / MB-0736 | Cùng inline JS output trong PHTML tạo hai High/confirmed. | Chung issue family/context/location. Cả hai hiện chưa được chọn bởi built-in profile. |
| MB-0780 / MB-0800 | `pub/media/unexpected.php` tạo một finding ở mỗi rule. Hai rule cùng có trong prelaunch/hardening/takeover. | Một issue upload artifact với filename/content/handler evidence; giữ các tín hiệu khác biệt nếu có. |
| MB-0790 / MB-0822 | Cùng exec(request) location tạo policy finding và request-flow finding. Cùng xuất hiện trong development/prelaunch/takeover. | Ưu tiên flow finding; API-policy occurrence là supporting evidence, không tăng số lỗi độc lập. |
| MB-0795 / MB-0814 | Cùng log($_POST) location tạo finding ở hai detector khác scope selection. | Normalize subject/location và gắn module attribution. Không nhất thiết trùng trong profile mặc định hiện tại. |
| MB-0046 / MB-0783 / MB-0047 / MB-0048 / MB-0785 | Scheduler presence, cadence, execution recency, queue count và success/backlog health là các câu hỏi khác nhau. | Chung nhóm cron, giữ từng evidence fact. Không gộp thành một predicate rồi làm mất khả năng phân biệt nguyên nhân. |
| MB-0035 / MB-0784 | Có artifact bất kỳ và representative assets theo observed theme/locale là hai mức coverage. | Một nhóm artifact readiness với evidence theo scope; PASS mức thô không chứng nhận mức đầy đủ. |
| MB-0729 / MB-0739 / MB-0740 / MB-0742 / MB-0804 / MB-0807 | Project declarations, named integration flags và process maps không có cùng proof strength. | Chia evidence level declared/resolved/process-observed; chỉ merge khi cùng nguồn/path/claim. |

Không dedupe chỉ theo tên file: cùng file có thể có nhiều lỗi độc lập. Group theo subject, location, issue family/root cause và scope, giữ provenance các rule.

## 3. Conflict về scope hoặc policy

### P1 — runtime credential hợp lệ bị gọi như secret exposure

Probe đặt credential tổng hợp trong `app/etc/env.php`, mode 0600, không có Git metadata. MB-0072 vẫn tạo Critical/confirmed từ working-tree match; MB-0730 PASS vì chủ ý loại env.php. `GitHistoryCheck.php` gọi scanWorkingTree ngay trong history mode. Đây không phải contradiction Boolean: hai predicate khác exclusions. Nhưng tên/scope finding đang không phân biệt approved runtime secret với tracked/history/public exposure.

Cần tách: credential nằm đúng runtime config, secret bị commit, file công khai và secret lộ ở vị trí bất thường. Pattern match không tự chứng minh exposure hay credential còn hiệu lực.

### Dependency lock khác installed/enabled deployment

Fixture production installed inventory chỉ có package production; lock còn packages-dev và dependency dev-only có advisory. MB-0049 và MB-0055 đều FAIL trên dev-only package không có trong installed inventory. Matching đúng lock criterion, nhưng chưa chứng minh store runtime đang dùng component đó. Cần ghi provenance locked/installed/dev/enabled, giữ build-risk trong scope riêng. Không tự bỏ mọi dev dependency: development/CI có thể thực sự dùng chúng.

### Absence không thống nhất với disabled

MB-0729 có thể xác nhận không thấy khai báo debug enabled; các rule restored yêu cầu explicit disabled và cho UNKNOWN khi missing. Hai kết quả không mâu thuẫn logic, nhưng không được tóm tắt cả hai thành “runtime debug đã tắt”. Tương tự, no-file cache và must-use-Redis là hai policy level khác nhau.

### Trạng thái tạm thời khác lỗi vận hành

MB-0039 đánh dấu `working` là FAIL mà không xét khoảng thời gian; một indexing job đang chạy bình thường chưa phải stuck job. MB-0047 PASS cho execution error mới 60 giây và MB-0048 PASS vì không có pending backlog là đúng hai predicate hẹp, không chứng minh cron khỏe. Nên trình bày các fact và dùng duration/status/success context để tạo incident có ý nghĩa.

## 4. Lỗi implementation tái hiện được

| Ưu tiên QA | Rule / code | Kết quả thực nghiệm | Yêu cầu sửa |
|---|---|---|---|
| P1 | MB-0815/0816/0818; `MagentoDiCheck::concrete()` | Child kế thừa constructor private được inspect trả `ok`; PHP khởi tạo đúng pattern đó ném Error. | Resolve inherited construction hoặc báo unavailable, không xác nhận instantiability chỉ từ constructor own-class. |
| P2 | MB-0062; `ComposerRepositoryChecks.php:334` | `2026-02-30` được normalize sang March 2 và PASS; `yesterday` cũng PASS như release timestamp hợp lệ. | Strict absolute timestamp/calendar validation; dữ liệu không hợp lệ không tạo clean maintenance conclusion. |
| P2 | MB-0059; `ComposerAdvisoryChecks.php:700,708,767` | Published=2099 cho tuổi 0 và PASS; message nói remediation SLA dù criterion loại SLA. | Reject future/malformed dates và sửa message thành publication-age context. |

Hai điểm cần làm rõ, không khẳng định source/policy mismatch đã chứng minh:

- MB-0805 PASS khi lock package version rỗng nhưng source policy khớp. Cần validator inventory chung; đây là input-quality gap, không phải bằng chứng approved source URL/reference sai.
- MB-0817 chấp nhận array cho callable parameter mà không kiểm tra callable shape/target. Hoặc thu hẹp rõ “potential type compatibility”, hoặc unavailable khi callable construction chưa được hỗ trợ.

## 5. Chất lượng finding và profile

- Các raw policy FAIL có confidence=confirmed nhưng category không hiện diện trong projection legacy; điều được confirmed là syntax/config-policy observation, không phải lỗ hổng đã khai thác được. Cần category và title rõ ngay cả khi overview ẩn confidence theo yêu cầu người dùng.
- Module checks thường có file/line/module và reason tốt, nhưng nhiều risk/remediation vẫn dùng đoạn chung. DI, missing service method, patch cycle và handler mismatch nên nói cụ thể ảnh hưởng đến module/area nào và test lại command/flow nào; không hứa toàn bộ checkout/upgrade đúng.
- Mười rule restored đều không có membership trong built-in profile: 0043,0093,0731,0733,0736,0739,0740,0741,0742,0744. Điều này tránh auto-duplicate nhưng cũng làm template coverage 0733/0736 không chạy ở development/prelaunch. Cần quyết định membership theo mission, không theo việc ID mới được khôi phục.
- Development kiểm tra source declarations, prelaunch có thể kiểm tra effective enabled context; cùng rule ID cần ghi scope mode/module activation rõ trong evidence, không suy ra active exposure từ source tồn tại.
- Core module source mặc định chủ yếu app/code; vendor được dùng làm context hoặc module được chọn. Không dùng số rules executed như coverage của mọi installed extension/file/route.
- Collection budgets, missing inputs và unsupported analysis là scanner diagnostics. Giữ structured coverage và exit semantics, nhưng không biến chúng thành security findings. Không đề xuất khôi phục warning-heavy overview mà người dùng đã yêu cầu ẩn.

## 6. Đề xuất thống nhất

1. **Core current-state findings:** known advisory đúng inventory, protection/config có context, exposure/file/permission có bằng chứng, source-to-sink hoặc declaration/consistency defects trong scope hỗ trợ.
2. **Contextual advisories:** maintenance age, repository status, transient operational state, suspicious source patterns. Ghi vì sao cần xem xét mà không nâng thành xác nhận exploitability.
3. **Explicit policies:** coding bans, backend preference, build/update thresholds, approved-source/role baselines. Opt-in/baseline rõ; policy violation là một loại finding riêng.
4. **Evidence/governance lint:** checklist và record structure. Có thể tự động làm tốt nhưng nằm ngoài core technical weakness.

Trước khi một finding được coi là actionable technical issue, cần có: subject/location/observed value cụ thể; source và collection time/scope; baseline hoặc quan hệ kỹ thuật bị vi phạm; confidence/category phù hợp; remediation gắn bằng chứng; cách kiểm tra lại; và correlation tránh đếm một vấn đề nhiều lần.

Thứ tự đề xuất: sửa ba lỗi kết luận sạch ở trên và conflict secret scope; thống nhất dependency provenance; gom duplicate findings; tách policy/governance khỏi core; cuối cùng điều chỉnh profile và hướng dẫn theo 110 dòng review. Đây là báo cáo để quyết định, chưa thực hiện các thay đổi đó.
