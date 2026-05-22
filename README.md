# CISA KEV Crawler

하루보안(HaruBoan) 파이프라인의 **데이터 수집기**.

[CISA Known Exploited Vulnerabilities 카탈로그](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)를 크롤링해 팀 공통 스키마(`AdvisoryRecord`)로 정규화한 뒤 JSON으로 저장한다. CVSS 점수·벡터는 [NVD REST API](https://services.nvd.nist.gov/rest/json/cves/2.0)에서 보강하며, 저장된 JSON은 이후 LLM 후처리 단계의 입력으로 쓰인다.

## 동작 방식

1. CISA KEV 전체 카탈로그를 한 번에 내려받는다.
2. `--days N` 기준으로 최근 N일 내 추가된 항목만 필터링한다.
3. 각 항목의 CVE ID로 NVD API를 조회해 CVSS 점수·벡터·CPE 정보를 보강한다.
   - NVD 호출은 `ThreadPoolExecutor`로 병렬 처리한다 (API 키 없음: 5 workers, 있음: 50 workers).
4. `product`가 `"Multiple Products"`인 항목은 NVD CPE 목록을 기반으로 개별 `affected` 항목으로 확장한다.
5. 결과를 `output/`에 JSON으로 저장한다.

## 요구사항

- Python 3.11 이상
- NVD API 키 (선택) — 없으면 건당 6초 제한, 있으면 0.6초

## 설치

```bash
pip install -e ".[dev]"
```

`uv` 사용 시:

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
```

## 환경설정

```bash
cp .env.example .env
```

| 변수              | 설명                           | 기본값     |
| ----------------- | ------------------------------ | ---------- |
| `NVD_API_KEY`     | NVD API 키 (rate limit 완화용) | (없음)     |
| `OUTPUT_DIR`      | 크롤 결과 저장 디렉터리        | `./output` |
| `REQUEST_TIMEOUT` | HTTP 요청 타임아웃 (초)        | `30`       |

`.env`는 `.gitignore` 대상이므로 커밋되지 않는다.

## 실행

```bash
cisa-kev-crawler              # 최근 7일치 수집
cisa-kev-crawler --days 14    # 최근 14일치 수집
cisa-kev-crawler --output-dir ./data  # 저장 경로 지정
```

## 출력 형식

결과는 `output/`에 두 가지 형태로 저장된다.

```
output/
├── latest.json                          # 항상 최신 결과 (다운스트림 고정 경로)
└── cisa_kev_{YYYYMMDD_HHmmss}.json      # 실행 이력
```

최상위 구조(`CrawlResult`):

```json
{
  "crawled_at": "2026-05-22T10:00:00Z",
  "query_from": "2026-05-16",
  "query_to": "2026-05-22",
  "source": "cisa_kev",
  "count": 5,
  "records": []
}
```

`records` 각 원소(`AdvisoryRecord`) 주요 필드:

| 필드           | 내용                                                                             |
| -------------- | -------------------------------------------------------------------------------- |
| `id`           | `sha256("cisa_kev:" + cveID)[:32]`                                               |
| `title`        | `vulnerabilityName`                                                              |
| `content_raw`  | `shortDescription`                                                               |
| `published_at` | `dateAdded` → ISO 8601                                                           |
| `due_date`     | `dueDate` → ISO 8601                                                             |
| `severity`     | NVD CVSS 보강 (`label` / `cvss_score` / `cvss_vector`), 실패 시 `label: unknown` |
| `affected[]`   | 단일 제품이면 1개, `"Multiple Products"`이면 NVD CPE 기반 확장                   |
| `identifiers`  | `cve_ids`, `kev_listed: true`, `ransomware_known`                                |
| `tags.cwe`     | `cwes` → `[{id, name}]`                                                          |
| `action`       | `required_action` + `notes`에서 파싱한 `references[]`                            |
| `audience`     | LLM 후처리 슬롯 — 크롤러는 기본값(0.0)으로 채운다                                |

`jq` 활용 예시:

```bash
jq '.count'            output/latest.json   # 수집 건수
jq '.records[0]'       output/latest.json   # 첫 레코드 전체
jq '.records[].identifiers.cve_ids[]'  output/latest.json  # CVE ID 목록
```

## 테스트

```bash
pytest                          # 전체 테스트 (네트워크 호출은 모두 모킹)
ruff check . && ruff format .   # 린트·포맷
```

## 트러블슈팅

| 증상              | 원인 및 해결                                                                                  |
| ----------------- | --------------------------------------------------------------------------------------------- |
| NVD 응답이 느리다 | API 키 미설정 시 건당 6초 sleep. `NVD_API_KEY` 설정으로 0.6초로 단축된다.                     |
| `count`가 0이다   | 해당 기간 내 신규 KEV 항목 없음. `--days` 값을 늘린다.                                        |
| NVD 조회 실패     | 네트워크 오류·rate limit 초과 시 `severity.label`이 `"unknown"`으로 저장되고 크롤은 계속된다. |
