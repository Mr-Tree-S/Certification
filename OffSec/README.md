# Certification counts

## reference

<https://status.offsec.com/>

## list

|Name|count|
|---|-----|
|OffSec Experienced Penetration Tester (OSEP)|2338|
|OffSec Web Expert (OSWE)|3136|
|OffSec Exploit Developer (OSED)|834|
|---|-----|
|OffSec Certified Expert 3 (OSCE3)|475|
|OffSec Exploitation Expert (OSEE)|134|
|---|-----|
|OffSec Certified Professional (OSCP)|16953|
|OffSec Web Assessor (OSWA)|612|
|OffSec macOS Researcher (OSMR)|114|
|---|-----|
|OffSec Wireless Professional (OSWP)|3037|
|OffSec Defense Analyst (OSDA)|457|

## command

```bash
curl -s -k -X POST 'https://api.accredible.com/v1/recipient/groups/search' \
    -H 'content-type: application/json' \
    -H 'accept: application/json' \
    -H 'x-signature: 72d1c71f991bf57347c8806a5b9532f26e663c37a5ffd5d827f05bac22680923' \
    -H 'x-timestamp: 1706668878' \
    --data-raw '{"filter_queries":[{"field":"organization.id","value":81055}]}' | jq -r "[.hits[]|{course_name: ._source.course_name,count: ._source.credentials_count}]"
```
