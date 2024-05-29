# Certification counts

## list

|Name|count|
|---|-----|
|OffSec Web Expert (OSWE)|3136|
|OffSec Certified Expert (OSCE)|1299|
|OffSec Certified Expert 3 (OSCE3)|475|
|OffSec Exploitation Expert (OSEE)|134|
|Kali Linux Certified Professional (KLCP)|267|
|OffSec Wireless Professional (OSWP)|3037|
|OffSec Web Assessor (OSWA)|612|
|OffSec Certified Professional (OSCP)|16953|
|OffSec Exploit Developer (OSED)|834|
|OffSec Defense Analyst (OSDA)|457|
|OffSec macOS Researcher (OSMR)|114|
|OffSec Experienced Penetration Tester (OSEP)|2338|

## command

```bash
curl -s -k -X POST 'https://api.accredible.com/v1/recipient/groups/search' \
    -H 'content-type: application/json' \
    -H 'accept: application/json' \
    -H 'x-signature: 72d1c71f991bf57347c8806a5b9532f26e663c37a5ffd5d827f05bac22680923' \
    -H 'x-timestamp: 1706668878' \
    --data-raw '{"filter_queries":[{"field":"organization.id","value":81055}]}' | jq -r "[.hits[]|{course_name: ._source.course_name,count: ._source.credentials_count}]"
```
