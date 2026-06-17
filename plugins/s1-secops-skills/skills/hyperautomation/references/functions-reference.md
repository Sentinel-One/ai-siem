# Functions Reference

All functions use the syntax `{{Function.FUNCTION_NAME(args)}}`.
Functions can be nested: `{{Function.STRING(Function.MUL(42, Function.DATETIME_TO_MS(Function.DATETIME_NOW())))}}`.

Store complex JQ expressions in a Variable first, then reference the variable in the function call —
this avoids escaping headaches: `{{Function.JQ(input, local_var.myJqExpression)}}`.

---

## Arithmetic
| Function | Description | Usage |
|----------|-------------|-------|
| `ADD(n1, n2)` | Sum | `{{Function.ADD(5, 3)}}` |
| `SUBTRACT(n1, n2)` | Difference | `{{Function.SUBTRACT(10, 3)}}` |
| `MUL(n1, n2)` | Product | `{{Function.MUL(42424242, Function.DATETIME_TO_MS(Function.DATETIME_NOW()))}}` |
| `DIV(n1, n2)` | Quotient | `{{Function.DIV(local_var.minutes, 60)}}` |

---

## Date & Time
| Function | Description | Usage |
|----------|-------------|-------|
| `DATETIME_NOW()` | Current datetime as string | `{{Function.DATETIME_NOW()}}` |
| `DATETIME_TO_MS(date)` | Convert datetime string to milliseconds | `{{Function.DATETIME_TO_MS(Function.DATETIME_NOW())}}` |
| `DATETIME_TO_EPOCH(date)` | Convert to epoch timestamp | `{{Function.DATETIME_TO_EPOCH(date)}}` |
| `EPOCH_TO_DATETIME(epoch)` | Epoch to datetime string | `{{Function.EPOCH_TO_DATETIME(epoch)}}` |
| `MS_TO_DATETIME(ms)` | Milliseconds to datetime | `{{Function.MS_TO_DATETIME(local_var.time_from)}}` |
| `DELTA(date, hours)` | Subtract hours from date (negative = add) | `{{Function.DELTA(singularity-response-trigger.data.indicators[0].eventTime,-0.1)}}` |
| `DELTA_NOW(hours)` | Subtract hours from now (negative = add) | `{{Function.DELTA_NOW(-72)}}` adds 72h |
| `DELTA_SECONDS_NOW(seconds)` | Subtract seconds from now | `{{Function.DELTA_SECONDS_NOW(seconds)}}` |
| `FORMATTED_DATE(input, format, tz?)` | Format a date | `{{Function.FORMATTED_DATE("now", "%d %b \| %I:%M:%S %p %Z")}}` |
| `DATE(string)` | Convert string to date format | `{{Function.DATE(string)}}` |

---

## Array & Object Operations
| Function | Description | Usage |
|----------|-------------|-------|
| `APPEND(array, item)` | Add item to array | `{{Function.APPEND(local_var.myList, loop.item)}}` |
| `PREPEND(array, item)` | Add item to front | `{{Function.PREPEND(array, item)}}` |
| `ACCESS_LIST_ITEM(list, index)` | Get item at index | `{{Function.ACCESS_LIST_ITEM(Function.JQ(data, filter), 0)}}` |
| `FILTER_ARRAY(array, value)` | Filter array by value | `{{Function.FILTER_ARRAY(array, value)}}` |
| `FILTER_OBJECTS(array, key, value)` | Filter objects by key/value | `{{Function.FILTER_OBJECTS(channels, "name", local_var.channelName)}}` |
| `FLATTEN_ARRAY(nested)` | Flatten nested array | `{{Function.FLATTEN_ARRAY(nested_array)}}` |
| `DEDUP_ARRAY(array)` | Remove duplicates | `{{Function.DEDUP_ARRAY(array)}}` |
| `DEDUP_BY_KEY(array, key)` | Remove duplicate objects by key | `{{Function.DEDUP_BY_KEY(array, key)}}` |
| `INTERSECTION(a, b)` | Array intersection | `{{Function.INTERSECTION(array1, array2)}}` |
| `UNION(a, b)` | Array union | `{{Function.UNION(list1, list2)}}` |
| `ARRAY_DIFF(a, b)` | Elements in a not in b | `{{Function.ARRAY_DIFF(list1, list2)}}` |
| `MAP_TABLE(columns, rows)` | Map PQ results to named objects | `{{Function.MAP_TABLE(local_var.cols, local_var.rows)}}` |
| `AGG_BY_KEY(array, key)` | Aggregate objects by key | `{{Function.AGG_BY_KEY(array, key)}}` |
| `EXTRACT_VALUE_BY_KEY(array, key)` | Extract values for a key | `{{Function.EXTRACT_VALUE_BY_KEY(array, key)}}` |
| `UNIQUE_BY_KEY(array, key)` | Unique values for key | `{{Function.UNIQUE_BY_KEY(array, key)}}` |
| `ISIN(value, lookfor)` | Check if value contains lookfor | `{{Function.ISIN(value, lookfor)}}` |
| `LENGTH(value)` | Length of string or array | `{{Function.LENGTH(local_var.myList)}}` |

---

## JQ (JSON Query)
The most powerful function. Reference: https://jqlang.org/manual

```
{{Function.JQ(input, jq_filter)}}
{{Function.JQ(input, jq_filter, true)}}  ← raw output (no JSON wrapping)
```

**Best practice**: Store the JQ expression in a Variable first:
```json
{ "name": "jqFilter", "value": ".[] | select(.score > 50) | {ip: .ipAddress, score: .abuseConfidenceScore}" }
```
Then use: `{{Function.JQ(local_var.data, local_var.jqFilter)}}`

Common patterns:
```jq
# Extract field from array
.[].name

# Filter and select
.[] | select(.location == "Antarctica")

# Build new object from each element
.[] | {source: "Custom", type: "URL", value: .value}

# Get column names from PowerQuery
.[].name

# Convert object keys to array of {key, value}
.data | to_entries | .[]

# Export as CSV
["Device","IP"], (.[] | [.computerName, .lastIpToMgmt]) | @csv
```

---

## Extraction
| Function | Description | Usage |
|----------|-------------|-------|
| `EXTRACT_IPS(string)` | Extract all IPs from text | `{{Function.EXTRACT_IPS(response.body)}}` |
| `EXTRACT_EXTERNAL_IPS(string)` | External IPs only | `{{Function.EXTRACT_EXTERNAL_IPS(string)}}` |
| `EXTRACT_DOMAINS(string)` | Extract domain names | `{{Function.EXTRACT_DOMAINS(string)}}` |
| `EXTRACT_URLS(string)` | Extract URLs | `{{Function.EXTRACT_URLS(string)}}` |
| `EXTRACT_EMAIL(string)` | First email address | `{{Function.EXTRACT_EMAIL(string)}}` |
| `EXTRACT_EMAILS(string)` | All email addresses | `{{Function.EXTRACT_EMAILS(string)}}` |
| `EXTRACT_ANY_HASH(string)` | All hash types | `{{Function.EXTRACT_ANY_HASH(string)}}` |
| `EXTRACT_MD5(string)` | MD5 hashes | `{{Function.EXTRACT_MD5(string)}}` |
| `EXTRACT_SHA1(string)` | SHA1 hashes | `{{Function.EXTRACT_SHA1(string)}}` |
| `EXTRACT_SHA256(string)` | SHA256 hashes | `{{Function.EXTRACT_SHA256(string)}}` |
| `EXTRACT_LINKS(string)` | Hyperlinks | `{{Function.EXTRACT_LINKS(string)}}` |

---

## String Manipulation
| Function | Description | Usage |
|----------|-------------|-------|
| `REPLACE(str, find, replace)` | Replace all occurrences | `{{Function.REPLACE(text, "]", "")}}` |
| `REPLACE_FIRST(str, find, replace)` | Replace first occurrence | `{{Function.REPLACE_FIRST(str, find, with)}}` |
| `SPLIT(str, delim)` | Split string | `{{Function.SPLIT(str, ".")}}` |
| `UPPER(str)` | Uppercase | `{{Function.UPPER(str)}}` |
| `LOWER(str)` | Lowercase | `{{Function.LOWER(str)}}` |
| `CAPITALIZE(str)` | Capitalize first char | `{{Function.CAPITALIZE(str)}}` |
| `TITLE(str)` | Title case | `{{Function.TITLE(str)}}` |
| `STRIP_HTML_TAGS(str)` | Remove HTML | `{{Function.STRIP_HTML_TAGS(str)}}` |
| `STRIP_NEWLINES(str)` | Remove newlines | `{{Function.STRIP_NEWLINES(str)}}` |
| `NEWLINE_TO_BR(str)` | Newlines to `<br>` | `{{Function.NEWLINE_TO_BR(str)}}` |
| `HTML_ENCODE(str)` | HTML-encode string | `{{Function.HTML_ENCODE(local_var.note)}}` |
| `HTML_DECODE(str)` | HTML-decode string | `{{Function.HTML_DECODE(str)}}` |
| `URL_ENCODE(str)` | URL-encode | `{{Function.URL_ENCODE(str)}}` |
| `URL_DECODE(str)` | URL-decode | `{{Function.URL_DECODE(str)}}` |
| `STRING(value)` | Convert to string | `{{Function.STRING(Function.MUL(42, ts))}}` |
| `INT(value)` | Convert to integer | `{{Function.INT(value)}}` |
| `FLOAT(value)` | Convert to float | `{{Function.FLOAT(value)}}` |
| `SUBSTRING(str, maxChars)` | Truncate string | `{{Function.SUBSTRING(str, 100)}}` |
| `TRUNCATE_WORDS(str, maxWords)` | Truncate to N words | `{{Function.TRUNCATE_WORDS(str, 50)}}` |
| `SLICE(str)` | Remove leading chars | `{{Function.SLICE(str)}}` |
| `LSTRIP(str)` | Remove leading whitespace | `{{Function.LSTRIP(str)}}` |
| `RSTRIP(str)` | Remove trailing whitespace | `{{Function.RSTRIP(email-trigger.body)}}` |
| `INCLUDE(value, search)` | Check if value contains search | `{{Function.INCLUDE(str, "needle")}}` |
| `INDEX_OF(value, sub)` | Index of substring | `{{Function.INDEX_OF(str, sub)}}` |
| `LAST_INDEX_OF(value, sub)` | Last index of substring | `{{Function.LAST_INDEX_OF(str, sub)}}` |
| `MATCH_REGEX(str, regex)` | Boolean regex match | `{{Function.MATCH_REGEX(str, pattern)}}` |
| `REGEX_EXTRACT(str, regex)` | Extract matching parts | `{{Function.REGEX_EXTRACT(str, pattern)}}` |
| `PARSE_JSON(str)` | Parse JSON string | `{{Function.PARSE_JSON(json_string)}}` |
| `OBJECTIFY(str)` | Deep JSON parse | `{{Function.OBJECTIFY(str)}}` |
| `PARSE_LIST(csv)` | CSV string to list | `{{Function.PARSE_LIST("a,b,c")}}` |
| `PRETTY_PRINT(value, indent?)` | Format JSON nicely | `{{Function.PRETTY_PRINT(local_var.obj)}}` |
| `BEAUTIFY(input, delim)` | Human-readable from JSON list | `{{Function.BEAUTIFY(input, ",")}}` |
| `REMOVE_TEXT(str, remove)` | Remove text | `{{Function.REMOVE_TEXT(str, to_remove)}}` |
| `REMOVE_FIRST_TEXT(str, remove)` | Remove first occurrence | `{{Function.REMOVE_FIRST_TEXT(str, sub)}}` |
| `RANDOM_STRING(length)` | Random alphanumeric | `{{Function.RANDOM_STRING(8)}}` |
| `GENERATE_UUID4()` | Random UUID | `{{Function.GENERATE_UUID4()}}` |
| `BASE64_ENCODE(str)` | Encode to Base64 | `{{Function.BASE64_ENCODE(str)}}` |
| `BASE64_DECODE(b64)` | Decode from Base64 | `{{Function.BASE64_DECODE(b64)}}` |
| `BASE64_DECODE_AS_BYTES(b64)` | Decode to bytes | `{{Function.BASE64_DECODE_AS_BYTES(b64)}}` ← used for COMPRESS |
| `TO_SNAKE_CASE(str)` | snake_case | `{{Function.TO_SNAKE_CASE(str)}}` |

---

## Validation & Conditions
| Function | Description | Usage |
|----------|-------------|-------|
| `DEFAULT(value, fallback)` | Use fallback if value is null/empty | `{{Function.DEFAULT(action.body.field, "")}}` |
| `IS_BLANK(value)` | Boolean: is blank? | `{{Function.IS_BLANK(value)}}` |
| `IS_EMPTY(value)` | Boolean: is empty? | `{{Function.IS_EMPTY(value)}}` |

---

## File Handling
| Function | Description | Usage |
|----------|-------------|-------|
| `COMPRESS(files_array, type?, password?)` | Compress files | `{{Function.COMPRESS([local_var.csvData], "zip")}}` |
| `DECOMPRESS(file_data, type?, password?)` | Decompress | `{{Function.DECOMPRESS(file_data, "zip")}}` |

File data object format: `{"name": "file.csv", "data": "<base64_content>"}`
Compression types: `"zip"` (default), `"tar"`, `"gzip"`, `"bzip2"`
For Send Email attachments: pass in `[local_var.fileDataVar]` (in square brackets).

---

## Hashing & Cryptography
| Function | Description | Usage |
|----------|-------------|-------|
| `MD5(input)` | MD5 hash | `{{Function.MD5(text)}}` |
| `SHA1(input)` | SHA1 hash | `{{Function.SHA1(text)}}` |
| `SHA256(input)` | SHA256 hash | `{{Function.SHA256(text)}}` |
| `SHA512(input)` | SHA512 hash | `{{Function.SHA512(text)}}` |
| `HMAC_SHA256(text, key)` | HMAC-SHA256 | `{{Function.HMAC_SHA256(text, key)}}` |
| `HMAC_SHA1(text, key)` | HMAC-SHA1 | `{{Function.HMAC_SHA1(text, key)}}` |
| `HMAC_SHA256_VALIDATE(text, key, sig)` | Validate HMAC | `{{Function.HMAC_SHA256_VALIDATE(text, key, sig)}}` |
| `JWT_ENCODE(claims, secret, alg?)` | Sign JWT | `{{Function.JWT_ENCODE(claims, secret)}}` |
| `JWT_DECODE(jwt, secret, alg?)` | Decode JWT | `{{Function.JWT_DECODE(jwt, secret)}}` |
| `JWT_VERIFY(jwt, secret, alg?)` | Verify JWT signature | `{{Function.JWT_VERIFY(jwt, secret)}}` |

---

## Workflow Metadata
| Function | Description | Usage |
|----------|-------------|-------|
| `GET_WORKFLOW_ID()` | Current workflow ID | `{{Function.GET_WORKFLOW_ID()}}` |
| `GET_WORKFLOW_NAME()` | Current workflow name | `{{Function.GET_WORKFLOW_NAME()}}` |
| `GET_WORKFLOW_VERSION_ID()` | Version ID | `{{Function.GET_WORKFLOW_VERSION_ID()}}` |
| `GET_EXECUTION_ID()` | Current execution ID | `{{Function.GET_EXECUTION_ID()}}` |
| `WORKFLOW_LINK(...)` | URL to this execution | `{{Function.WORKFLOW_LINK()}}` |
| `GET_MANAGEMENT_URL()` | Console management URL | `{{Function.GET_MANAGEMENT_URL()}}` ← used in some actions |

---

## Variable Retrieval
| Function | Description | Usage |
|----------|-------------|-------|
| `GET_LOCAL_VAR(name)` | Get local variable | `{{Function.GET_LOCAL_VAR("myVar")}}` |
| `GET_GLOBAL_VAR(name)` | Get global variable | `{{Function.GET_GLOBAL_VAR("myVar")}}` |

---

## PowerQuery result handling pattern

When a PowerQuery returns `columns` (array of `{name}` objects) and `values` (2D array):

```json
/* Step 1: Extract column names */
{ "name": "cols", "value": "{{Function.JQ(power-query.body.columns, \".[].name\")}}" }

/* Step 2: Map results to named objects */
{ "name": "mapped", "value": "{{Function.MAP_TABLE(local_var.cols, local_var.rows)}}" }

/* Result: array of objects like {column1: val, column2: val, ...} */
```
