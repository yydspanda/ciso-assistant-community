\set ON_ERROR_STOP on

SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I',
    current_database(),
    :'runtime_role'
)
\gexec
SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I',
    current_database(),
    :'backup_role'
)
\gexec

REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('GRANT ALL ON SCHEMA public TO %I', :'migrator_role')
\gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_role')
\gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'backup_role')
\gexec

SELECT format(
    'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO %I',
    schemaname,
    tablename,
    :'runtime_role'
)
FROM pg_tables
WHERE schemaname = 'public'
\gexec
SELECT format(
    'GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I',
    :'runtime_role'
)
\gexec

-- Authority-bearing regulatory rows deny table-wide UPDATE/DELETE/TRUNCATE.
-- The later recorded_to grant is a compatibility concession for the Django
-- temporal-close service, not a database-enforced transition contract. Django
-- services and IAM remain the primary authority boundary in this local profile.
SELECT format(
    'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE %I.%I FROM %I',
    schemaname,
    tablename,
    :'runtime_role'
)
FROM pg_tables
WHERE schemaname = 'public' AND tablename LIKE 'regulatory\_%' ESCAPE '\'
\gexec

-- PostgreSQL requires some UPDATE privilege for SELECT ... FOR UPDATE. Every
-- regulatory table has a database check fixing is_published to false in this
-- bounded slice, so that column is the non-authoritative row-lock token.
SELECT format(
    'GRANT UPDATE (is_published) ON TABLE %I.%I TO %I',
    schemaname,
    tablename,
    :'runtime_role'
)
FROM pg_tables
WHERE schemaname = 'public' AND tablename LIKE 'regulatory\_%' ESCAPE '\'
\gexec

SELECT format(
    'GRANT UPDATE (recorded_to) ON TABLE public.%I TO %I',
    table_name,
    :'runtime_role'
)
FROM (
    VALUES
        ('regulatory_regulatorydocumentversion'),
        ('regulatory_regulatoryprovision'),
        ('regulatory_regulatoryobligation'),
        ('regulatory_regulatoryapplicabilitydecision')
) AS temporal_table(table_name)
WHERE to_regclass('public.' || table_name) IS NOT NULL
\gexec

-- A compromised runtime identity can still retime or reopen recorded_to through
-- direct SQL. Production must replace or constrain this grant with an approved
-- transition function/trigger contract if the database is expected to enforce
-- NULL -> immutable cutoff semantics.

-- Runtime code may append audit entries but cannot rewrite or delete them.
SELECT format(
    'REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.auditlog_logentry FROM %I',
    :'runtime_role'
)
WHERE to_regclass('public.auditlog_logentry') IS NOT NULL
\gexec

-- Migration state belongs to the migrator, never to the application process.
SELECT format(
    'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE public.django_migrations FROM %I',
    :'runtime_role'
)
WHERE to_regclass('public.django_migrations') IS NOT NULL
\gexec

SELECT format(
    'GRANT SELECT ON TABLE %I.%I TO %I',
    schemaname,
    tablename,
    :'backup_role'
)
FROM pg_tables
WHERE schemaname = 'public'
\gexec
SELECT format(
    'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO %I',
    :'backup_role'
)
\gexec
