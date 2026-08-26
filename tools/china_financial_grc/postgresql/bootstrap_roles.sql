\set ON_ERROR_STOP on
\getenv migrator_password CISO_ACCEPTANCE_MIGRATOR_PASSWORD
\getenv runtime_password CISO_ACCEPTANCE_RUNTIME_PASSWORD
\getenv backup_password CISO_ACCEPTANCE_BACKUP_PASSWORD

SELECT format('CREATE ROLE %I', :'migrator_role')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'migrator_role'
)
\gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'migrator_role',
    :'migrator_password'
)
\gexec

SELECT format('CREATE ROLE %I', :'runtime_role')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role'
)
\gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'runtime_role',
    :'runtime_password'
)
\gexec

SELECT format('CREATE ROLE %I', :'backup_role')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'backup_role'
)
\gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
    :'backup_role',
    :'backup_password'
)
\gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L',
    :'database_name',
    :'migrator_role',
    'UTF8'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'database_name'
)
\gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'database_name')
\gexec
SELECT format(
    'GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I',
    :'database_name',
    :'migrator_role'
)
\gexec
SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I',
    :'database_name',
    :'runtime_role'
)
\gexec
SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I',
    :'database_name',
    :'backup_role'
)
\gexec
