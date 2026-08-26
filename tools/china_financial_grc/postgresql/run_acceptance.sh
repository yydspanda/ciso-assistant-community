#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../../.." && pwd)"
compose_file="$script_dir/docker-compose.yml"
bootstrap_sql="$script_dir/bootstrap_roles.sql"
grants_sql="$script_dir/apply_grants.sql"
fixture="$script_dir/acceptance_fixture.py"
python_bin="$repository_root/backend/.venv/bin/python"
pytest_bin="$repository_root/backend/.venv/bin/pytest"

acceptance_port="${PG_ACCEPTANCE_PORT:-55432}"
project_name="ciso-china-grc-pg-acceptance-${PPID}-$$"
database_name="ciso_regulatory_acceptance"
migration_database="ciso_regulatory_acceptance_migration"
restore_database="ciso_regulatory_acceptance_restored"
test_database="test_${database_name}"
migrator_role="ciso_regulatory_migrator"
runtime_role="ciso_regulatory_runtime"
backup_role="ciso_regulatory_backup"
admin_role="ciso_acceptance_admin"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_parent="${CHINA_GRC_ACCEPTANCE_EVIDENCE_PARENT:-/tmp}"
if [[ ! -d "$evidence_parent" || -L "$evidence_parent" ]]; then
    echo "evidence parent must be an existing non-symlink directory" >&2
    exit 1
fi
evidence_parent="$(cd "$evidence_parent" && pwd -P)"
if [[ "$evidence_parent" == "/" \
    || "$evidence_parent" == "$repository_root" \
    || "$evidence_parent" == "$repository_root/"* ]]; then
    echo "refusing root or repository-local evidence parent: $evidence_parent" >&2
    exit 1
fi
if [[ -n "${HOME:-}" ]]; then
    user_home="$(cd "$HOME" && pwd -P)"
    if [[ "$evidence_parent" == "$user_home" ]]; then
        echo "refusing to use the user home as the evidence parent" >&2
        exit 1
    fi
fi
evidence_dir="$(mktemp -d "$evidence_parent/ciso-china-grc-postgresql-$timestamp-XXXXXX")"

for dependency in docker openssl sha256sum git grep; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        echo "missing required command: $dependency" >&2
        exit 1
    fi
done
if [[ ! -x "$python_bin" || ! -x "$pytest_bin" ]]; then
    echo "backend virtual environment is missing; run 'cd backend && uv sync --locked'" >&2
    exit 1
fi
if [[ ! "$acceptance_port" =~ ^[0-9]+$ ]] || ((acceptance_port < 1024 || acceptance_port > 65535)); then
    echo "PG_ACCEPTANCE_PORT must be an unused TCP port from 1024 to 65535" >&2
    exit 1
fi

PG_ACCEPTANCE_ADMIN_PASSWORD="$(openssl rand -hex 24)"
migrator_password="$(openssl rand -hex 24)"
runtime_password="$(openssl rand -hex 24)"
backup_password="$(openssl rand -hex 24)"
export PG_ACCEPTANCE_ADMIN_PASSWORD
export PG_ACCEPTANCE_PORT="$acceptance_port"

compose() {
    docker compose --project-name "$project_name" --file "$compose_file" "$@"
}

compose_with_pgpassword() {
    local password=$1
    shift
    local PGPASSWORD="$password"
    export PGPASSWORD
    compose exec -T -e PGPASSWORD postgres "$@"
}

cleanup() {
    local exit_code=$?
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    unset PG_ACCEPTANCE_ADMIN_PASSWORD migrator_password runtime_password backup_password
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

run_manage() {
    local target_database=$1
    local target_user=$2
    local target_password=$3
    shift 3
    POSTGRES_NAME="$target_database" \
        POSTGRES_USER="$target_user" \
        POSTGRES_PASSWORD="$target_password" \
        DB_HOST=127.0.0.1 \
        DB_PORT="$acceptance_port" \
        DJANGO_DEBUG=True \
        "$python_bin" "$repository_root/backend/manage.py" "$@"
}

run_fixture() {
    local fixture_command=$1
    local target_database=$2
    local output_path=$3
    CHINA_GRC_POSTGRES_ACCEPTANCE=1 \
        POSTGRES_NAME="$target_database" \
        POSTGRES_USER="$runtime_role" \
        POSTGRES_PASSWORD="$runtime_password" \
        DB_HOST=127.0.0.1 \
        DB_PORT="$acceptance_port" \
        DJANGO_DEBUG=True \
        "$python_bin" "$fixture" "$fixture_command" --output "$output_path"
}

admin_psql() {
    compose exec -T postgres psql \
        --username "$admin_role" \
        --dbname postgres \
        --set ON_ERROR_STOP=1 \
        "$@"
}

role_psql() {
    local role=$1
    local password=$2
    local target_database=$3
    local sql=$4
    compose_with_pgpassword "$password" psql \
        --host 127.0.0.1 \
        --username "$role" \
        --dbname "$target_database" \
        --set ON_ERROR_STOP=1 \
        --set VERBOSITY=verbose \
        --command "$sql"
}

apply_grants() {
    local target_database=$1
    local evidence_name=$2
    compose_with_pgpassword "$migrator_password" psql \
        --host 127.0.0.1 \
        --username "$migrator_role" \
        --dbname "$target_database" \
        --set ON_ERROR_STOP=1 \
        --set migrator_role="$migrator_role" \
        --set runtime_role="$runtime_role" \
        --set backup_role="$backup_role" \
        --file - < "$grants_sql" \
        >"$evidence_dir/$evidence_name.log" 2>&1
}

bootstrap_acceptance_database() {
    local CISO_ACCEPTANCE_MIGRATOR_PASSWORD="$migrator_password"
    local CISO_ACCEPTANCE_RUNTIME_PASSWORD="$runtime_password"
    local CISO_ACCEPTANCE_BACKUP_PASSWORD="$backup_password"
    export CISO_ACCEPTANCE_MIGRATOR_PASSWORD
    export CISO_ACCEPTANCE_RUNTIME_PASSWORD
    export CISO_ACCEPTANCE_BACKUP_PASSWORD
    compose exec -T \
        -e CISO_ACCEPTANCE_MIGRATOR_PASSWORD \
        -e CISO_ACCEPTANCE_RUNTIME_PASSWORD \
        -e CISO_ACCEPTANCE_BACKUP_PASSWORD \
        postgres psql \
        --username "$admin_role" \
        --dbname postgres \
        --set ON_ERROR_STOP=1 \
        --set database_name="$database_name" \
        --set migrator_role="$migrator_role" \
        --set runtime_role="$runtime_role" \
        --set backup_role="$backup_role" \
        --file - < "$bootstrap_sql"
}

create_owned_database() {
    local target_database=$1
    local template_database=${2:-template0}
    admin_psql \
        --set target_database="$target_database" \
        --set owner_role="$migrator_role" \
        --set template_database="$template_database" \
        --file - <<'SQL'
SELECT format(
    'CREATE DATABASE %I OWNER %I TEMPLATE %I',
    :'target_database',
    :'owner_role',
    :'template_database'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'target_database'
)
\gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'target_database')
\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'target_database', :'owner_role')
\gexec
SQL
}

expect_denied() {
    local label=$1
    local role=$2
    local password=$3
    local target_database=$4
    local sql=$5
    if role_psql "$role" "$password" "$target_database" "$sql" \
        >"$evidence_dir/$label.stdout.log" \
        2>"$evidence_dir/$label.stderr.log"; then
        echo "expected SQL denial succeeded unexpectedly: $label" >&2
        return 1
    fi
    if ! grep -Eq 'ERROR:[[:space:]]+42501:' \
        "$evidence_dir/$label.stderr.log"; then
        echo "SQL failed for a reason other than insufficient privilege: $label" >&2
        return 1
    fi
    printf '%s\n' "denied as expected" >"$evidence_dir/$label.result"
}

expect_allowed() {
    local label=$1
    local role=$2
    local password=$3
    local target_database=$4
    local sql=$5
    role_psql "$role" "$password" "$target_database" "$sql" \
        >"$evidence_dir/$label.stdout.log" \
        2>"$evidence_dir/$label.stderr.log"
    printf '%s\n' "allowed as expected" >"$evidence_dir/$label.result"
}

assert_role_contract() {
    admin_psql \
        --set migrator_role="$migrator_role" \
        --set runtime_role="$runtime_role" \
        --set backup_role="$backup_role" \
        --file - <<'SQL' >"$evidence_dir/role-contract-assertion.log"
WITH expected(role_name) AS (
    VALUES (:'migrator_role'), (:'runtime_role'), (:'backup_role')
), role_contract AS (
    SELECT
        count(*) = 3
        AND bool_and(
            role.rolcanlogin
            AND role.rolinherit
            AND NOT role.rolsuper
            AND NOT role.rolcreatedb
            AND NOT role.rolcreaterole
            AND NOT role.rolreplication
            AND NOT role.rolbypassrls
            AND (role.rolvaliduntil IS NULL OR role.rolvaliduntil > now())
        ) AS valid
    FROM pg_roles AS role
    JOIN expected ON expected.role_name = role.rolname
), membership_contract AS (
    SELECT NOT EXISTS (
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role ON member_role.oid = membership.member
        JOIN expected ON expected.role_name = member_role.rolname
    ) AS valid
)
SELECT 1 / CASE
    WHEN role_contract.valid AND membership_contract.valid THEN 1
    ELSE 0
END AS role_contract_assertion
FROM role_contract
CROSS JOIN membership_contract;
SQL
}

echo "Starting isolated PostgreSQL 16 acceptance environment"
echo "Evidence directory: $evidence_dir"
compose up --detach --wait

bootstrap_acceptance_database

echo "Rehearsing the full migration graph as the non-superuser migrator"
run_manage "$database_name" "$migrator_role" "$migrator_password" migrate --noinput \
    >"$evidence_dir/fresh-migration.log" 2>&1
run_manage "$database_name" "$migrator_role" "$migrator_password" check \
    >"$evidence_dir/django-check.log" 2>&1
run_manage "$database_name" "$migrator_role" "$migrator_password" \
    makemigrations --check --dry-run >"$evidence_dir/migration-drift.log" 2>&1

echo "Rehearsing empty 0004 -> 0003 -> 0004 -> 0003 -> 0004 migration history"
create_owned_database "$migration_database" "$database_name"
run_manage "$migration_database" "$migrator_role" "$migrator_password" \
    migrate regulatory 0003 --noinput >"$evidence_dir/migration-empty-reverse-first.log" 2>&1
run_manage "$migration_database" "$migrator_role" "$migrator_password" \
    migrate regulatory 0004 --noinput >"$evidence_dir/migration-0003-to-0004.log" 2>&1
run_manage "$migration_database" "$migrator_role" "$migrator_password" \
    migrate regulatory 0003 --noinput >"$evidence_dir/migration-empty-reverse.log" 2>&1
run_manage "$migration_database" "$migrator_role" "$migrator_password" \
    migrate regulatory 0004 --noinput >"$evidence_dir/migration-empty-reapply.log" 2>&1

echo "Running the complete regulatory test suite on PostgreSQL"
create_owned_database "$test_database" "$database_name"
POSTGRES_NAME="$database_name" \
    POSTGRES_USER="$admin_role" \
    POSTGRES_PASSWORD="$PG_ACCEPTANCE_ADMIN_PASSWORD" \
    DB_HOST=127.0.0.1 \
    DB_PORT="$acceptance_port" \
    DJANGO_DEBUG=True \
    "$pytest_bin" "$repository_root/backend/regulatory/tests" -q --reuse-db \
    --junitxml="$evidence_dir/postgresql-regulatory-tests.xml" \
    >"$evidence_dir/postgresql-regulatory-tests.log" 2>&1

echo "Applying and probing the bounded runtime and backup role contract"
apply_grants "$database_name" source-grants
assert_role_contract
admin_psql --csv --command "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolvaliduntil FROM pg_roles WHERE rolname IN ('$migrator_role', '$runtime_role', '$backup_role') ORDER BY rolname" \
    >"$evidence_dir/role-attributes.csv"
expect_denied runtime-create-table "$runtime_role" "$runtime_password" "$database_name" \
    "CREATE TABLE public.runtime_should_not_create(id integer)"
expect_denied runtime-regulatory-delete "$runtime_role" "$runtime_password" "$database_name" \
    "DELETE FROM regulatory_regulatorydocumentversion WHERE false"
expect_denied runtime-regulatory-update "$runtime_role" "$runtime_password" "$database_name" \
    "UPDATE regulatory_regulatorydocument SET issuer = issuer WHERE false"
expect_denied runtime-regulatory-truncate "$runtime_role" "$runtime_password" "$database_name" \
    "TRUNCATE regulatory_regulatorydocumentversion"
expect_allowed runtime-temporal-close-column "$runtime_role" "$runtime_password" "$database_name" \
    "UPDATE regulatory_regulatorydocumentversion SET recorded_to = recorded_to WHERE false"
expect_denied runtime-migration-write "$runtime_role" "$runtime_password" "$database_name" \
    "INSERT INTO django_migrations(app, name, applied) VALUES ('forbidden', 'forbidden', now())"
expect_denied runtime-audit-delete "$runtime_role" "$runtime_password" "$database_name" \
    "DELETE FROM auditlog_logentry WHERE false"
expect_denied backup-write "$backup_role" "$backup_password" "$database_name" \
    "INSERT INTO django_migrations(app, name, applied) VALUES ('forbidden', 'forbidden', now())"
expect_allowed backup-read "$backup_role" "$backup_password" "$database_name" \
    "SELECT count(*) FROM django_migrations"

echo "Seeding a synthetic temporal chain through the runtime domain services"
run_fixture seed "$database_name" "$evidence_dir/seed-fingerprint.json" \
    >"$evidence_dir/runtime-domain-service.log" 2>&1

echo "Proving that populated review history refuses destructive reverse migration"
if run_manage "$database_name" "$migrator_role" "$migrator_password" \
    migrate regulatory 0003 --noinput \
    >"$evidence_dir/populated-reverse-refusal.log" 2>&1; then
    echo "populated reverse migration unexpectedly succeeded" >&2
    exit 1
fi
role_psql "$runtime_role" "$runtime_password" "$database_name" \
    "SELECT count(*) AS review_rows FROM regulatory_regulatoryapplicabilityreviewdisposition" \
    >"$evidence_dir/populated-history-preserved.log"

echo "Capturing the exact source state immediately before backup"
run_fixture verify "$database_name" "$evidence_dir/source-fingerprint.json" \
    >"$evidence_dir/pre-backup-domain-service.log" 2>&1

echo "Creating a synthetic-only custom-format backup with the read-only role"
dump_path="$evidence_dir/synthetic-regulatory-acceptance.dump"
backup_started="$(date +%s)"
compose_with_pgpassword "$backup_password" pg_dump \
    --host 127.0.0.1 \
    --username "$backup_role" \
    --dbname "$database_name" \
    --format custom \
    --no-owner \
    --no-acl >"$dump_path"
backup_finished="$(date +%s)"
dump_sha256="$(sha256sum "$dump_path" | awk '{print $1}')"

echo "Restoring into a new empty database and comparing logical fingerprints"
create_owned_database "$restore_database"
restore_started="$(date +%s)"
compose_with_pgpassword "$migrator_password" pg_restore \
    --host 127.0.0.1 \
    --username "$migrator_role" \
    --dbname "$restore_database" \
    --single-transaction \
    --exit-on-error <"$dump_path" \
    >"$evidence_dir/restore.log" 2>&1
restore_finished="$(date +%s)"
apply_grants "$restore_database" restored-grants
run_fixture verify "$restore_database" "$evidence_dir/restored-fingerprint.json" \
    >"$evidence_dir/restored-domain-service.log" 2>&1
if ! cmp --silent \
    "$evidence_dir/source-fingerprint.json" \
    "$evidence_dir/restored-fingerprint.json"; then
    echo "restored regulatory fingerprint differs from the source" >&2
    diff --unified \
        "$evidence_dir/source-fingerprint.json" \
        "$evidence_dir/restored-fingerprint.json" \
        >"$evidence_dir/fingerprint.diff" || true
    exit 1
fi

echo "Proving restored runtime grants, sequences, and successor selection"
run_fixture mutate-restored "$restore_database" \
    "$evidence_dir/restored-runtime-mutation.json" \
    >"$evidence_dir/restored-runtime-mutation.log" 2>&1

postgres_version="$(admin_psql --tuples-only --no-align --command 'SHOW server_version')"
postgres_image_id="$(docker inspect --format '{{.Image}}' "$(compose ps --quiet postgres)")"
commit_sha="$(git -C "$repository_root" rev-parse HEAD)"
source_tree_sha256="$(
    cd "$repository_root"
    git ls-files -co --exclude-standard -z -- \
        backend \
        tools/china_financial_grc/postgresql \
        | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum -- \
        | sha256sum \
        | awk '{print $1}'
)"
if [[ -n "$(
    git -C "$repository_root" status --porcelain -- \
        backend \
        tools/china_financial_grc/postgresql
)" ]]; then
    worktree_dirty=true
else
    worktree_dirty=false
fi
"$python_bin" - \
    "$evidence_dir/manifest.json" \
    "$commit_sha" \
    "$source_tree_sha256" \
    "$worktree_dirty" \
    "$postgres_version" \
    "$postgres_image_id" \
    "$dump_sha256" \
    "$((backup_finished - backup_started))" \
    "$((restore_finished - restore_started))" <<'PY'
from datetime import UTC, datetime
import json
from pathlib import Path
import sys

(
    output_path,
    commit_sha,
    source_tree_sha256,
    worktree_dirty,
    postgres_version,
    postgres_image_id,
    dump_sha256,
    backup_seconds,
    restore_seconds,
) = sys.argv[1:]
manifest = {
    "contract": "china-financial-grc/postgresql-acceptance/v1",
    "completed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    "base_commit_sha": commit_sha,
    "tested_source_tree_sha256": source_tree_sha256,
    "worktree_dirty": worktree_dirty == "true",
    "postgres_version": postgres_version.strip(),
    "postgres_image": "postgres:16",
    "postgres_image_id": postgres_image_id,
    "synthetic_only": True,
    "dump_sha256": dump_sha256,
    "backup_seconds": int(backup_seconds),
    "restore_seconds": int(restore_seconds),
    "scope": "local technical acceptance; not legal review or production approval",
    "unresolved_external_gates": [
        "named production owner approval",
        "retention and legal-hold decision",
        "tamper-evident external audit archive",
        "audit-export privacy and recipient authorization",
        "encryption and key-custody approval",
        "representative production-volume query-plan baseline",
    ],
}
Path(output_path).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

(
    cd "$evidence_dir"
    find . -maxdepth 1 -type f \
        ! -name SHA256SUMS \
        ! -name SHAREABLE_SHA256SUMS \
        ! -name '*.dump' \
        -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum -- >SHAREABLE_SHA256SUMS
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 -r sha256sum -- >SHA256SUMS
)
evidence_index_sha256="$(sha256sum "$evidence_dir/SHA256SUMS" | awk '{print $1}')"

echo "PostgreSQL technical acceptance passed"
echo "Evidence: $evidence_dir"
echo "Evidence index SHA256: $evidence_index_sha256"
echo "This does not close the named production, legal, privacy, security, or audit gates."
