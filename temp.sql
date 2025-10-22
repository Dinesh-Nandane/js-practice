\set ON_ERROR_STOP on

-- DATABASE privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON DATABASE ' || current_database() || ' TO ' || grantee || ';'
    FROM information_schema.role_database_grants
    WHERE grantee NOT IN ('pg_signal_backend')
) TO '/tmp/db_grants.sql';

-- SCHEMA ownership
COPY (
    SELECT 'ALTER SCHEMA ' || quote_ident(nspname) || ' OWNER TO ' || quote_ident(r.rolname) || ';'
    FROM pg_namespace n
    JOIN pg_roles r ON r.oid = n.nspowner
    WHERE nspname NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/schema_owners.sql';

-- SCHEMA privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON SCHEMA ' || quote_ident(table_schema) || ' TO ' || grantee || ';'
    FROM information_schema.role_schema_grants
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/schema_grants.sql';

-- TABLE ownership
COPY (
    SELECT 'ALTER TABLE ' || quote_ident(n.nspname) || '.' || quote_ident(c.relname) || 
           ' OWNER TO ' || quote_ident(r.rolname) || ';'
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/table_owners.sql';

-- TABLE privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON TABLE ' || table_schema || '.' || table_name || 
           ' TO ' || grantee || ';'
    FROM information_schema.role_table_grants
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/table_grants.sql';

-- SEQUENCE ownership
COPY (
    SELECT 'ALTER SEQUENCE ' || quote_ident(n.nspname) || '.' || quote_ident(c.relname) || 
           ' OWNER TO ' || quote_ident(r.rolname) || ';'
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE c.relkind = 'S' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/seq_owners.sql';

-- SEQUENCE privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON SEQUENCE ' || table_schema || '.' || table_name ||
           ' TO ' || grantee || ';'
    FROM information_schema.role_sequence_grants
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/seq_grants.sql';

-- VIEW ownership
COPY (
    SELECT 'ALTER VIEW ' || quote_ident(n.nspname) || '.' || quote_ident(c.relname) || 
           ' OWNER TO ' || quote_ident(r.rolname) || ';'
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles r ON r.oid = c.relowner
    WHERE c.relkind = 'v' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/view_owners.sql';

-- VIEW privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON TABLE ' || table_schema || '.' || table_name || 
           ' TO ' || grantee || ';'
    FROM information_schema.role_table_grants
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/view_grants.sql';

-- FUNCTION / PROCEDURE ownership
COPY (
    SELECT 'ALTER FUNCTION ' || quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' ||
           pg_get_function_identity_arguments(p.oid) || ') OWNER TO ' || quote_ident(r.rolname) || ';'
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles r ON r.oid = p.proowner
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
) TO '/tmp/function_owners.sql';

-- FUNCTION / PROCEDURE privileges
COPY (
    SELECT 'GRANT ' || privilege_type || ' ON FUNCTION ' || routine_schema || '.' || routine_name ||
           '(' || coalesce(string_agg(parameter_name || ' ' || data_type, ', '), '') || ') TO ' || grantee || ';'
    FROM information_schema.role_routine_grants
    LEFT JOIN information_schema.parameters ON parameters.specific_name = role_routine_grants.specific_name
    WHERE routine_schema NOT IN ('pg_catalog', 'information_schema')
    GROUP BY routine_schema, routine_name, grantee
) TO '/tmp/function_grants.sql';
