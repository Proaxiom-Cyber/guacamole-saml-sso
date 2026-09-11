#!/bin/sh
# Creates the two authorisation groups named in .env, and removes the default
# guacadmin account. PostgreSQL runs this once, on first start, when ./data is
# empty. It runs after 001-initdb.sql because of the file name order.
#
# The identity provider authenticates. This database only authorises. No
# individual users are created here, so onboarding and offboarding a person is
# a group change in the identity provider and needs no database work.
#
# The group names must match what the identity provider sends in the group
# claim, exactly. If the claim sends object IDs instead of names, put those
# object IDs in .env.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v admin_group="$GUAC_ADMIN_GROUP" -v operator_group="$GUAC_OPERATOR_GROUP" <<'SQL'

INSERT INTO guacamole_entity (name, type) VALUES
    (:'admin_group',    'USER_GROUP'),
    (:'operator_group', 'USER_GROUP')
ON CONFLICT DO NOTHING;

INSERT INTO guacamole_user_group (entity_id)
SELECT entity_id FROM guacamole_entity
WHERE type = 'USER_GROUP'
  AND name IN (:'admin_group', :'operator_group')
ON CONFLICT DO NOTHING;

-- Operators may create and manage connections. Administrators may not: they get
-- READ on each connection, granted by an operator when the connection is made.
INSERT INTO guacamole_system_permission (entity_id, permission)
SELECT e.entity_id, p.permission::guacamole_system_permission_type
FROM guacamole_entity e
CROSS JOIN (VALUES
    ('CREATE_CONNECTION'),
    ('CREATE_CONNECTION_GROUP'),
    ('ADMINISTER')
) AS p(permission)
WHERE e.type = 'USER_GROUP'
  AND e.name = :'operator_group'
ON CONFLICT DO NOTHING;

-- The generated schema ships a "guacadmin" account with a known password.
-- Remove it. Every identity comes from the identity provider instead, so the
-- database holds no password to attack. The delete cascades to the user row
-- and to all of its permissions.
DELETE FROM guacamole_entity WHERE type = 'USER' AND name = 'guacadmin';

SQL
