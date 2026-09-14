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
