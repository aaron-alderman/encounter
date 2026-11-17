WITH source AS MATERIALIZED (
    SELECT state_revision, state_document AS doc FROM public.sourcery_hosted_authority_state
    WHERE authority_key = $1 FOR UPDATE
), tenant AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(doc->'tenants') AS entry(item) WHERE item->>'id' = $2 LIMIT 2
), app AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(doc->'apps') AS entry(item) WHERE item->>'id' = $3 LIMIT 2
), project AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(doc->'projects') AS entry(item) WHERE item->>'id' = $4 LIMIT 2
), workspace AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(doc->'workspaces') AS entry(item) WHERE item->>'id' = $5 LIMIT 2
), members AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(doc->'memberships') AS entry(item)
    WHERE item->>'tenantId' = $2 AND item->>'userId' = $6
    AND coalesce(item->'revokedAt', 'null'::jsonb) IN ('null','false','0','""') LIMIT 2
), project_members AS MATERIALIZED (
    SELECT item FROM source, jsonb_array_elements(CASE
        WHEN doc->'schemaVersion' = '2'::jsonb THEN doc->'projectMemberships' ELSE '[]'::jsonb END) AS entry(item)
    WHERE item->>'projectId' = $4 AND item->>'userId' = $6
    AND coalesce(item->'revokedAt', 'null'::jsonb) IN ('null','false','0','""') LIMIT 2
), projected AS (
    SELECT jsonb_build_object('rowRevision', state_revision, 'documentRevision', doc->'revision', 'schemaVersion', doc->'schemaVersion',
        'collectionsPresent', (SELECT bool_and(coalesce(jsonb_typeof(doc->name) = 'array', false))
            FROM unnest(ARRAY['tenants','apps','projects','workspaces','memberships','identities',
            'sessions','developerCredentials','secrets','audit']) AS fields(name))
            AND (doc->'schemaVersion' = '1'::jsonb OR coalesce(jsonb_typeof(doc->'projectMemberships') = 'array', false)),
        'counts', jsonb_build_array((SELECT count(*) FROM tenant), (SELECT count(*) FROM app), (SELECT count(*) FROM project),
            (SELECT count(*) FROM workspace), (SELECT count(*) FROM members), (SELECT count(*) FROM project_members)),
        'tenant', (SELECT jsonb_build_object('id',item->'id') FROM tenant LIMIT 1),
        'app', (SELECT jsonb_build_object('id',item->'id','tenantId',item->'tenantId') FROM app LIMIT 1),
        'project', (SELECT jsonb_build_object('id',item->'id','tenantId',item->'tenantId','appId',item->'appId') FROM project LIMIT 1),
        'workspace', (SELECT jsonb_build_object('id',item->'id','tenantId',item->'tenantId','appId',item->'appId','projectId',item->'projectId') FROM workspace LIMIT 1),
        'member', (SELECT jsonb_build_object('tenantId',item->'tenantId','userId',item->'userId','role',item->'role',
            'revokedAt',item->'revokedAt') FROM members LIMIT 1),
        'projectMember', (SELECT jsonb_build_object('tenantId',item->'tenantId','appId',item->'appId','projectId',item->'projectId',
            'userId',item->'userId','role',item->'role','revokedAt',item->'revokedAt') FROM project_members LIMIT 1)
    )::text AS document FROM source
)
SELECT CASE WHEN octet_length(document) <= 32768 THEN document END FROM projected
