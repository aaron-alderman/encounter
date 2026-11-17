WITH source AS MATERIALIZED (
    SELECT state_revision, state_document AS doc FROM public.sourcery_hosted_authority_state
    WHERE authority_key = $1 FOR UPDATE
), candidates AS MATERIALIZED (
    SELECT item_data, n - 1 AS position FROM source,
    jsonb_array_elements(doc->$2::text) WITH ORDINALITY AS item(item_data, n)
    WHERE item_data->>'id' = $3 LIMIT 2
), membership AS (
    SELECT member FROM source, jsonb_array_elements(doc->'memberships') AS entry(member)
    WHERE member->>'tenantId' = $4 AND member->>'userId' = $5
    AND coalesce(member->'revokedAt', 'null'::jsonb) IN ('null','false','0','""') LIMIT 2
), projected AS (
    SELECT jsonb_build_object('rowRevision', state_revision, 'documentRevision', doc->'revision', 'schemaVersion', doc->'schemaVersion',
        'collectionsPresent', (SELECT bool_and(coalesce(jsonb_typeof(doc->name) = 'array', false))
            FROM unnest(ARRAY['tenants','apps','projects','workspaces','memberships','identities',
            'sessions','developerCredentials','secrets','audit']) AS fields(name))
            AND (doc->'schemaVersion' = '1'::jsonb OR coalesce(jsonb_typeof(doc->'projectMemberships') = 'array', false)),
        'matches', (SELECT count(*) FROM candidates), 'record', (SELECT item_data FROM candidates LIMIT 1),
        'position', (SELECT position FROM candidates LIMIT 1),
        'memberships', coalesce((SELECT jsonb_agg(jsonb_build_object('tenantId',member->'tenantId','userId',member->'userId',
            'role',member->'role','revokedAt',member->'revokedAt')) FROM membership), '[]'::jsonb)
    )::text AS document FROM source
)
SELECT CASE WHEN octet_length(document) <= 32768 THEN document END FROM projected
