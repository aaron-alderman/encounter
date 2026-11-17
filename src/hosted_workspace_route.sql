WITH source AS MATERIALIZED (
    SELECT state_revision, state_document AS doc
    FROM public.sourcery_hosted_authority_state
    WHERE authority_key = $1
), tenants AS MATERIALIZED (
    SELECT item_data, n FROM source, jsonb_array_elements(doc->'tenants') WITH ORDINALITY AS item(item_data,n)
    WHERE item_data->>'slug' = $2 AND coalesce(item_data->'deletedAt', 'null'::jsonb) IN ('null','false','0','""') ORDER BY n LIMIT 129
), apps AS MATERIALIZED (
    SELECT item_data, n FROM source, jsonb_array_elements(doc->'apps') WITH ORDINALITY AS item(item_data,n)
    WHERE item_data->>'slug' = $3 AND coalesce(item_data->'deletedAt', 'null'::jsonb) IN ('null','false','0','""') AND item_data->>'tenantId' IN (SELECT item_data->>'id' FROM tenants)
    ORDER BY n LIMIT 129
), projects AS MATERIALIZED (
    SELECT item_data, n FROM source, jsonb_array_elements(doc->'projects') WITH ORDINALITY AS item(item_data,n)
    WHERE item_data->>'slug' = $4 AND coalesce(item_data->'deletedAt', 'null'::jsonb) IN ('null','false','0','""') AND item_data->>'appId' IN (SELECT item_data->>'id' FROM apps)
    ORDER BY n LIMIT 129
), workspaces AS (
    SELECT item_data, n FROM source, jsonb_array_elements(doc->'workspaces') WITH ORDINALITY AS item(item_data,n)
    WHERE item_data->>'slug' = $5 AND coalesce(item_data->'deletedAt', 'null'::jsonb) IN ('null','false','0','""') AND item_data->>'projectId' IN (SELECT item_data->>'id' FROM projects)
    ORDER BY n LIMIT 129
), memberships AS (
    SELECT item_data, n FROM source, jsonb_array_elements(doc->'memberships') WITH ORDINALITY AS item(item_data,n)
    WHERE item_data->>'userId' = $6 AND coalesce(item_data->'revokedAt', 'null'::jsonb) IN ('null','false','0','""')
    AND item_data->>'tenantId' IN (SELECT item_data->>'id' FROM tenants)
    ORDER BY n LIMIT 129
), projected AS (
    SELECT jsonb_build_object(
        'rowRevision', state_revision, 'documentRevision', doc->'revision', 'schemaVersion', doc->'schemaVersion',
        'collectionsPresent', (SELECT bool_and(coalesce(jsonb_typeof(doc->name) = 'array', false))
            FROM unnest(ARRAY['tenants','apps','projects','workspaces','memberships','identities',
            'sessions','developerCredentials','secrets','audit']) AS fields(name))
            AND (doc->'schemaVersion' = '1'::jsonb OR coalesce(jsonb_typeof(doc->'projectMemberships') = 'array', false)),
        'userPresent', (SELECT count(*) = 1 FROM jsonb_array_elements(doc->'identities') AS item(item_data)
            WHERE item_data->>'id' = $6),
        'tenants', coalesce((SELECT jsonb_agg(jsonb_build_object('id', item_data->'id', 'slug', item_data->'slug',
            'deletedAt', item_data->'deletedAt', 'ownerPresent', EXISTS(SELECT FROM jsonb_array_elements(doc->'memberships') AS owner(member)
                WHERE member->>'tenantId' = tenants.item_data->>'id' AND member->>'role' = 'owner'
                AND coalesce(member->'revokedAt', 'null'::jsonb) IN ('null','false','0','""')
                AND EXISTS(SELECT FROM jsonb_array_elements(doc->'identities') AS identity(actor)
                    WHERE actor->>'id' = member->>'userId'))) ORDER BY n) FROM tenants), '[]'::jsonb),
        'apps', coalesce((SELECT jsonb_agg(jsonb_build_object('id', item_data->'id', 'slug', item_data->'slug',
            'deletedAt', item_data->'deletedAt', 'tenantId', item_data->'tenantId') ORDER BY n) FROM apps), '[]'::jsonb),
        'projects', coalesce((SELECT jsonb_agg(jsonb_build_object('id', item_data->'id', 'slug', item_data->'slug',
            'deletedAt', item_data->'deletedAt', 'tenantId', item_data->'tenantId', 'appId', item_data->'appId') ORDER BY n) FROM projects), '[]'::jsonb),
        'workspaces', coalesce((SELECT jsonb_agg(jsonb_build_object('id', item_data->'id', 'slug', item_data->'slug',
            'deletedAt', item_data->'deletedAt', 'tenantId', item_data->'tenantId', 'appId', item_data->'appId', 'projectId', item_data->'projectId',
            'region', item_data->'region', 'storageNamespace', item_data->'storageNamespace') ORDER BY n) FROM workspaces), '[]'::jsonb),
        'memberships', coalesce((SELECT jsonb_agg(jsonb_build_object('tenantId', item_data->'tenantId', 'userId', item_data->'userId',
            'role', item_data->'role', 'revokedAt', item_data->'revokedAt') ORDER BY n) FROM memberships), '[]'::jsonb)
    )::text AS document FROM source
)
SELECT CASE WHEN octet_length(document) <= 131072 THEN document END
FROM (SELECT coalesce((SELECT document FROM projected), 'null') AS document) AS bounded
