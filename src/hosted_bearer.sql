WITH source AS MATERIALIZED (
    SELECT state_revision, state_document AS doc
    FROM public.sourcery_hosted_authority_state WHERE authority_key = $1
), candidates AS MATERIALIZED (
    SELECT item_data FROM source, jsonb_array_elements(
        CASE $2 WHEN 'session' THEN doc->'sessions' ELSE doc->'developerCredentials' END
    ) AS item(item_data)
    WHERE CASE $2 WHEN 'session' THEN item_data->>'tokenDigest' ELSE item_data->>'id' END = $3
    LIMIT 2
), basis AS (
    SELECT state_revision, doc, (SELECT count(*) FROM candidates) AS matches,
        (SELECT item_data FROM candidates LIMIT 1) AS credential FROM source
), projected AS (
    SELECT jsonb_build_object(
        'rowRevision', state_revision, 'documentRevision', doc->'revision', 'schemaVersion', doc->'schemaVersion',
        'collectionsPresent', (SELECT bool_and(coalesce(jsonb_typeof(doc->name) = 'array', false))
            FROM unnest(ARRAY['tenants','apps','projects','workspaces','memberships','identities',
            'sessions','developerCredentials','secrets','audit']) AS fields(name))
            AND (doc->'schemaVersion' = '1'::jsonb OR coalesce(jsonb_typeof(doc->'projectMemberships') = 'array', false)),
        'matches', matches,
        'record', CASE $2 WHEN 'session' THEN
            jsonb_build_object('id', credential->'id', 'userId', credential->'userId',
              'tokenDigest', credential->'tokenDigest', 'revokedAt', credential->'revokedAt', 'expiresAt', credential->'expiresAt')
            ELSE jsonb_build_object('id', credential->'id', 'tenantId', credential->'tenantId', 'appId', credential->'appId',
              'projectId', credential->'projectId', 'workspaceId', credential->'workspaceId', 'scopeMode', credential->'scopeMode',
              'subjectUserId', credential->'subjectUserId', 'permissions', credential->'permissions',
              'tokenDigest', credential->'tokenDigest', 'revokedAt', credential->'revokedAt', 'expiresAt', credential->'expiresAt') END,
        'identities', (SELECT count(*) FROM jsonb_array_elements(doc->'identities') AS identity(actor)
            WHERE actor->>'id' = CASE $2 WHEN 'session' THEN credential->>'userId' ELSE credential->>'subjectUserId' END),
        'tenantRoles', coalesce((SELECT jsonb_agg(role) FROM (
            SELECT member->'role' AS role FROM jsonb_array_elements(doc->'memberships') AS membership(member)
            WHERE member->>'tenantId' = credential->>'tenantId' AND member->>'userId' = credential->>'subjectUserId'
            AND coalesce(member->'revokedAt', 'null'::jsonb) IN ('null','false','0','""') LIMIT 2) AS active), '[]'::jsonb),
        'projectRoles', coalesce((SELECT jsonb_agg(role) FROM (
            SELECT member->'role' AS role FROM jsonb_array_elements(CASE
                WHEN doc->'schemaVersion' = '2'::jsonb THEN doc->'projectMemberships' ELSE '[]'::jsonb END) AS membership(member)
            WHERE member->>'projectId' = credential->>'projectId' AND member->>'userId' = credential->>'subjectUserId'
            AND member->>'tenantId' = credential->>'tenantId' AND member->>'appId' = credential->>'appId'
            AND coalesce(member->'revokedAt', 'null'::jsonb) IN ('null','false','0','""') LIMIT 2) AS active), '[]'::jsonb),
        'appActive', EXISTS(SELECT FROM jsonb_array_elements(doc->'apps') AS apps(app)
            WHERE app->>'id' = credential->>'appId' AND app->>'tenantId' = credential->>'tenantId'
            AND coalesce(app->'deletedAt', 'null'::jsonb) IN ('null','false','0','""')),
        'lineage', EXISTS(SELECT FROM jsonb_array_elements(doc->'apps') AS apps(app)
            WHERE app->>'id' = credential->>'appId' AND app->>'tenantId' = credential->>'tenantId')
          AND (CASE WHEN credential->>'projectId' IS NULL
            THEN credential->>'scopeMode' = 'application-portfolio-v1' AND credential->>'workspaceId' IS NULL
            ELSE EXISTS(SELECT FROM jsonb_array_elements(doc->'projects') AS projects(project)
                WHERE project->>'id' = credential->>'projectId' AND project->>'appId' = credential->>'appId'
                AND project->>'tenantId' = credential->>'tenantId')
              AND (credential->>'workspaceId' IS NULL OR EXISTS(SELECT FROM jsonb_array_elements(doc->'workspaces') AS workspaces(workspace)
                WHERE workspace->>'id' = credential->>'workspaceId' AND workspace->>'projectId' = credential->>'projectId'
                AND workspace->>'appId' = credential->>'appId' AND workspace->>'tenantId' = credential->>'tenantId'))
          END)
    )::text AS document FROM basis
)
SELECT CASE WHEN octet_length(document) <= 32768 THEN document END
FROM (SELECT coalesce((SELECT document FROM projected), 'null') AS document) AS bounded
