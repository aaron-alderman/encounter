BEGIN;

CREATE SCHEMA IF NOT EXISTS sourcery_mcp_access;
REVOKE ALL ON SCHEMA sourcery_mcp_access FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.browser_session_snapshot(digest text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $browser$
WITH control AS (
    SELECT state_revision, state_document
    FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.control-plane'
), matching AS (
    SELECT value AS record FROM control, jsonb_array_elements(control.state_document->'sessions')
    WHERE digest ~ '^[a-f0-9]{64}$' AND value->>'tokenDigest' = digest
    LIMIT 2
)
SELECT jsonb_build_object(
    'projectionProtocol', 'encounter/hosted-mcp-browser-session/1',
    'controlRevision', control.state_revision,
    'controlDocumentRevision', control.state_document->'revision',
    'controlSchemaVersion', control.state_document->'schemaVersion',
    'sessions', coalesce((SELECT jsonb_agg(jsonb_build_object(
        'id', record->'id', 'userId', record->'userId', 'expiresAt', record->'expiresAt', 'revokedAt', record->'revokedAt',
        'identityCount', (SELECT count(*) FROM (
            SELECT 1 FROM jsonb_array_elements(control.state_document->'identities')
            WHERE value->>'id' = record->>'userId' LIMIT 2
        ) AS identities)
    )) FROM matching), '[]'::jsonb)
)
FROM control;
$browser$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.browser_session_snapshot(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.oauth_candidates(document jsonb, digest text)
RETURNS SETOF jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $tokens$
SELECT jsonb_build_object(
    'credentialKind', 'oauth',
    'clientId', value->'clientId', 'resource', value->'resource',
    'scopes', value->'scopes', 'familyId', value->'familyId',
    'expiresAt', value->'expiresAt', 'revokedAt', value->'revokedAt',
    'principalKind', value#>'{grant,principal,kind}',
    'userId', value#>'{grant,principal,userId}',
    'tenantId', value#>'{grant,scope,tenantId}',
    'appId', value#>'{grant,scope,appId}'
)
FROM jsonb_array_elements(document->'accessTokens')
WHERE value->>'tokenDigest' = digest
LIMIT 2;
$tokens$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.oauth_candidates(jsonb, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.bearer_candidates(oauth jsonb, control jsonb, coordinate text)
RETURNS SETOF jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $bearers$
SELECT token FROM sourcery_mcp_access.oauth_candidates(oauth, coordinate) AS token
WHERE coordinate ~ '^[a-f0-9]{64}$'
UNION ALL
SELECT jsonb_build_object(
    'credentialKind', 'personal', 'familyId', value->'id',
    'userId', value->'subjectUserId', 'tenantId', value->'tenantId', 'appId', value->'appId',
    'projectId', value->'projectId', 'workspaceId', value->'workspaceId', 'scopeMode', value->'scopeMode',
    'scopes', value->'permissions', 'expiresAt', value->'expiresAt', 'revokedAt', value->'revokedAt'
)
FROM jsonb_array_elements(control->'developerCredentials')
WHERE coordinate ~ '^dvc_[a-f0-9]{24}:[a-f0-9]{64}$'
    AND value->>'id' = split_part(coordinate, ':', 1)
    AND value->>'tokenDigest' = split_part(coordinate, ':', 2)
LIMIT 2;
$bearers$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.bearer_candidates(jsonb, jsonb, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.workspace_snapshot(
    digest text, tenant text, app text, project text, workspace text
) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog
AS $snapshot$
WITH oauth AS (
    SELECT state_revision, state_document
    FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth'
), control AS (
    SELECT state_revision, state_document
    FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.control-plane'
), matching_tokens AS (
    SELECT record FROM control LEFT JOIN oauth ON true
    CROSS JOIN LATERAL sourcery_mcp_access.bearer_candidates(oauth.state_document, control.state_document, digest) AS record
), subject AS (
    SELECT record->>'userId' AS id, record->>'tenantId' AS tenant, record->>'appId' AS app FROM matching_tokens
    WHERE record->>'tenantId' = tenant AND record->>'appId' = app
    LIMIT 1
), lineage AS (
    SELECT collection, value AS record
    FROM control CROSS JOIN subject
    CROSS JOIN LATERAL (VALUES ('tenants', tenant), ('apps', app),
        ('projects', project), ('workspaces', workspace)) AS coordinate(collection, id)
    CROSS JOIN LATERAL (
        SELECT value FROM jsonb_array_elements(control.state_document->coordinate.collection)
        WHERE value->>'id' = coordinate.id LIMIT 2
    ) AS matched
), memberships AS (
    SELECT value AS record
    FROM control, subject, jsonb_array_elements(control.state_document->'memberships')
    WHERE value->>'userId' = subject.id AND value->>'tenantId' = tenant
        AND value->>'revokedAt' IS NULL
    LIMIT 2
), project_memberships AS (
    SELECT value AS record
    FROM control, subject, jsonb_array_elements(control.state_document->'projectMemberships')
    WHERE value->>'userId' = subject.id AND value->>'projectId' = project
        AND value->>'revokedAt' IS NULL
    LIMIT 2
)
SELECT jsonb_build_object(
    'projectionProtocol', 'encounter/hosted-mcp-access/2',
    'oauthRevision', oauth.state_revision,
    'oauthDocumentRevision', oauth.state_document->'revision',
    'oauthSchemaVersion', oauth.state_document->'schemaVersion',
    'controlRevision', control.state_revision,
    'controlDocumentRevision', control.state_document->'revision',
    'controlSchemaVersion', control.state_document->'schemaVersion',
    'tokens', coalesce((SELECT jsonb_agg(record) FROM matching_tokens), '[]'::jsonb),
    'lineage', coalesce((
        SELECT jsonb_agg(jsonb_build_object(
            'collection', collection, 'id', record->'id', 'tenantId', record->'tenantId',
            'appId', record->'appId', 'projectId', record->'projectId',
            'deletedAt', record->'deletedAt', 'region', record->'region',
            'storageNamespace', record->'storageNamespace'
        )) FROM lineage
    ), '[]'::jsonb),
    'identityCount', (SELECT count(*) FROM (
        SELECT 1 FROM subject, jsonb_array_elements(control.state_document->'identities')
        WHERE value->>'id' = subject.id LIMIT 2
    ) AS identities),
    'applicationCount', (SELECT count(*) FROM (
        SELECT 1 FROM subject, jsonb_array_elements(control.state_document->'apps') AS records(application)
        WHERE application->>'id' = subject.app AND application->>'tenantId' = subject.tenant
          AND application->>'deletedAt' IS NULL LIMIT 2
    ) AS applications),
    'tenantRoles', coalesce((SELECT jsonb_agg(record->'role') FROM memberships), '[]'::jsonb),
    'projectRoles', coalesce((SELECT jsonb_agg(record->'role') FROM project_memberships), '[]'::jsonb)
)
FROM control LEFT JOIN oauth ON true;
$snapshot$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.workspace_snapshot(text, text, text, text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.workspace_candidates(
    document jsonb, subject_id text, subject_tenant text, subject_app text, all_portfolios boolean
) RETURNS jsonb LANGUAGE sql STABLE SET search_path = pg_catalog AS $inventory$
WITH tenant_roles AS (
    SELECT membership->>'tenantId' AS tenant, jsonb_agg(membership->'role') AS roles
    FROM jsonb_array_elements(document->'memberships') AS membership
    WHERE membership->>'userId' = subject_id AND membership->>'revokedAt' IS NULL
    GROUP BY membership->>'tenantId'
), project_roles AS (
    SELECT membership->>'projectId' AS project, jsonb_agg(membership->'role') AS roles
    FROM jsonb_array_elements(document->'projectMemberships') AS membership
    WHERE membership->>'userId' = subject_id AND membership->>'revokedAt' IS NULL
    GROUP BY membership->>'projectId'
), projects AS MATERIALIZED (
    SELECT record FROM jsonb_array_elements(document->'projects') AS record
), apps AS MATERIALIZED (
    SELECT record FROM jsonb_array_elements(document->'apps') AS record
), tenants AS MATERIALIZED (
    SELECT record FROM jsonb_array_elements(document->'tenants') AS record
), coordinates AS (
    SELECT ordinality, tenants.record AS tenant, apps.record AS app, projects.record AS project, workspace,
        tenant_roles.roles AS tenant_roles,
        coalesce(project_roles.roles, '[]'::jsonb) AS project_roles,
        all_portfolios OR (subject_tenant = tenants.record->>'id' AND subject_app = apps.record->>'id') AS in_portfolio
    FROM jsonb_array_elements(document->'workspaces') WITH ORDINALITY AS entries(workspace, ordinality)
    JOIN projects ON projects.record->>'id' = workspace->>'projectId'
    JOIN apps ON apps.record->>'id' = projects.record->>'appId'
    JOIN tenants ON tenants.record->>'id' = apps.record->>'tenantId'
    JOIN tenant_roles ON tenant_roles.tenant = tenants.record->>'id'
    LEFT JOIN project_roles ON project_roles.project = projects.record->>'id'
    ORDER BY ordinality LIMIT 4097
), candidates AS (
    SELECT ordinality, jsonb_build_object(
        'lineageMatches', coalesce(project->'tenantId' = tenant->'id'
            AND workspace->'tenantId' = tenant->'id' AND workspace->'appId' = app->'id', false),
        'deleted', coalesce(tenant->'deletedAt', 'null'::jsonb) <> 'null'::jsonb
            OR coalesce(app->'deletedAt', 'null'::jsonb) <> 'null'::jsonb
            OR coalesce(project->'deletedAt', 'null'::jsonb) <> 'null'::jsonb
            OR coalesce(workspace->'deletedAt', 'null'::jsonb) <> 'null'::jsonb,
        'tenantRoles', tenant_roles, 'projectRoles', project_roles
    ) || CASE WHEN all_portfolios THEN jsonb_build_object(
        'tenantId', tenant->'id', 'appId', app->'id',
        'labels', jsonb_build_object(
            'tenant', tenant->'name', 'app', app->'name',
            'sortKey', concat_ws('/', tenant->>'slug', app->>'slug', project->>'slug', workspace->>'slug')
        )
    ) WHEN in_portfolio THEN jsonb_build_object(
        'tenantId', tenant->'id', 'appId', app->'id', 'projectId', project->'id', 'workspaceId', workspace->'id',
        'labels', jsonb_build_object(
            'tenant', tenant->'name', 'app', app->'name', 'project', project->'name', 'workspace', workspace->'name',
            'sortKey', concat_ws('/', tenant->>'slug', app->>'slug', project->>'slug', workspace->>'slug')
        )
    ) ELSE '{}'::jsonb END AS record FROM coordinates
)
SELECT coalesce(jsonb_agg(record ORDER BY ordinality), '[]'::jsonb) FROM candidates;
$inventory$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.workspace_candidates(jsonb,text,text,text,boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.browser_portfolio_snapshot(digest text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $browser_portfolio$
WITH browser AS MATERIALIZED (
    SELECT sourcery_mcp_access.browser_session_snapshot(digest) AS snapshot
), credential AS (
    SELECT snapshot, snapshot#>'{sessions,0}' AS session
    FROM browser WHERE snapshot IS NOT NULL
)
SELECT snapshot || jsonb_build_object('portfolioProtocol', 'encounter/hosted-mcp-browser-portfolio/1',
    'candidates', CASE WHEN jsonb_array_length(snapshot->'sessions') = 1
        AND session->>'revokedAt' IS NULL AND session->>'identityCount' = '1'
        AND jsonb_typeof(session->'id') = 'string' AND session->>'id' <> ''
        AND jsonb_typeof(session->'userId') = 'string' AND session->>'userId' <> ''
        AND session->>'expiresAt' IS NOT NULL AND (session->>'expiresAt')::timestamptz > statement_timestamp()
        AND snapshot->'controlRevision' = snapshot->'controlDocumentRevision'
        AND snapshot->'controlSchemaVersion' IN ('1'::jsonb, '2'::jsonb)
    THEN sourcery_mcp_access.workspace_candidates(state.state_document, session->>'userId', NULL, NULL, true)
    ELSE '[]'::jsonb END)
FROM credential, public.sourcery_hosted_authority_state AS state
WHERE state.authority_key = 'sourcery.control-plane';
$browser_portfolio$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.browser_portfolio_snapshot(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.browser_consent_snapshot(digest text, request_id text, decision text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $consent$
WITH browser AS MATERIALIZED (
    SELECT CASE WHEN decision = 'approve' THEN sourcery_mcp_access.browser_portfolio_snapshot(digest)
        WHEN decision = 'deny' THEN sourcery_mcp_access.browser_session_snapshot(digest) END AS snapshot
), journal AS (
    SELECT state_revision, state_document FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth'
), requests AS (
    SELECT value AS record
    FROM browser, journal, jsonb_array_elements(journal.state_document->'authorizationRequests')
    WHERE request_id ~ '^mcp_arq_[a-f0-9]{24}$' AND value->>'id' = request_id
    LIMIT 2
)
SELECT browser.snapshot || jsonb_build_object(
    'consentProtocol', 'encounter/hosted-mcp-browser-consent/1',
    'oauthRevision', journal.state_revision, 'oauthDocumentRevision', journal.state_document->'revision',
    'oauthSchemaVersion', journal.state_document->'schemaVersion',
    'requests', CASE WHEN jsonb_array_length(browser.snapshot->'sessions') = 1
        AND browser.snapshot#>>'{sessions,0,revokedAt}' IS NULL
        AND browser.snapshot#>>'{sessions,0,identityCount}' = '1'
        AND (browser.snapshot#>>'{sessions,0,expiresAt}')::timestamptz > statement_timestamp()
        AND browser.snapshot->'controlRevision' = browser.snapshot->'controlDocumentRevision'
    THEN coalesce((SELECT jsonb_agg(jsonb_build_object(
        'id', record->'id', 'userId', record#>'{grant,principal,userId}',
        'tenantId', record#>'{grant,scope,tenantId}', 'appId', record#>'{grant,scope,appId}',
        'resource', record->'resource', 'scopes', record->'scopes', 'expiresAt', record->'expiresAt',
        'completedAt', record->'completedAt', 'deniedAt', record->'deniedAt',
        'redirectUri', record->'redirectUri', 'state', record->'state'))
        FROM requests WHERE record#>>'{grant,principal,kind}' = 'user'
        AND record#>>'{grant,principal,userId}' = browser.snapshot#>>'{sessions,0,userId}'
        AND (SELECT count(*) FROM requests) = 1), '[]'::jsonb)
    ELSE '[]'::jsonb END)
FROM browser LEFT JOIN journal ON true;
$consent$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.browser_consent_snapshot(text,text,text) FROM PUBLIC;

CREATE TABLE IF NOT EXISTS sourcery_mcp_access.browser_consent_key (
    singleton boolean PRIMARY KEY CHECK (singleton),
    secret bytea NOT NULL CHECK (octet_length(secret) = 32)
);
REVOKE ALL ON TABLE sourcery_mcp_access.browser_consent_key FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.consent_proof_matches(message text, proof text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $proof$
DECLARE
    key_bytes bytea;
    inner_pad bytea := decode(repeat('36',64), 'hex');
    outer_pad bytea := decode(repeat('5c',64), 'hex');
    expected bytea;
    supplied bytea;
    difference integer := 0;
    i integer;
BEGIN
    IF proof IS NULL OR proof !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
    SELECT secret INTO key_bytes FROM sourcery_mcp_access.browser_consent_key WHERE singleton;
    IF NOT FOUND THEN RETURN false; END IF;
    FOR i IN 0..31 LOOP
        inner_pad := set_byte(inner_pad, i, get_byte(inner_pad, i) # get_byte(key_bytes, i));
        outer_pad := set_byte(outer_pad, i, get_byte(outer_pad, i) # get_byte(key_bytes, i));
    END LOOP;
    expected := sha256(outer_pad || sha256(inner_pad || convert_to(message,'UTF8')));
    supplied := decode(proof,'hex');
    FOR i IN 0..31 LOOP
        difference := difference | (get_byte(expected, i) # get_byte(supplied, i));
    END LOOP;
    RETURN difference = 0;
END;
$proof$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.consent_proof_matches(text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.browser_consent_ready(proof text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $ready$
SELECT sourcery_mcp_access.consent_proof_matches('encounter/browser-consent-ready/1',proof);
$ready$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.browser_consent_ready(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.begin_browser_authorization(
    digest text, control_revision bigint, deadline_ms bigint, request_text text, proof text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $begin_authorize$
DECLARE
    journal jsonb;
    revision bigint;
    pending jsonb;
    browser jsonb;
    issued_at timestamptz;
    outcome constant jsonb := '{"protocol":"encounter/hosted-mcp-browser-authorize/1"}';
BEGIN
    IF digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR control_revision IS NULL
        OR control_revision NOT BETWEEN 0 AND 9007199254740991 OR deadline_ms IS NULL
        OR deadline_ms NOT BETWEEN 1 AND 9007199254740991 OR request_text IS NULL
        OR octet_length(request_text) > 16384
        OR NOT sourcery_mcp_access.consent_proof_matches(concat_ws('|','encounter/browser-authorize/1',
            digest,control_revision,deadline_ms,encode(sha256(convert_to(request_text,'UTF8')),'hex')),proof) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    pending := request_text::jsonb;
    IF jsonb_typeof(pending) IS DISTINCT FROM 'object'
        OR coalesce(pending->>'id','') !~ '^mcp_arq_[a-f0-9]{24}$'
        OR coalesce(pending->>'codeChallengeDigest','') !~ '^[a-f0-9]{64}$'
        OR pending->'scopes' IS DISTINCT FROM '["authoring.read"]'::jsonb
        OR pending->>'resource' IS DISTINCT FROM 'https://mcp.sourcerytech.com.au/mcp'
        OR NOT coalesce(pending->>'clientRegistrationMode' IN ('preRegisteredClientV1','clientIdMetadataDocumentV1'),false)
        OR pending#>>'{grant,principal,kind}' IS DISTINCT FROM 'user'
        OR NOT coalesce(length(pending#>>'{grant,scope,tenantId}') BETWEEN 1 AND 128,false)
        OR NOT coalesce(length(pending#>>'{grant,scope,appId}') BETWEEN 1 AND 128,false) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    PERFORM 1 FROM public.sourcery_hosted_authority_state WHERE authority_key = 'sourcery.control-plane'
        AND state_revision = control_revision AND state_document->'revision' = to_jsonb(control_revision) FOR SHARE;
    IF NOT FOUND THEN RETURN outcome || '{"status":"stale"}'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sourcery.mcp-oauth',0));
    issued_at := clock_timestamp();
    browser := sourcery_mcp_access.browser_session_snapshot(digest);
    IF extract(epoch FROM issued_at)*1000 >= deadline_ms
        OR jsonb_array_length(browser->'sessions') IS DISTINCT FROM 1
        OR browser#>>'{sessions,0,identityCount}' IS DISTINCT FROM '1'
        OR browser#>>'{sessions,0,revokedAt}' IS NOT NULL
        OR NOT coalesce((browser#>>'{sessions,0,expiresAt}')::timestamptz > issued_at,false)
        OR pending#>>'{grant,principal,userId}' IS DISTINCT FROM browser#>>'{sessions,0,userId}' THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    SELECT state_revision, state_document INTO revision, journal FROM public.sourcery_hosted_authority_state
        WHERE authority_key = 'sourcery.mcp-oauth' FOR UPDATE;
    IF NOT FOUND THEN
        revision := 0;
        journal := '{"schemaVersion":1,"revision":0,"authorizationRequests":[],"authorizationCodes":[],"accessTokens":[],"refreshTokens":[]}';
        INSERT INTO public.sourcery_hosted_authority_state(authority_key,state_revision,state_document)
            VALUES ('sourcery.mcp-oauth', revision, journal);
    END IF;
    IF revision NOT BETWEEN 0 AND 9007199254740990 OR journal->'revision' IS DISTINCT FROM to_jsonb(revision)
        OR journal->'schemaVersion' IS DISTINCT FROM '1'::jsonb
        OR EXISTS (SELECT 1 FROM jsonb_array_elements(journal->'authorizationRequests')
            WHERE value->>'id' = pending->>'id') THEN
        RAISE EXCEPTION 'Invalid OAuth journal for browser authorization';
    END IF;
    pending := pending || jsonb_build_object(
        'createdAt',to_char(issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'expiresAt',to_char((issued_at + interval '300 seconds') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'completedAt',NULL,'deniedAt',NULL);
    journal := jsonb_set(journal, '{authorizationRequests}', (journal->'authorizationRequests') || jsonb_build_array(pending));
    UPDATE public.sourcery_hosted_authority_state
        SET state_revision = revision+1, state_document = jsonb_set(journal,'{revision}',to_jsonb(revision+1)),
            updated_at = CURRENT_TIMESTAMP
        WHERE authority_key = 'sourcery.mcp-oauth' AND state_revision = revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'Browser authorization lost its OAuth journal revision'; END IF;
    RETURN outcome || '{"status":"committed"}';
END;
$begin_authorize$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.begin_browser_authorization(text,bigint,bigint,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.commit_browser_consent(
    digest text, request_id text, decision text, oauth_revision bigint, control_revision bigint,
    csrf_expiry bigint, code_id text, code_digest text, proof text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $commit$
DECLARE
    journal jsonb;
    pending jsonb;
    request_index bigint;
    browser jsonb;
    issued_at timestamptz;
    stamp text;
    outcome constant jsonb := '{"protocol":"encounter/hosted-mcp-browser-consent-commit/1"}';
BEGIN
    IF digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR request_id IS NULL OR request_id !~ '^mcp_arq_[a-f0-9]{24}$'
        OR decision IS NULL OR decision NOT IN ('approve','deny') OR oauth_revision IS NULL
        OR oauth_revision NOT BETWEEN 0 AND 9007199254740990 OR control_revision IS NULL
        OR control_revision NOT BETWEEN 0 AND 9007199254740991 OR csrf_expiry IS NULL
        OR csrf_expiry NOT BETWEEN 1 AND 9007199254740991 OR code_id IS NULL OR code_digest IS NULL
        OR (decision = 'approve' AND (code_id !~ '^mcp_code_[a-f0-9]{24}$' OR code_digest !~ '^[a-f0-9]{64}$'))
        OR (decision = 'deny' AND (code_id <> '' OR code_digest <> '')) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    IF NOT sourcery_mcp_access.consent_proof_matches(concat_ws('|','encounter/browser-consent-commit/1',
        digest,request_id,decision,oauth_revision,control_revision,csrf_expiry,code_id,code_digest),proof) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    PERFORM 1 FROM public.sourcery_hosted_authority_state WHERE authority_key = 'sourcery.control-plane'
        AND state_revision = control_revision AND state_document->'revision' = to_jsonb(control_revision) FOR SHARE;
    IF NOT FOUND THEN RETURN outcome || '{"status":"stale"}'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sourcery.mcp-oauth',0));
    SELECT state_document INTO journal FROM public.sourcery_hosted_authority_state
        WHERE authority_key = 'sourcery.mcp-oauth' AND state_revision = oauth_revision FOR UPDATE;
    IF NOT FOUND OR journal->'revision' IS DISTINCT FROM to_jsonb(oauth_revision)
        OR journal->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN
        RETURN outcome || '{"status":"stale"}';
    END IF;
    issued_at := clock_timestamp();
    browser := sourcery_mcp_access.browser_session_snapshot(digest);
    IF extract(epoch FROM issued_at)*1000 >= csrf_expiry
        OR jsonb_array_length(browser->'sessions') IS DISTINCT FROM 1
        OR browser#>>'{sessions,0,identityCount}' IS DISTINCT FROM '1'
        OR browser#>>'{sessions,0,revokedAt}' IS NOT NULL
        OR NOT coalesce((browser#>>'{sessions,0,expiresAt}')::timestamptz > issued_at,false) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(journal->'authorizationRequests')
        WHERE value->>'id' = request_id) <> 1 THEN RETURN outcome || '{"status":"refused"}'; END IF;
    SELECT value, ordinality - 1 INTO pending, request_index
        FROM jsonb_array_elements(journal->'authorizationRequests') WITH ORDINALITY WHERE value->>'id' = request_id;
    IF pending#>>'{grant,principal,kind}' IS DISTINCT FROM 'user'
        OR pending#>>'{grant,principal,userId}' IS DISTINCT FROM browser#>>'{sessions,0,userId}'
        OR pending->'scopes' IS DISTINCT FROM '["authoring.read"]'::jsonb
        OR pending->>'resource' IS DISTINCT FROM 'https://mcp.sourcerytech.com.au/mcp'
        OR pending->>'completedAt' IS NOT NULL OR pending->>'deniedAt' IS NOT NULL
        OR NOT coalesce((pending->>'expiresAt')::timestamptz > issued_at,false) THEN
        RETURN outcome || '{"status":"refused"}';
    END IF;
    stamp := to_char(issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    IF decision = 'approve' THEN
        IF EXISTS (SELECT 1 FROM jsonb_array_elements(journal->'authorizationCodes') AS code
            WHERE code->>'id' = code_id OR code->>'codeDigest' = code_digest) THEN
            RETURN outcome || '{"status":"refused"}';
        END IF;
        journal := jsonb_set(journal, ARRAY['authorizationRequests',request_index::text,'completedAt'], to_jsonb(stamp));
        journal := jsonb_set(journal, '{authorizationCodes}', (journal->'authorizationCodes') || jsonb_build_array(
            jsonb_build_object('id',code_id,'requestId',request_id,'codeDigest',code_digest,'scopes',pending->'scopes',
                'expiresAt',to_char((issued_at + interval '300 seconds') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
                'usedAt',NULL)));
    ELSE
        journal := jsonb_set(journal, ARRAY['authorizationRequests',request_index::text,'deniedAt'], to_jsonb(stamp));
    END IF;
    UPDATE public.sourcery_hosted_authority_state
        SET state_revision = oauth_revision + 1, state_document = jsonb_set(journal,'{revision}',to_jsonb(oauth_revision+1)),
            updated_at = CURRENT_TIMESTAMP
        WHERE authority_key = 'sourcery.mcp-oauth' AND state_revision = oauth_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'Browser consent lost its OAuth journal revision'; END IF;
    RETURN outcome || '{"status":"committed"}';
END;
$commit$;
REVOKE ALL ON FUNCTION sourcery_mcp_access.commit_browser_consent(text,text,text,bigint,bigint,bigint,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.read_portfolio(digest text, include_inventory boolean)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $portfolio$
WITH oauth AS (
    SELECT state_revision, state_document FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth'
), control AS (
    SELECT state_revision, state_document FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.control-plane'
), tokens AS (
    SELECT record FROM control LEFT JOIN oauth ON true
    CROSS JOIN LATERAL sourcery_mcp_access.bearer_candidates(oauth.state_document, control.state_document, digest) AS record
), subject AS (
    SELECT record->>'userId' AS id, record->>'tenantId' AS tenant, record->>'appId' AS app FROM tokens
    WHERE (SELECT count(*) FROM tokens) = 1
)
SELECT jsonb_build_object(
    'projectionProtocol', 'encounter/hosted-mcp-access/2',
    'oauthRevision', oauth.state_revision, 'oauthDocumentRevision', oauth.state_document->'revision',
    'oauthSchemaVersion', oauth.state_document->'schemaVersion', 'controlRevision', control.state_revision,
    'controlDocumentRevision', control.state_document->'revision', 'controlSchemaVersion', control.state_document->'schemaVersion',
    'tokens', coalesce((SELECT jsonb_agg(record) FROM tokens), '[]'::jsonb),
    'identityCount', (SELECT count(*) FROM (
        SELECT 1 FROM subject, jsonb_array_elements(control.state_document->'identities')
        WHERE value->>'id' = subject.id LIMIT 2
    ) AS identities),
    'applicationCount', (SELECT count(*) FROM (
        SELECT 1 FROM subject, jsonb_array_elements(control.state_document->'apps') AS applications(item)
        WHERE item->>'id' = subject.app AND item->>'tenantId' = subject.tenant AND item->>'deletedAt' IS NULL LIMIT 2
    ) AS applications),
    'tenantRoles', coalesce((SELECT jsonb_agg(membership->'role')
        FROM subject, jsonb_array_elements(control.state_document->'memberships') AS membership
        WHERE membership->>'userId' = subject.id AND membership->>'tenantId' = subject.tenant
          AND membership->>'revokedAt' IS NULL), '[]'::jsonb),
    'candidates', CASE WHEN include_inventory THEN coalesce((
        SELECT sourcery_mcp_access.workspace_candidates(control.state_document, subject.id, subject.tenant, subject.app, false)
        FROM subject), '[]'::jsonb) ELSE '[]'::jsonb END
) FROM control LEFT JOIN oauth ON true;
$portfolio$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.read_portfolio(text, boolean) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.portfolio_snapshot(digest text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $portfolio$
SELECT sourcery_mcp_access.read_portfolio(digest, true);
$portfolio$;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.credential_snapshot(digest text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $credential$
SELECT sourcery_mcp_access.read_portfolio(digest, false);
$credential$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.portfolio_snapshot(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sourcery_mcp_access.credential_snapshot(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.oauth_scope_snapshot(digest text, operation text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $oauth_scope$
WITH state AS (
    SELECT state_revision, state_document FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth'
), codes AS (
    SELECT code->'scopes' AS scopes, request->'resource' AS resource, NULL::text AS family, 'code' AS source
    FROM state
    CROSS JOIN LATERAL jsonb_array_elements(state_document->'authorizationCodes') AS code
    JOIN LATERAL jsonb_array_elements(state_document->'authorizationRequests') AS request ON request->>'id' = code->>'requestId'
    WHERE operation = 'authorization_code' AND code->>'codeDigest' = digest
    LIMIT 2
), refreshes AS (
    SELECT token->'scopes' AS scopes, token->'resource' AS resource, token->>'familyId' AS family, 'refresh' AS source
    FROM state, jsonb_array_elements(state_document->'refreshTokens') AS token
    WHERE operation IN ('refresh_token', 'revoke') AND token->>'tokenDigest' = digest
    LIMIT 2
), accesses AS (
    SELECT token->'scopes' AS scopes, token->'resource' AS resource, NULL::text AS family, 'access' AS source
    FROM state, jsonb_array_elements(state_document->'accessTokens') AS token
    WHERE operation = 'revoke' AND token->>'tokenDigest' = digest
    LIMIT 2
), matched AS (
    SELECT * FROM codes UNION ALL SELECT * FROM refreshes UNION ALL SELECT * FROM accesses
), family_grants AS (
    SELECT DISTINCT member->'scopes' AS scopes, member->'resource' AS resource
    FROM state CROSS JOIN refreshes
    CROSS JOIN LATERAL jsonb_array_elements(
        (state_document->'refreshTokens') || (state_document->'accessTokens')
    ) AS member
    WHERE member->>'familyId' = refreshes.family
    LIMIT 33
)
SELECT jsonb_build_object(
    'protocol', 'encounter/public-mcp-oauth-scope/1',
    'revision', state_revision, 'documentRevision', state_document->'revision',
    'schemaVersion', state_document->'schemaVersion',
    'grants', coalesce((SELECT jsonb_agg((to_jsonb(matched) - 'family') || jsonb_build_object(
        'familyBound', coalesce(family ~ '^mcp_family_[a-f0-9]{24}$', false))) FROM matched), '[]'::jsonb),
    'familyGrants', coalesce((SELECT jsonb_agg(to_jsonb(family_grants)) FROM family_grants), '[]'::jsonb)
)
FROM (VALUES (true)) AS anchor(present) LEFT JOIN state ON true
WHERE operation IN ('authorization_code', 'refresh_token', 'revoke') AND digest ~ '^[a-f0-9]{64}$';
$oauth_scope$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.oauth_scope_snapshot(text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.public_oauth_revoke(digest text, expected_revision bigint)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $revoke$
DECLARE
    revision bigint;
    document jsonb;
    projection jsonb;
    grant_record jsonb;
    family text;
    revoked_at jsonb;
    public_resource constant jsonb := '"https://mcp.sourcerytech.com.au/mcp"';
    public_scopes constant jsonb := '["authoring.read"]';
BEGIN
    IF digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR expected_revision IS NULL OR expected_revision < 0 THEN
        RAISE EXCEPTION 'Invalid public OAuth revocation coordinate';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sourcery.mcp-oauth', 0));
    SELECT state_revision, state_document INTO revision, document
    FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth' FOR UPDATE;
    IF NOT FOUND OR revision <> expected_revision THEN
        RETURN '{"protocol":"encounter/public-mcp-oauth-revoke/1","status":"stale"}'::jsonb;
    END IF;
    IF revision >= 9007199254740991 OR document->'revision' IS DISTINCT FROM to_jsonb(revision)
        OR document->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN
        RAISE EXCEPTION 'Invalid retained OAuth authority revision';
    END IF;
    projection := sourcery_mcp_access.oauth_scope_snapshot(digest, 'revoke');
    grant_record := projection->'grants'->0;
    -- This is the write capability ceiling, including for a direct SQL caller.
    IF projection->>'protocol' IS DISTINCT FROM 'encounter/public-mcp-oauth-scope/1'
        OR jsonb_array_length(projection->'grants') IS DISTINCT FROM 1
        OR grant_record->'scopes' IS DISTINCT FROM public_scopes
        OR grant_record->'resource' IS DISTINCT FROM public_resource THEN
        RETURN '{"protocol":"encounter/public-mcp-oauth-revoke/1","status":"unchanged"}'::jsonb;
    END IF;
    IF grant_record->>'source' = 'refresh' THEN
        IF grant_record->'familyBound' IS DISTINCT FROM 'true'::jsonb
            OR jsonb_array_length(projection->'familyGrants') IS DISTINCT FROM 1
            OR projection->'familyGrants'->0->'scopes' IS DISTINCT FROM public_scopes
            OR projection->'familyGrants'->0->'resource' IS DISTINCT FROM public_resource THEN
            RETURN '{"protocol":"encounter/public-mcp-oauth-revoke/1","status":"unchanged"}'::jsonb;
        END IF;
        SELECT value->>'familyId' INTO STRICT family FROM jsonb_array_elements(document->'refreshTokens')
        WHERE value->>'tokenDigest' = digest;
    ELSIF grant_record->>'source' IS DISTINCT FROM 'access' THEN
        RETURN '{"protocol":"encounter/public-mcp-oauth-revoke/1","status":"unchanged"}'::jsonb;
    END IF;
    revoked_at := to_jsonb(to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    document := jsonb_set(document, '{accessTokens}', coalesce((
        SELECT jsonb_agg(CASE WHEN value->>'revokedAt' IS NULL
            AND CASE WHEN family IS NULL THEN value->>'tokenDigest' = digest ELSE value->>'familyId' = family END
            THEN jsonb_set(value, '{revokedAt}', revoked_at) ELSE value END ORDER BY ordinality)
        FROM jsonb_array_elements(document->'accessTokens') WITH ORDINALITY
    ), '[]'::jsonb));
    IF family IS NOT NULL THEN
        document := jsonb_set(document, '{refreshTokens}', coalesce((
            SELECT jsonb_agg(CASE WHEN value->>'revokedAt' IS NULL AND value->>'familyId' = family
                THEN jsonb_set(value, '{revokedAt}', revoked_at) ELSE value END ORDER BY ordinality)
            FROM jsonb_array_elements(document->'refreshTokens') WITH ORDINALITY
        ), '[]'::jsonb));
    END IF;
    UPDATE public.sourcery_hosted_authority_state
    SET state_revision = revision + 1, state_document = jsonb_set(document, '{revision}', to_jsonb(revision + 1)),
        updated_at = CURRENT_TIMESTAMP
    WHERE authority_key = 'sourcery.mcp-oauth' AND state_revision = revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'OAuth revocation lost its authority revision'; END IF;
    RETURN '{"protocol":"encounter/public-mcp-oauth-revoke/1","status":"revoked"}'::jsonb;
END;
$revoke$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.public_oauth_revoke(text, bigint) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.oauth_exchange_snapshot(
    digest text, operation text, client text, resource text, redirect_uri text, proof text
) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $exchange_snapshot$
WITH state AS (
    SELECT state_document FROM public.sourcery_hosted_authority_state WHERE authority_key = 'sourcery.mcp-oauth'
), candidates AS (
    SELECT (request->>'clientId' = client AND request->>'resource' = resource
        AND request->>'redirectUri' = redirect_uri AND request->>'codeChallengeDigest' = proof) AS binding,
        code->>'expiresAt' AS expiry, code->>'usedAt' IS NOT NULL AS used, false AS revoked
    FROM state, jsonb_array_elements(state_document->'authorizationCodes') AS code,
        jsonb_array_elements(state_document->'authorizationRequests') AS request
    WHERE operation = 'authorization_code' AND code->>'codeDigest' = digest AND request->>'id' = code->>'requestId'
    UNION ALL
    SELECT (token->>'clientId' = client AND token->>'resource' = resource),
        token->>'expiresAt', token->>'usedAt' IS NOT NULL, token->>'revokedAt' IS NOT NULL
    FROM state, jsonb_array_elements(state_document->'refreshTokens') AS token
    WHERE operation = 'refresh_token' AND token->>'tokenDigest' = digest
    LIMIT 2
)
SELECT sourcery_mcp_access.oauth_scope_snapshot(digest, operation) || jsonb_build_object(
    'exchangeProtocol', 'encounter/public-mcp-oauth-exchange/1',
    'candidates', coalesce((SELECT jsonb_agg(jsonb_build_object('binding', binding, 'used', used,
        'revoked', revoked, 'expiresAt', expiry)) FROM candidates), '[]'::jsonb)
);
$exchange_snapshot$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.oauth_exchange_snapshot(text,text,text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION sourcery_mcp_access.public_oauth_exchange(
    digest text, operation text, client text, resource text, redirect_uri text, proof text, expected_revision bigint, mint jsonb
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $exchange$
DECLARE
    revision bigint;
    document jsonb;
    projection jsonb;
    candidate jsonb;
    grant_record jsonb;
    source_record jsonb;
    source_collection text;
    source_digest text;
    retained_grant jsonb;
    family text;
    generation bigint;
    issued_at timestamptz;
    stamp text;
    access_seconds integer;
    refresh_seconds integer;
    common jsonb;
    outcome constant jsonb := '{"protocol":"encounter/public-mcp-oauth-exchange/1"}';
BEGIN
    IF operation IS NULL OR operation NOT IN ('authorization_code','refresh_token')
        OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR expected_revision IS NULL OR expected_revision < 0 THEN
        RAISE EXCEPTION 'Invalid public OAuth exchange coordinate';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('sourcery.mcp-oauth', 0));
    SELECT state_revision, state_document INTO revision, document FROM public.sourcery_hosted_authority_state
    WHERE authority_key = 'sourcery.mcp-oauth' FOR UPDATE;
    IF NOT FOUND OR revision <> expected_revision THEN RETURN outcome || '{"status":"stale"}'; END IF;
    IF revision >= 9007199254740991 OR document->'revision' IS DISTINCT FROM to_jsonb(revision)
        OR document->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN
        RAISE EXCEPTION 'Invalid retained OAuth authority revision';
    END IF;

    projection := sourcery_mcp_access.oauth_exchange_snapshot(digest, operation, client, resource, redirect_uri, proof);
    grant_record := projection->'grants'->0;
    candidate := projection->'candidates'->0;
    issued_at := clock_timestamp();
    -- The SQL role can consume only a live, bound grant in the public read lane.
    IF resource IS DISTINCT FROM 'https://mcp.sourcerytech.com.au/mcp'
        OR jsonb_array_length(projection->'grants') IS DISTINCT FROM 1
        OR grant_record->'scopes' IS DISTINCT FROM '["authoring.read"]'::jsonb
        OR grant_record->>'resource' IS DISTINCT FROM resource
        OR jsonb_array_length(projection->'candidates') IS DISTINCT FROM 1
        OR candidate->'binding' IS DISTINCT FROM 'true'::jsonb
        OR candidate->>'expiresAt' IS NULL OR (candidate->>'expiresAt')::timestamptz <= issued_at THEN
        RETURN outcome || '{"status":"invalid"}';
    END IF;
    IF operation = 'refresh_token' THEN
        IF grant_record->'familyBound' IS DISTINCT FROM 'true'::jsonb
            OR jsonb_array_length(projection->'familyGrants') IS DISTINCT FROM 1
            OR projection->'familyGrants'->0->'scopes' IS DISTINCT FROM '["authoring.read"]'::jsonb
            OR projection->'familyGrants'->0->>'resource' IS DISTINCT FROM resource THEN
            RETURN outcome || '{"status":"invalid"}';
        END IF;
        IF candidate->'used' = 'true'::jsonb OR candidate->'revoked' = 'true'::jsonb THEN
            IF sourcery_mcp_access.public_oauth_revoke(digest, revision)->>'status' IS DISTINCT FROM 'revoked' THEN
                RAISE EXCEPTION 'Public OAuth replay revocation did not complete';
            END IF;
            RETURN outcome || '{"status":"replay"}';
        END IF;
        source_collection := 'refreshTokens';
        source_digest := 'tokenDigest';
    ELSE
        IF candidate->'used' = 'true'::jsonb THEN RETURN outcome || '{"status":"invalid"}'; END IF;
        source_collection := 'authorizationCodes';
        source_digest := 'codeDigest';
    END IF;
    SELECT value INTO STRICT source_record FROM jsonb_array_elements(document->source_collection)
    WHERE value->>source_digest = digest;

    access_seconds := (mint->>'accessSeconds')::integer;
    refresh_seconds := (mint->>'refreshSeconds')::integer;
    IF NOT coalesce(mint->>'accessDigest' ~ '^[a-f0-9]{64}$' AND mint->>'refreshDigest' ~ '^[a-f0-9]{64}$'
        AND mint->>'accessDigest' <> mint->>'refreshDigest'
        AND mint->>'accessId' ~ '^mcp_at_[a-f0-9]{24}$' AND mint->>'refreshId' ~ '^mcp_rt_[a-f0-9]{24}$'
        AND access_seconds BETWEEN 60 AND 900 AND refresh_seconds BETWEEN access_seconds AND 2592000, false)
        OR EXISTS (SELECT 1 FROM jsonb_array_elements((document->'accessTokens') || (document->'refreshTokens')) AS token
            WHERE token->>'tokenDigest' IN (mint->>'accessDigest', mint->>'refreshDigest')
              OR token->>'id' IN (mint->>'accessId', mint->>'refreshId')) THEN
        RAISE EXCEPTION 'Invalid public OAuth mint material';
    END IF;
    IF operation = 'authorization_code' THEN
        family := mint->>'familyId';
        generation := 1;
        IF NOT coalesce(family ~ '^mcp_family_[a-f0-9]{24}$', false)
            OR EXISTS (SELECT 1 FROM jsonb_array_elements((document->'accessTokens') || (document->'refreshTokens')) AS token
                WHERE token->>'familyId' = family) THEN
            RAISE EXCEPTION 'Invalid public OAuth mint family';
        END IF;
        SELECT value->'grant' INTO STRICT retained_grant FROM jsonb_array_elements(document->'authorizationRequests')
        WHERE value->>'id' = source_record->>'requestId';
    ELSE
        family := source_record->>'familyId';
        generation := (source_record->>'generation')::bigint + 1;
        retained_grant := source_record->'grant';
        IF generation IS NULL OR generation < 2 OR generation > 9007199254740991 THEN
            RAISE EXCEPTION 'Invalid public OAuth refresh generation';
        END IF;
    END IF;
    IF jsonb_typeof(retained_grant) IS DISTINCT FROM 'object'
        OR retained_grant#>>'{principal,kind}' IS DISTINCT FROM 'user'
        OR EXISTS (
            SELECT 1 FROM unnest(ARRAY['{principal,userId}', '{scope,tenantId}', '{scope,appId}']::text[]) AS path
            WHERE jsonb_typeof(retained_grant#>(path::text[])) IS DISTINCT FROM 'string'
                OR retained_grant#>>(path::text[]) = ''
        )
        OR EXISTS (
            SELECT 1 FROM unnest(ARRAY['projectId','workspaceId']) AS name
            WHERE (retained_grant->'scope') ? name
                AND (jsonb_typeof(retained_grant->'scope'->name) IS DISTINCT FROM 'string' OR retained_grant->'scope'->>name = '')
        ) THEN
        RAISE EXCEPTION 'Invalid retained OAuth grant';
    END IF;
    stamp := to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
    common := jsonb_build_object('clientId',client,'resource',resource,'scopes',grant_record->'scopes',
        'grant',retained_grant,'familyId',family,'issuedAt',stamp,'revokedAt',NULL);
    document := jsonb_set(document, ARRAY[source_collection], (
        SELECT jsonb_agg(CASE WHEN value->>source_digest = digest THEN
            value || jsonb_build_object('usedAt',stamp) || CASE WHEN operation = 'refresh_token'
                THEN jsonb_build_object('replacedById',mint->>'refreshId') ELSE '{}'::jsonb END
            ELSE value END ORDER BY ordinality)
        FROM jsonb_array_elements(document->source_collection) WITH ORDINALITY
    ));
    document := jsonb_set(document, '{accessTokens}', (document->'accessTokens') || jsonb_build_array(common || jsonb_build_object(
        'id',mint->>'accessId','tokenDigest',mint->>'accessDigest',
        'expiresAt',to_char((issued_at + make_interval(secs => access_seconds)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))));
    document := jsonb_set(document, '{refreshTokens}', (document->'refreshTokens') || jsonb_build_array(common || jsonb_build_object(
        'id',mint->>'refreshId','tokenDigest',mint->>'refreshDigest','generation',generation,'usedAt',NULL,'replacedById',NULL,
        'expiresAt',to_char((issued_at + make_interval(secs => refresh_seconds)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))));
    UPDATE public.sourcery_hosted_authority_state
    SET state_revision = revision + 1, state_document = jsonb_set(document,'{revision}',to_jsonb(revision+1)), updated_at = CURRENT_TIMESTAMP
    WHERE authority_key = 'sourcery.mcp-oauth' AND state_revision = revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'OAuth exchange lost its authority revision'; END IF;
    RETURN outcome || '{"status":"issued"}';
END;
$exchange$;

REVOKE ALL ON FUNCTION sourcery_mcp_access.public_oauth_exchange(text,text,text,text,text,text,bigint,jsonb) FROM PUBLIC;

COMMIT;
